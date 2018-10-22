/*
 * libxt_GLBREDIRECT: iptables target for GLB proxy alternate fallback
 *
 * Copyright (c) 2018 GitHub.
 *
 * This file is part of the `glb-redirect` iptables module.
 *
 * glb-redirect is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * glb-redirect is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with glb-redirect.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <net/tcp.h>
#include <net/gue.h>
#include <net/udp.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/inet6_hashtables.h>
#include "ipt_glbredirect.h"

// #define DEBUG

#define MAX_HOPS 256

#ifdef DEBUG
#define PRINT_DEBUG(...) printk(__VA_ARGS__)
/* like WARN_ON(), except returns NF_DROP as well */
#define DROP_ON(condition) do { \
	if (unlikely((condition)!=0)) { \
		printk("Failed condition (%s) in %s at %s:%d, dropping packet\n", #condition, __FUNCTION__, __FILE__, __LINE__); \
		dump_stack(); \
		return NF_DROP; \
	} \
} while (0)
#else
#define PRINT_DEBUG(...)
/* when debugging is off, still validate these assertions but don't print the debug trace */
#define DROP_ON(condition) do { \
	if (unlikely((condition)!=0)) { \
		return NF_DROP; \
	} \
} while (0)
#endif

struct glbgue_chained_routing {
	uint16_t private_data_type;
	uint8_t next_hop;
	uint8_t hop_count;
	__be32 hops[MAX_HOPS];
} __attribute__((packed));

static unsigned int is_valid_locally(struct net *net, struct sk_buff *skb, int inner_ip_ofs, struct iphdr *iph_v4, struct ipv6hdr *iph_v6, struct tcphdr *th);

static unsigned int glbredirect_send_forwarded_skb(struct net *net, struct sk_buff *skb)
{
	nf_reset(skb);
	skb_forward_csum(skb);

	if (ip_route_me_harder(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	        net,
#endif
	        skb, RTN_UNSPEC)) {
		kfree_skb(skb);
		return NF_STOLEN;
	}

	PRINT_DEBUG(KERN_ERR " -> forwarded to alternate\n");
	ip_local_out(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
		net,
		skb->sk,
#endif
		skb);

	return NF_STOLEN;
}

static unsigned int glbredirect_handle_inner_tcp_generic(struct net *net, struct sk_buff *skb, struct iphdr *outer_ip, struct glbgue_chained_routing *glb_routing, int gue_cr_ofs, int inner_ip_ofs, struct iphdr *inner_ip_v4, struct ipv6hdr *inner_ip_v6, struct tcphdr *th)
{
	struct udphdr *uh = udp_hdr(skb);
	struct glbgue_chained_routing *raw_cr;
	__be32 alt;

	DROP_ON(net == NULL);
	DROP_ON(skb == NULL);
	DROP_ON(outer_ip == NULL);
	DROP_ON(glb_routing == NULL);
	DROP_ON(inner_ip_v4 == NULL && inner_ip_v6 == NULL);
	DROP_ON(th == NULL);
	DROP_ON(uh == NULL);

	/* SYN packets are always taken locally. */
	if (th->syn) {
		PRINT_DEBUG(KERN_ERR " -> SYN packet, accepting locally\n");
		return XT_CONTINUE;
	}

	/* If we've exhausted alternate hops, don't bother looking.
	 * The local IP stack is the best option, and it can handle responses.
	 */
	if (glb_routing->next_hop >= glb_routing->hop_count) {
		PRINT_DEBUG(KERN_ERR " -> no more alternative hops available, accept here regardless\n");
		return XT_CONTINUE;
	}

	PRINT_DEBUG(KERN_ERR " -> checking for local matching connection\n");

	/* Do we know about this flow? Handle through local IP stack too */
	if (is_valid_locally(net, skb, inner_ip_ofs, inner_ip_v4, inner_ip_v6, th)) {
		PRINT_DEBUG(KERN_ERR " -> matched local flow, accepting\n");
		return XT_CONTINUE;
	}

	PRINT_DEBUG(KERN_ERR " -> unknown locally\n");

	/* Extract our next alternate server. */
	alt = glb_routing->hops[glb_routing->next_hop];

	/* Although in theory we can forward to ourselves because we always increment the
	 * next hop index, be defensive and force the packet to be taken locally.
	 * Avoids any potential loops if something goes wrong.
	 */
	if (alt == outer_ip->daddr)
		return XT_CONTINUE;

	PRINT_DEBUG(KERN_ERR " -> got an alternate: %08x\n", alt);

	/* Steal the packet and forward it on to the next alternate hop.
	 * As we do this, we want to increment our next hop
	 * Conveniently, we can source from our host by using the original daddr.
	 * Also note we've retrieved and validated the size of the full header previously.
	 */
	raw_cr = (struct glbgue_chained_routing *)(((char *)outer_ip) + gue_cr_ofs);

	/* Adjust the UDP checksum if it's included */
	if (uh->check != 0) {
		csum_replace2(&uh->check, raw_cr->next_hop, raw_cr->next_hop + 1);

		/* daddr just moves around (from dst to src)
		 * but the old src goes away and the new alt is added.
		 */
		csum_replace4(&uh->check, outer_ip->saddr, alt);
	}

	raw_cr->next_hop++;

	outer_ip->saddr = outer_ip->daddr;
	outer_ip->daddr = alt;

	return glbredirect_send_forwarded_skb(net, skb);
}

static unsigned int glbredirect_handle_inner_ipv6(struct net *net, struct sk_buff *skb, struct iphdr *outer_ip, struct glbgue_chained_routing *glb_routing, int gue_cr_ofs, int inner_ip_ofs)
{
	struct ipv6hdr *inner_ip_v6, _inner_ip_v6;
	struct tcphdr *th, _th;
	int tcp_ofs;

	DROP_ON(net == NULL);
	DROP_ON(skb == NULL);
	DROP_ON(outer_ip == NULL);
	DROP_ON(glb_routing == NULL);
	
	inner_ip_v6 = skb_header_pointer(skb, inner_ip_ofs, sizeof(_inner_ip_v6), &_inner_ip_v6);
	if (inner_ip_v6 == NULL)
		return NF_DROP;

	/* We only need to process TCP packets - they have flow state.
	 * ICMP and UDP (the only others forwarded by glb-director) are
	 * always handled by the first host since they have no socket.
	 * Other protocols are an error.
	 */
	if (inner_ip_v6->nexthdr != IPPROTO_TCP) {
		if (inner_ip_v6->nexthdr == IPPROTO_UDP || inner_ip_v6->nexthdr == IPPROTO_ICMPV6)
			return XT_CONTINUE;
		else
			return NF_DROP;
	}

	tcp_ofs = inner_ip_ofs + sizeof(struct ipv6hdr);
	th = skb_header_pointer(skb, tcp_ofs, sizeof(_th), &_th);
	if (th == NULL)
		return NF_DROP;

	PRINT_DEBUG(KERN_ERR "IP<%08x,%08x> GUE<> IPv6<%08x %08x %08x %08x,%08x %08x %08x %08x> TCP<%d,%d flags %c%c%c%c%c>\n",
		outer_ip->saddr, outer_ip->daddr,
		ntohl(inner_ip_v6->saddr.in6_u.u6_addr32[0]),
		ntohl(inner_ip_v6->saddr.in6_u.u6_addr32[1]),
		ntohl(inner_ip_v6->saddr.in6_u.u6_addr32[2]),
		ntohl(inner_ip_v6->saddr.in6_u.u6_addr32[3]),
		ntohl(inner_ip_v6->daddr.in6_u.u6_addr32[0]),
		ntohl(inner_ip_v6->daddr.in6_u.u6_addr32[1]),
		ntohl(inner_ip_v6->daddr.in6_u.u6_addr32[2]),
		ntohl(inner_ip_v6->daddr.in6_u.u6_addr32[3]),
		ntohs(th->source), ntohs(th->dest),
		th->syn ? 'S' : '.',
		th->ack ? 'A' : '.',
		th->rst ? 'R' : '.',
		th->psh ? 'P' : '.',
		th->fin ? 'F' : '.'
	);

	return glbredirect_handle_inner_tcp_generic(net, skb, outer_ip, glb_routing, gue_cr_ofs, inner_ip_ofs, NULL, inner_ip_v6, th);
}

static unsigned int glbredirect_handle_inner_ipv4(struct net *net, struct sk_buff *skb, struct iphdr *outer_ip, struct glbgue_chained_routing *glb_routing, int gue_cr_ofs, int inner_ip_ofs)
{
	struct iphdr *inner_ip_v4, _inner_ip_v4;
	struct tcphdr *th, _th;
	int tcp_ofs;

	DROP_ON(net == NULL);
	DROP_ON(skb == NULL);
	DROP_ON(outer_ip == NULL);
	DROP_ON(glb_routing == NULL);

	inner_ip_v4 = skb_header_pointer(skb, inner_ip_ofs, sizeof(_inner_ip_v4), &_inner_ip_v4);
	if (inner_ip_v4 == NULL)
		return NF_DROP;

	/* We only need to process TCP packets - they have flow state.
	 * ICMP and UDP (the only others forwarded by glb-director) are
	 * always handled by the first host since they have no socket.
	 * Other protocols are an error.
	 */
	if (inner_ip_v4->protocol != IPPROTO_TCP) {
		if (inner_ip_v4->protocol == IPPROTO_UDP || inner_ip_v4->protocol == IPPROTO_ICMP)
			return XT_CONTINUE;
		else
			return NF_DROP;
	}

	tcp_ofs = inner_ip_ofs + (inner_ip_v4->ihl * 4);
	th = skb_header_pointer(skb, tcp_ofs, sizeof(_th), &_th);
	if (th == NULL)
		return NF_DROP;

	PRINT_DEBUG(KERN_ERR "IP<%08x,%08x> GUE<> IPv4<%08x,%08x> TCP<%d,%d flags %c%c%c%c%c>\n",
		outer_ip->saddr, outer_ip->daddr,
		inner_ip_v4->saddr, inner_ip_v4->daddr,
		ntohs(th->source), ntohs(th->dest),
		th->syn ? 'S' : '.',
		th->ack ? 'A' : '.',
		th->rst ? 'R' : '.',
		th->psh ? 'P' : '.',
		th->fin ? 'F' : '.'
	);

	return glbredirect_handle_inner_tcp_generic(net, skb, outer_ip, glb_routing, gue_cr_ofs, inner_ip_ofs, inner_ip_v4, NULL, th);
}

/* Our skb here contains a FOU packet:
 * <IP>  director -> local proxy
 * <UDP> 
 * <GUE> hop list
 * <IP>  src_addr -> dst_addr
 * <TCP> src_port -> dst_port
 *
 * We need to safely extract the tuple:
 *  (src_addr, src_port, dst_addr, dst_port)
 *
 * If we know about this tuple (conntrack or socket) or no more hops, then:
 *   XT_CONTINUE to let the packet be handled locally
 * Otherwise:
 *   Take the next hop from the GUE header,
 *   set destination IP to that hop and transmit.
 */
static unsigned int
glbredirect_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct iphdr *outer_ip;
	struct udphdr *uh, _uh;
	struct guehdr *gh, _gh;
	struct glbgue_chained_routing *cr, _cr;
	int udp_ofs, gue_ofs, gue_cr_ofs, inner_ip_ofs;
	int cr_len_bytes;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	struct net *net = xt_net(par);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
	struct net *net = par->net;
#else
	struct net *net = dev_net(skb->dev);
#endif

	/* Extract outer IP, inner IP and TCP headers */
	outer_ip = ip_hdr(skb);
	if (outer_ip == NULL)
		return NF_DROP;

	/* We expect a UDP packet, bail if it's wrong */
	if (outer_ip->protocol != IPPROTO_UDP)
		return NF_DROP;

	/* Extract the UDP header */
	udp_ofs = outer_ip->ihl * 4;
	uh = skb_header_pointer(skb, udp_ofs, sizeof(_uh), &_uh);
	if (uh == NULL)
		return NF_DROP;

	/* Extract the base GUE header */
	gue_ofs = udp_ofs + sizeof(struct udphdr);
	gh = skb_header_pointer(skb, gue_ofs, sizeof(_gh), &_gh);
	if (gh == NULL)
		return NF_DROP;

	/* The GUE header has a length field that specifies the number of
	 * 32bit ints in the GUE header, not including the header struct itself.
	 * Make sure it's a sane size - at least 1 (must have the private struct)
	 * but no more than the size glbgue_chained_routing can take.
	 */
	cr_len_bytes = gh->hlen * sizeof(uint32_t);
	if (gh->hlen < 1 || cr_len_bytes > sizeof(struct glbgue_chained_routing))
		return NF_DROP;

	/* Extract the GUE private data after the GUE header */
	gue_cr_ofs = gue_ofs + sizeof(struct guehdr);
	cr = skb_header_pointer(skb, gue_cr_ofs, cr_len_bytes, &_cr);
	if (cr == NULL)
		return NF_DROP;

	/* Validate the chained routing data.
	 * Expect that we read exactly the amount we expect based on hop_count.
	 */
	if (gh->hlen != cr->hop_count + 1)
		return NF_DROP;

	/* Finally, jump over the GUE private data to get our inner data packet. */
	inner_ip_ofs = gue_cr_ofs + cr_len_bytes;
	
	/* GUE expects an IANA IP protocol number.
	 * GLB only supports encapsulating IPv4 and IPv6 packets:
	 *  - IPv4 is encapsulated as IPPROTO_IPIP
	 *  - IPv6 is encapsulated as IPPROTO_IPV6
	 */
	if (gh->proto_ctype == IPPROTO_IPIP) {
		/* IPv4 inside */
		return glbredirect_handle_inner_ipv4(net, skb, outer_ip, cr, gue_cr_ofs, inner_ip_ofs);
	} else if (gh->proto_ctype == IPPROTO_IPV6) {
		/* IPv6 inside */
		return glbredirect_handle_inner_ipv6(net, skb, outer_ip, cr, gue_cr_ofs, inner_ip_ofs);
	} else {
		/* Unsupported by GLB */
		return NF_DROP;
	}
}

static unsigned int is_valid_locally(struct net *net, struct sk_buff *skb, int inner_ip_ofs, struct iphdr *iph_v4, struct ipv6hdr *iph_v6, struct tcphdr *th)
{
#ifdef DEBUG
	WARN_ON(net == NULL);
	WARN_ON(skb == NULL);
	WARN_ON(iph_v4 == NULL && iph_v6 == NULL);
	WARN_ON(th == NULL);
#endif

	PRINT_DEBUG(KERN_ERR " -> checking for established\n");

	/* First check: existing established connection is fine.
	 * This avoids locking on any central resource (LISTEN socket, conntrack)
	 */
	{
		struct sock *nsk;

		if (likely(iph_v4 != NULL)) {
			nsk = inet_lookup_established(net, &tcp_hashinfo,
						iph_v4->saddr, th->source,
						iph_v4->daddr, th->dest,
						inet_iif(skb));
		} else if (likely(iph_v6 != NULL)) {
			nsk = __inet6_lookup_established(net, &tcp_hashinfo,
						&iph_v6->saddr, th->source,
						&iph_v6->daddr, ntohs(th->dest),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
						inet_iif(skb), 0);
#else
						inet_iif(skb));
#endif
		} else {
			return 0; /* no IPv4 or IPv6 header provided */
		}

		if (nsk) {
			sock_put(nsk);
			return 1;
		}
	}

	PRINT_DEBUG(KERN_ERR " -> checking conntrack for SYN_RECV\n");

	/* If we're not ESTABLISHED yet, check conntrack for a SYN_RECV.
	 * When syncookies aren't enabled, this will let ACKs come in to complete
	 * a connection.
	 */
	{
		const struct nf_conntrack_tuple_hash *thash;
		struct nf_conntrack_tuple tuple;
		struct nf_conn *ct;

		int ip_proto_ver = NFPROTO_IPV4;
		if (iph_v6 != NULL) {
			ip_proto_ver = NFPROTO_IPV6;
		}

		if (!nf_ct_get_tuplepr(skb, skb_network_offset(skb) + inner_ip_ofs, ip_proto_ver,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
			net,
#endif
			&tuple))
			goto no_ct_entry;

		rcu_read_lock();

		thash = nf_conntrack_find_get(net,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
			&nf_ct_zone_dflt,
#else
			NF_CT_DEFAULT_ZONE,
#endif
			&tuple);
		if (thash == NULL)
			goto no_ct_entry;

		ct = nf_ct_tuplehash_to_ctrack(thash);
		if (ct == NULL)
			goto no_ct_entry;

		if (!nf_ct_is_dying(ct) && nf_ct_tuple_equal(&tuple, &thash->tuple)) {
			nf_ct_put(ct);
			rcu_read_unlock();
			return 1;
		}

		nf_ct_put(ct);
		rcu_read_unlock();
	}

no_ct_entry:

	PRINT_DEBUG(KERN_ERR " -> checking for syncookie\n");

	/* Last chance, if syncookies are enabled, then a valid syncookie ACK is also acceptable */
	if (th->ack && !th->fin && !th->rst && !th->syn) {
		struct sock *listen_sk;
		int ret = 0;

		if (likely(iph_v4 != NULL)) {
			/* IPv4 */

			listen_sk = inet_lookup_listener(net, &tcp_hashinfo,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
				skb, ip_hdrlen(skb) + __tcp_hdrlen(th),
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0)
				iph_v4->saddr, th->source,
#endif
				iph_v4->daddr, th->dest,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
				inet_iif(skb), 0);
#else
				inet_iif(skb));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
			if (listen_sk && !refcount_inc_not_zero(&listen_sk->sk_refcnt))
				listen_sk = NULL;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
			if (listen_sk && !atomic_inc_not_zero(&listen_sk->sk_refcnt))
				listen_sk = NULL;
#endif

			if (listen_sk) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
				int syncookies = sock_net(listen_sk)->ipv4.sysctl_tcp_syncookies;
#else
				int syncookies = sysctl_tcp_syncookies;
#endif
				bool want_cookie = (syncookies == 2 ||
			    	                !tcp_synq_no_recent_overflow(listen_sk));

				if (want_cookie) {
					int mss = __cookie_v4_check(iph_v4, th, ntohl(th->ack_seq) - 1);
					if (mss > 0)
						ret = 1;
				}

				sock_put(listen_sk);
			}
		} else if (likely(iph_v6 != NULL)) {
			/* IPv6 */
			
			listen_sk = inet6_lookup_listener(net, &tcp_hashinfo,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
				skb, ip_hdrlen(skb) + __tcp_hdrlen(th),
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0)
				&iph_v6->saddr, th->source,
#endif
				&iph_v6->daddr, th->dest,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,0)
				inet_iif(skb), 0);
#else
				inet_iif(skb));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
			if (listen_sk && !refcount_inc_not_zero(&listen_sk->sk_refcnt))
				listen_sk = NULL;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
			if (listen_sk && !atomic_inc_not_zero(&listen_sk->sk_refcnt))
				listen_sk = NULL;
#endif

			if (listen_sk) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0)
				int syncookies = sock_net(listen_sk)->ipv4.sysctl_tcp_syncookies;
#else
				int syncookies = sysctl_tcp_syncookies;
#endif
				bool want_cookie = (syncookies == 2 ||
			    	                !tcp_synq_no_recent_overflow(listen_sk));

				if (want_cookie) {
					int mss = __cookie_v6_check(iph_v6, th, ntohl(th->ack_seq) - 1);
					if (mss > 0)
						ret = 1;
				}

				sock_put(listen_sk);
			}
		}

		return ret;
	}

	return 0;
}

static int glbredirect_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_entry *e = par->entryinfo;
	int valid_proto = 1;

	PRINT_DEBUG(KERN_ERR "Validating GLBREDIRECT with proto=%d %d\n",
		e->ip.proto, e->ip.invflags & XT_INV_PROTO
	);

	/* Invalid to match "anything except" a protocol. */
	if (e->ip.invflags & XT_INV_PROTO)
		return -EINVAL;

	valid_proto = (e->ip.proto == IPPROTO_UDP);

	if (!valid_proto)
		return -EINVAL;

	return nf_ct_l3proto_try_module_get(par->family);
}

static void glbredirect_tg4_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_l3proto_module_put(par->family);
}

static struct xt_target glbredirect_tg4_reg __read_mostly = {
	.name		= "GLBREDIRECT",
	.family		= NFPROTO_IPV4,
	.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
	.target		= glbredirect_tg4,
	.targetsize	= sizeof(struct ipt_glbredirect_info),
	.checkentry	= glbredirect_tg4_check,
	.destroy	= glbredirect_tg4_destroy,
	.me		    = THIS_MODULE,
};

static int __init glbredirect_tg4_init(void)
{
	int err;

	err = xt_register_target(&glbredirect_tg4_reg);
	if (err < 0)
		goto err1;

	return 0;

err1:
	return err;
}

static void __exit glbredirect_tg4_exit(void)
{
	xt_unregister_target(&glbredirect_tg4_reg);
}

module_init(glbredirect_tg4_init);
module_exit(glbredirect_tg4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Theo Julienne <theo@github.com>");
