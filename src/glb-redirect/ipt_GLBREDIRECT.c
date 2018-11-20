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
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/u64_stats_sync.h>
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
#include <net/net_namespace.h>
#include "ipt_glbredirect.h"

// #define DEBUG

#define MAX_HOPS 256
#define PROCFS_NAME "glb_redirect_stats"

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

struct glbgue_stats {
	__u64 total_packets;
	__u64 accepted_syn_packets;
	__u64 accepted_last_resort_packets;
	__u64 accepted_established_packets;
	__u64 accepted_conntracked_packets;
	__u64 accepted_syn_cookie_packets;
	__u64 forwarded_to_self_packets;
	__u64 forwarded_to_alternate_packets;
	struct u64_stats_sync syncp;
};

struct glbgue_stats __percpu *percpu_stats;

static unsigned int is_valid_locally(struct net *net, struct sk_buff *skb, int inner_ip_ofs, struct iphdr *iph_v4, struct ipv6hdr *iph_v6, struct tcphdr *th);

static unsigned int glbredirect_send_forwarded_skb(struct net *net, struct sk_buff *skb)
{
	struct glbgue_stats *s = this_cpu_ptr(percpu_stats);
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

	u64_stats_update_begin(&s->syncp);
	s->forwarded_to_alternate_packets++;
	u64_stats_update_end(&s->syncp);

	return NF_STOLEN;
}

static unsigned int glbredirect_handle_inner_tcp_generic(struct net *net, struct sk_buff *skb, struct iphdr *outer_ip, struct glbgue_chained_routing *glb_routing, int gue_cr_ofs, int inner_ip_ofs, struct iphdr *inner_ip_v4, struct ipv6hdr *inner_ip_v6, struct tcphdr *th)
{
	struct glbgue_stats *s = this_cpu_ptr(percpu_stats);
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
		u64_stats_update_begin(&s->syncp);
		s->accepted_syn_packets++;
		u64_stats_update_end(&s->syncp);

		PRINT_DEBUG(KERN_ERR " -> SYN packet, accepting locally\n");
		return XT_CONTINUE;
	}

	PRINT_DEBUG(KERN_ERR " -> checking for local matching connection\n");

	/* Do we know about this flow? Handle through local IP stack too */
	if (is_valid_locally(net, skb, inner_ip_ofs, inner_ip_v4, inner_ip_v6, th)) {
		PRINT_DEBUG(KERN_ERR " -> matched local flow, accepting\n");
		return XT_CONTINUE;
	}

	PRINT_DEBUG(KERN_ERR " -> unknown locally\n");

	/* We've exhausted alternate hops and the packet is not known locally.
	 * The local IP stack is the best option, and it can handle responses.
	 * This is a symptom of an incorrectly constructed forwarding table.
	 */
	if (glb_routing->next_hop >= glb_routing->hop_count) {
		u64_stats_update_begin(&s->syncp);
		s->accepted_last_resort_packets++;
		u64_stats_update_end(&s->syncp);

		PRINT_DEBUG(KERN_ERR " -> no more alternative hops available, accept here regardless\n");
		return XT_CONTINUE;
	}

	/* Extract our next alternate server. */
	alt = glb_routing->hops[glb_routing->next_hop];

	/* Although in theory we can forward to ourselves because we always increment the
	 * next hop index, be defensive and force the packet to be taken locally.
	 * Avoids any potential loops if something goes wrong.
	 */
	if (alt == outer_ip->daddr) {
		u64_stats_update_begin(&s->syncp);
		s->forwarded_to_self_packets++;
		u64_stats_update_end(&s->syncp);

		return XT_CONTINUE;
	}

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

/* Build a fake TCP header from the payload of an ICMP Packet Too Big
 * message. This is required since ICMPv4 only carries the first 64bit
 * of the TCP / UDP header.
 */
static bool fill_tcp_from_icmp(const struct sk_buff *skb, int icmp_payload_ofs, struct tcphdr *th)
{
	uint32_t tmp;

	memset(th, 0, sizeof(*th));
	if (skb_copy_bits(skb, icmp_payload_ofs, th, offsetofend(struct tcphdr, dest)))
		return 0;

	/* Reverse ports from the usual order, since Packet Too Big messages
	 * contain packets from the return direction of the flow.
	 */
	tmp = th->source;
	th->source = th->dest;
	th->dest = tmp;
	return 1;
}

static void copy_v6(struct in6_addr *dst, const struct in6_addr *src)
{
	memcpy(dst->s6_addr32, src->s6_addr32, sizeof(dst->s6_addr32));
}

static unsigned int glbredirect_handle_inner_ipv6(struct net *net, struct sk_buff *skb, struct iphdr *outer_ip, struct glbgue_chained_routing *glb_routing, int gue_cr_ofs, int inner_ip_ofs)
{
	struct ipv6hdr *inner_ip_v6, _inner_ip_v6;
	struct icmp6hdr *icmp6h, _icmp6h;
	struct tcphdr *th, _th;
	struct in6_addr tmp_addr;
	bool is_icmp_pkt_too_big = 0;
	int ofs;

	DROP_ON(net == NULL);
	DROP_ON(skb == NULL);
	DROP_ON(outer_ip == NULL);
	DROP_ON(glb_routing == NULL);

	inner_ip_v6 = skb_header_pointer(skb, inner_ip_ofs, sizeof(_inner_ip_v6), &_inner_ip_v6);
	if (inner_ip_v6 == NULL)
		return NF_DROP;

	/* We need to process TCP packets and ICMP messages used in
	 * path MTU discovery, since they have flow state.
	 * Other ICMP and UDP (the only others forwarded by glb-director) are
	 * always handled by the first host since they have no socket.
	 * Other protocols are an error.
	 */
	ofs = inner_ip_ofs + sizeof(struct ipv6hdr);

	switch (inner_ip_v6->nexthdr) {
	case IPPROTO_ICMPV6:
		icmp6h = skb_header_pointer(skb, ofs, sizeof(_icmp6h), &_icmp6h);
		if (icmp6h == NULL)
			return NF_DROP;

		if (icmp6h->icmp6_type != ICMPV6_PKT_TOOBIG)
			return XT_CONTINUE;

		is_icmp_pkt_too_big = 1;

		inner_ip_v6 = &_inner_ip_v6;
		inner_ip_ofs = ofs + sizeof(struct icmp6hdr);
		if (skb_copy_bits(skb, inner_ip_ofs, inner_ip_v6, sizeof(*inner_ip_v6)))
			return NF_DROP;

		/* Same deal as with ports: this is a packet from the
		 * return flow, adjust accordingly.
		 */
		copy_v6(&tmp_addr, &inner_ip_v6->saddr);
		copy_v6(&inner_ip_v6->saddr, &inner_ip_v6->daddr);
		copy_v6(&inner_ip_v6->daddr, &tmp_addr);

		/* NB: We don't check the IPv6 nexthdr here. */

		th = &_th;
		ofs = inner_ip_ofs + sizeof(struct ipv6hdr);
		if (!fill_tcp_from_icmp(skb, ofs, th))
			return NF_DROP;

		break;

	case IPPROTO_TCP:
		th = skb_header_pointer(skb, ofs, sizeof(_th), &_th);
		if (th == NULL)
			return NF_DROP;

		break;

	case IPPROTO_UDP:
		return XT_CONTINUE;

	default:
		return NF_DROP;
	}

	PRINT_DEBUG(KERN_ERR "IP<%08x,%08x> GUE<> %sIPv6<%08x %08x %08x %08x,%08x %08x %08x %08x> TCP<%d,%d flags %c%c%c%c%c>\n",
		outer_ip->saddr, outer_ip->daddr,
		is_icmp_pkt_too_big ? "IPv6<> ICMPv6<PacketTooBig> " : "",
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

	return glbredirect_handle_inner_tcp_generic(net, skb, outer_ip, glb_routing, gue_cr_ofs, is_icmp_pkt_too_big ? 0 : inner_ip_ofs, NULL, inner_ip_v6, th);
}

static unsigned int glbredirect_handle_inner_ipv4(struct net *net, struct sk_buff *skb, struct iphdr *outer_ip, struct glbgue_chained_routing *glb_routing, int gue_cr_ofs, int inner_ip_ofs)
{
	struct iphdr *inner_ip_v4, _inner_ip_v4;
	struct icmphdr *icmph, _icmph;
	struct tcphdr *th, _th;
	uint32_t tmp_addr;
	bool is_icmp_pkt_too_big = 0;
	int ofs;

	DROP_ON(net == NULL);
	DROP_ON(skb == NULL);
	DROP_ON(outer_ip == NULL);
	DROP_ON(glb_routing == NULL);

	inner_ip_v4 = skb_header_pointer(skb, inner_ip_ofs, sizeof(_inner_ip_v4), &_inner_ip_v4);
	if (inner_ip_v4 == NULL)
		return NF_DROP;

	/* We need to process TCP packets and ICMP messages used in
	 * path MTU discovery, since they have flow state.
	 * Other ICMP and UDP (the only others forwarded by glb-director) are
	 * always handled by the first host since they have no socket.
	 * Other protocols are an error.
	 */
	ofs = inner_ip_ofs + (inner_ip_v4->ihl * 4);

	switch (inner_ip_v4->protocol) {
	case IPPROTO_ICMP:
		icmph = skb_header_pointer(skb, ofs, sizeof(_icmph), &_icmph);
		if (icmph == NULL)
			return NF_DROP;

		if (icmph->type != ICMP_DEST_UNREACH || icmph->code != ICMP_FRAG_NEEDED)
			return XT_CONTINUE;

		is_icmp_pkt_too_big = 1;

		inner_ip_v4 = &_inner_ip_v4;
		inner_ip_ofs = ofs + sizeof(struct icmphdr);
		if (skb_copy_bits(skb, inner_ip_ofs, inner_ip_v4, sizeof(*inner_ip_v4)))
			return NF_DROP;

		/* Same deal as with ports: this is a packet from the
		 * return flow, adjust accordingly.
		 */
		tmp_addr = inner_ip_v4->saddr;
		inner_ip_v4->saddr = inner_ip_v4->daddr;
		inner_ip_v4->daddr = tmp_addr;

		/* NB: We don't check protocol here */

		th = &_th;
		ofs = inner_ip_ofs + (inner_ip_v4->ihl * 4);
		if (!fill_tcp_from_icmp(skb, ofs, th))
			return NF_DROP;

		break;

	case IPPROTO_TCP:
		th = skb_header_pointer(skb, ofs, sizeof(_th), &_th);
		if (th == NULL)
			return NF_DROP;

		break;

	case IPPROTO_UDP:
		return XT_CONTINUE;

	default:
		return NF_DROP;
	}

	PRINT_DEBUG(KERN_ERR "IP<%08x,%08x> GUE<> %sIPv4<%08x,%08x> TCP<%d,%d flags %c%c%c%c%c>\n",
		outer_ip->saddr, outer_ip->daddr,
		is_icmp_pkt_too_big ? "IPv4<> ICMPv4<PacketTooBig> " : "",
		inner_ip_v4->saddr, inner_ip_v4->daddr,
		ntohs(th->source), ntohs(th->dest),
		th->syn ? 'S' : '.',
		th->ack ? 'A' : '.',
		th->rst ? 'R' : '.',
		th->psh ? 'P' : '.',
		th->fin ? 'F' : '.'
	);

	return glbredirect_handle_inner_tcp_generic(net, skb, outer_ip, glb_routing, gue_cr_ofs, is_icmp_pkt_too_big ? 0 : inner_ip_ofs, inner_ip_v4, NULL, th);
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
	struct glbgue_stats *s = this_cpu_ptr(percpu_stats);
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

	u64_stats_update_begin(&s->syncp);
	s->total_packets++;
	u64_stats_update_end(&s->syncp);

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
	struct glbgue_stats *s = this_cpu_ptr(percpu_stats);

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
			u64_stats_update_begin(&s->syncp);
			s->accepted_established_packets++;
			u64_stats_update_end(&s->syncp);
			sock_put(nsk);
			return 1;
		}
	}

	PRINT_DEBUG(KERN_ERR " -> checking conntrack for SYN_RECV\n");

	/* If we're not ESTABLISHED yet, check conntrack for a SYN_RECV.
	 * When syncookies aren't enabled, this will let ACKs come in to complete
	 * a connection.
	 * Only do this if we know the offset of the inner IP header (so don't
	 * check ICMP Packet Too Big).
	 */
	if (likely(inner_ip_ofs > 0)) {
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
		/* from now on no_ct_entry_unlock should be used to ensure we release this lock */

		thash = nf_conntrack_find_get(net,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
			&nf_ct_zone_dflt,
#else
			NF_CT_DEFAULT_ZONE,
#endif
			&tuple);
		if (thash == NULL)
			goto no_ct_entry_unlock;

		ct = nf_ct_tuplehash_to_ctrack(thash);
		if (ct == NULL)
			goto no_ct_entry_unlock;

		if (!nf_ct_is_dying(ct) && nf_ct_tuple_equal(&tuple, &thash->tuple)) {
			u64_stats_update_begin(&s->syncp);
			s->accepted_conntracked_packets++;
			u64_stats_update_end(&s->syncp);

			nf_ct_put(ct);
			rcu_read_unlock();
			return 1;
		}

		nf_ct_put(ct);
no_ct_entry_unlock:
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

		if (ret == 1) {
			u64_stats_update_begin(&s->syncp);
			s->accepted_syn_cookie_packets++;
			u64_stats_update_end(&s->syncp);
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
	if (e->ip.invflags & XT_INV_PROTO) {
		printk(KERN_ERR "GLBREDIRECT can only match on proto\n");
		return -EINVAL;
	}

	valid_proto = (e->ip.proto == IPPROTO_UDP);

	if (!valid_proto) {
		printk(KERN_ERR "GLBREDIRECT is incompatible with proto=%d\n",
			e->ip.proto
		);
		return -EINVAL;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0)
	return nf_ct_l3proto_try_module_get(par->family);
#else
	return 0;
#endif
}

static void glbredirect_tg4_destroy(const struct xt_tgdtor_param *par)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0)
	nf_ct_l3proto_module_put(par->family);
#endif
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

static int proc_show(struct seq_file *m, void *v)
{
	unsigned int cpu, start;
	struct glbgue_stats sum = {0};

	for_each_possible_cpu(cpu) {
		struct glbgue_stats *s = per_cpu_ptr(percpu_stats, cpu);
		struct glbgue_stats tmp = {0};

		do {
			start = u64_stats_fetch_begin(&s->syncp);
			tmp.total_packets = s->total_packets;
			tmp.accepted_syn_packets = s->accepted_syn_packets;
			tmp.accepted_last_resort_packets = s->accepted_last_resort_packets;
			tmp.accepted_established_packets = s->accepted_established_packets;
			tmp.accepted_conntracked_packets = s->accepted_conntracked_packets;
			tmp.accepted_syn_cookie_packets = s->accepted_syn_cookie_packets;
			tmp.forwarded_to_self_packets = s->forwarded_to_self_packets;
			tmp.forwarded_to_alternate_packets = s->forwarded_to_alternate_packets;
		} while (u64_stats_fetch_retry(&s->syncp, start));

		sum.total_packets += tmp.total_packets;
		sum.accepted_syn_packets += tmp.accepted_syn_packets;
		sum.accepted_last_resort_packets += tmp.accepted_last_resort_packets;
		sum.accepted_established_packets += tmp.accepted_established_packets;
		sum.accepted_conntracked_packets += tmp.accepted_conntracked_packets;
		sum.accepted_syn_cookie_packets += tmp.accepted_syn_cookie_packets;
		sum.forwarded_to_self_packets += tmp.forwarded_to_self_packets;
		sum.forwarded_to_alternate_packets += tmp.forwarded_to_alternate_packets;
	}

	seq_printf(m, "total_packets: %llu\n", sum.total_packets);
	seq_printf(m, "accepted_syn_packets: %llu\n", sum.accepted_syn_packets);
	seq_printf(m, "accepted_last_resort_packets: %llu\n", sum.accepted_last_resort_packets);
	seq_printf(m, "accepted_established_packets: %llu\n", sum.accepted_established_packets);
	seq_printf(m, "accepted_conntracked_packets: %llu\n", sum.accepted_conntracked_packets);
	seq_printf(m, "accepted_syn_cookie_packets: %llu\n", sum.accepted_syn_cookie_packets);
	seq_printf(m, "forwarded_to_self_packets: %llu\n", sum.forwarded_to_self_packets);
	seq_printf(m, "forwarded_to_alternate_packets: %llu\n", sum.forwarded_to_alternate_packets);

	return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, proc_show, NULL);
}

static const struct file_operations proc_operations = {
	.owner		= THIS_MODULE,
	.open		= proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init glbredirect_tg4_init(void)
{
	unsigned int cpu;
	int err;

	percpu_stats = alloc_percpu(struct glbgue_stats);
	if (!percpu_stats)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		struct glbgue_stats *s = per_cpu_ptr(percpu_stats, cpu);
		u64_stats_init(&s->syncp);
	}

	err = xt_register_target(&glbredirect_tg4_reg);
	if (err < 0)
		goto err1;

	proc_create(PROCFS_NAME, 0, NULL, &proc_operations);
	return 0;

err1:
	free_percpu(percpu_stats);
	return err;
}

static void __exit glbredirect_tg4_exit(void)
{
	remove_proc_subtree(PROCFS_NAME, NULL);

	xt_unregister_target(&glbredirect_tg4_reg);
	free_percpu(percpu_stats);
}

module_init(glbredirect_tg4_init);
module_exit(glbredirect_tg4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Theo Julienne <theo@github.com>");
