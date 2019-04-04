/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018 GitHub.
 * Copyright (c) 2016 Intel Corporation. (original DPDK example code)
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_udp.h>

#include <arpa/inet.h>

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_encap_dpdk.h"
#include "glb_fwd_config.h"
#include "log.h"

const void *encap_packet_data_read(void *packet_data, uint32_t off, uint32_t len, void *buf)
{
	struct rte_mbuf *mbuf = (struct rte_mbuf *)packet_data;
	return rte_pktmbuf_read(mbuf, off, len, buf);
}

int glb_encapsulate_packet_dpdk(struct glb_fwd_config_ctx *ctx,
				struct rte_mbuf *pkt, unsigned int table_id)
{
	if (table_id >= ctx->raw_config->num_tables) {
		glb_log_info("lcore: -> matched a table that was out of range");
		return -1;
	}

	// incoming: Ethernet / IP(v4/v6) / TCP / ...
	//           Ethernet / IP(v4/v6) / ICMP / IP(v4/v6) / TCP ...
	// outgoing: Ethernet / IPv4 / UDP / GRE(glb) / IP(v4/v6) / ...

#ifdef GLB_DUMP_FULL_PACKET
	char orig_src_ip[INET_ADDRSTRLEN];
	char orig_dst_ip[INET_ADDRSTRLEN];

	{
		struct ipv4_hdr ipv4_hdr_buf;
		struct ipv4_hdr *orig_ipv4_hdr = (struct ipv4_hdr *)rte_pktmbuf_read(pkt, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), &ipv4_hdr_buf);

		inet_ntop(AF_INET, &(orig_ipv4_hdr->src_addr), orig_src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(orig_ipv4_hdr->dst_addr), orig_dst_ip, INET_ADDRSTRLEN);
	}
#endif

	glb_route_context route_context;

	int ret = 0;
	ret = glb_calculate_packet_route(ctx, table_id, pkt, &route_context);

	if (ret != 0) {
		glb_log_info(
		    "lcore: -> failed to get primary/secondary mapping");
		return -1;
	}

	// remove the ethernet header
	rte_pktmbuf_adj(pkt, sizeof(struct ether_hdr));

	uint32_t encap_size = sizeof(struct ether_hdr) +
			      sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) +
			      sizeof(struct glb_gue_hdr) +
			      (sizeof(uint32_t) * (route_context.hop_count - 1));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)rte_pktmbuf_prepend(pkt, encap_size);

	if (eth_hdr == NULL) {
		glb_log_info("lcore: -> no headroom for encapsulation");
		return -1;
	}

	if (glb_encapsulate_packet(eth_hdr, &route_context) != 0) {
		return -1;
	}

	if (glb_checksum_offloading(pkt, eth_hdr) != 0) {
		return -1;
	}

#ifdef GLB_DUMP_FULL_PACKET
	uint16_t ip_total_length = 0;

	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ipv4_hdr + 1);
	struct glb_gue_hdr *gue_hdr = (struct glb_gue_hdr *)(udp_hdr + 1);

	ip_total_length = ntohs(ipv4_hdr->total_length);

	char via_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ipv4_hdr->dst_addr), via_ip, INET_ADDRSTRLEN);

	char alt_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(gue_hdr->hops[0]), alt_ip, INET_ADDRSTRLEN);

	glb_log_info(
	    "[packet] src: %s:%d, dst: %s, hash:%016lx, via_ip: %s alt_ip: "
	    "%s, fou_port:%d",
	    orig_src_ip, p_s.src_port, orig_dst_ip, p_s.pkt_hash, via_ip,
	    alt_ip, udp_hdr->dst_port);

	rte_pktmbuf_dump(stdout, pkt, encap_size + ip_total_length);
#endif

	return 0;
}

int glb_checksum_offloading(struct rte_mbuf *pkt, struct ether_hdr *eth_hdr)
{
	// enable checksum ofloading
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ipv4_hdr + 1);

	pkt->l2_len = sizeof(struct ether_hdr);
	pkt->l3_len = sizeof(struct ipv4_hdr);
	pkt->packet_type =
	    RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L4_UDP;
	pkt->ol_flags |= PKT_TX_IPV4;
	pkt->ol_flags &= ~(PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM);
	// pkt->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;

	if ((pkt->ol_flags & PKT_TX_UDP_CKSUM) != 0) {
		// UDP checksum offloading - use the pseudo checksum
		udp_hdr->dgram_cksum =
		    rte_ipv4_phdr_cksum(ipv4_hdr, pkt->ol_flags);
	} else {
		// not using checksum offloading
		udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
	}

	if ((pkt->ol_flags & PKT_TX_IP_CKSUM) != 0) {
		// using IP checksum offloading
		ipv4_hdr->hdr_checksum = 0;
	} else {
		// not using checksum offloading
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	}

	return 0;
}
