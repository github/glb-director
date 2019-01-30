/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018 GitHub.
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

#include <arpa/inet.h>
#include <pcap.h>

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_encap_pcap.h"
#include "glb_fwd_config.h"
#include "log.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#define INBOUND_HEADER_SIZE_L3 \
	(sizeof(struct ipv4_hdr) + \
	 sizeof(struct tcp_hdr))

#define INBOUND_HEADER_SIZE_L2 \
	(sizeof(struct ether_hdr) + INBOUND_HEADER_SIZE_L3)

const void *encap_packet_data_read(void *packet_data, uint32_t off, uint32_t len, void *buf)
{
	pcap_packet *pkt = (pcap_packet *)packet_data;
	// simulates rte_pktmbuf_read, except we don't need to linearize because our pkt is already contiguous memory.
	// we only need to make sure we're not reading past the end of the packet.
	if (pkt->len < off + len)
		return NULL;
	return &pkt->data[off];
}

int glb_encapsulate_packet_pcap(struct glb_fwd_config_ctx *ctx, pcap_packet *pkt,
				unsigned int table_id)
{

	if (table_id >= ctx->raw_config->num_tables) {
		glb_log_info("lcore: -> matched a table that was out of range");
		return -1;
	}

	char orig_src_ip[INET_ADDRSTRLEN];
	char orig_dst_ip[INET_ADDRSTRLEN];

	{
		struct ipv4_hdr ipv4_hdr_buf;
		struct ipv4_hdr *orig_ipv4_hdr = (struct ipv4_hdr *)encap_packet_data_read(pkt, sizeof(struct ether_hdr), sizeof(struct ipv4_hdr), &ipv4_hdr_buf);

		inet_ntop(AF_INET, &(orig_ipv4_hdr->src_addr), orig_src_ip,
			  INET_ADDRSTRLEN);

		inet_ntop(AF_INET, &(orig_ipv4_hdr->dst_addr), orig_dst_ip,
			  INET_ADDRSTRLEN);
	}

	glb_route_context route_context;

	int ret = 0;
	ret = glb_calculate_packet_route(ctx, table_id, pkt, &route_context);

	if (ret != 0) {
		glb_log_info(
		    "lcore: -> failed to get primary/secondary mapping");
		return -1;
	}

	/* simulate rte_pktmbuf_adj taking away the old ethernet header
	 * and rte_pktmbuf_prepend adding in the new encapsulation headers.
	 * essentially, take the inbound IP+TCP headers and put them after
	 * space for ROUTE_CONTEXT_ENCAP_SIZE(..)
	 */
	if (pkt->len < INBOUND_HEADER_SIZE_L3) {
		glb_log_info(
		    "lcore: -> glb_encap_pcap failed: packet smaller than L3 inbound header size");
		return -1;
	}
	u_char encap_copy[ROUTE_CONTEXT_ENCAP_SIZE(&route_context) + INBOUND_HEADER_SIZE_L3];
	memcpy(&encap_copy[ROUTE_CONTEXT_ENCAP_SIZE(&route_context)], pkt->data, INBOUND_HEADER_SIZE_L3);
	struct ether_hdr *eth_hdr = (struct ether_hdr *)&encap_copy;

	if (glb_encapsulate_packet(eth_hdr, &route_context) != 0) {
		return -1;
	}

	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ipv4_hdr + 1);
	struct glb_gue_hdr *gue_hdr = (struct glb_gue_hdr *)(udp_hdr + 1);

	char via_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ipv4_hdr->dst_addr), via_ip, INET_ADDRSTRLEN);

	char alt_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(gue_hdr->hops[0]), alt_ip, INET_ADDRSTRLEN);

	glb_log_info(
	    "[packet] src: %s, flow_hash:%d, dst: %s, hash:%016lx, via_ip: %s alt_ip: "
	    "%s, fou_port:%d",
	    orig_src_ip, route_context.flow_hash_hint, orig_dst_ip, route_context.pkt_hash, via_ip,
	    alt_ip, udp_hdr->dst_port);

	return 0;
}

void glb_pcap_handler(configuration args[], const struct pcap_pkthdr *pkthdr,
		      const u_char *pkt)
{
	glb_log_info("[glb-pcap-mode] start packet processing");

	int ret;
	int table_id = args[0].table_id;
	struct glb_fwd_config_ctx *ctx = args[0].ctx;
	u_char copy_pkt[INBOUND_HEADER_SIZE_L2];

	if (pkthdr->caplen < INBOUND_HEADER_SIZE_L2 || pkthdr->caplen > pkthdr->len) {
		glb_log_info(
		    "[glb-pcap-mode] error: bad pcap caplen (%d, packet "
		    "len: %d), skipping ...",
		    pkthdr->caplen, pkthdr->len);
	} else {
		glb_log_info("[glb-pcap-mode] caplen %d", pkthdr->caplen);
		glb_log_info("[glb-pcap-mode] len %d", pkthdr->len);
		glb_log_info("[glb-pcap-mode] memcpy %lu", INBOUND_HEADER_SIZE_L2);

		memcpy(copy_pkt, pkt, INBOUND_HEADER_SIZE_L2);

		glb_log_info("[glb-pcap-mode] encap");
		pcap_packet pkt;
		pkt.data = copy_pkt;
		pkt.len = pkthdr->caplen;
		ret = glb_encapsulate_packet_pcap(ctx, &pkt, table_id);

		if (ret != 0) {
			glb_log_info("packet encap failed! (ts: %ld.%06ld)",
				     pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
		}

		glb_log_info("[glb-pcap-mode] end packet processing");
	}
}
