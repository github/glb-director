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
#include <stdint.h>
#include <sys/time.h>

#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_fwd_config.h"
#include "log.h"
#include "siphash24.h"

#define DIRECTOR_GUE_PORT 19523 /* 'LB' + 1 */

#define IP_VERSION 0x40
#define IP_HDRLEN 0x05 /* default IP header length == five 32-bits words. */
#define IP_DEFTTL 64   /* from RFC 1340. */
#define IP_VHL_DEF (IP_VERSION | IP_HDRLEN)
#define IP_DN_FRAGMENT_FLAG 0x0040

#define IPV4_ICMP_DESTINATION_UNREACHABLE 3
#define IPV6_ICMP_PACKET_TOO_BIG 2

int get_primary_secondary(struct glb_fwd_config_ctx *ctx, unsigned int table_id,
			  struct ether_hdr *eth_hdr, primary_secondary *p_s)
{

	struct glb_fwd_config_content_table *table =
	    &ctx->raw_config->tables[table_id];

	int ether_type = ntohs(eth_hdr->ether_type);
	int gue_ipproto = 0;

	uint64_t pkt_hash = 0;
	uint16_t ip_total_length = 0;
	uint16_t flow_hash = 0;

	if (ether_type == ETHER_TYPE_IPv4) {
		struct ipv4_hdr *inner_ipv4_hdr =
		    (struct ipv4_hdr *)(eth_hdr + 1);
		ip_total_length = ntohs(inner_ipv4_hdr->total_length);

		// default the 'hash' ptr to the location of the IP source port
		uint16_t *hash_ptr = (uint16_t *)(inner_ipv4_hdr + 1);
		uint32_t _ip = inner_ipv4_hdr->src_addr;

		if (inner_ipv4_hdr->next_proto_id == IPPROTO_ICMP) {
			struct icmp_hdr *inner_icmp_hdr =
			    (struct icmp_hdr *)(inner_ipv4_hdr + 1);

			if (inner_icmp_hdr->icmp_type == IPV4_ICMP_DESTINATION_UNREACHABLE) {
				// handle ICMP fragmentation responses
				struct ipv4_hdr *orig_ipv4_hdr =
				    (struct ipv4_hdr *)(inner_icmp_hdr + 1);

				// both port and IP are reversed, since we're looking at
				// a packet we sent inside an ICMP response.
				// use the original source port as the 'hash' to match.
				hash_ptr = ((uint16_t *)(orig_ipv4_hdr + 1)) + 1;
				_ip = orig_ipv4_hdr->dst_addr;
			} else {
				// handle ICMP echo requests.
				// _ip is already fine, but use the packet id as 'hash'
				hash_ptr = &inner_ipv4_hdr->packet_id;
			}
		}

		flow_hash = htons(*hash_ptr);
		siphash((uint8_t *)&pkt_hash, (uint8_t *)&_ip, sizeof(_ip),
			table->secure_key);

		gue_ipproto = IPPROTO_IPIP;
	} else if (ether_type == ETHER_TYPE_IPv6) {
		struct ipv6_hdr *inner_ipv6_hdr =
		    (struct ipv6_hdr *)(eth_hdr + 1);
		ip_total_length = sizeof(struct ipv6_hdr) +
				  ntohs(inner_ipv6_hdr->payload_len);

		uint16_t *hash_ptr = (uint16_t *)(inner_ipv6_hdr + 1);
		uint8_t *saddr = (uint8_t *)&inner_ipv6_hdr->src_addr;

		if (inner_ipv6_hdr->proto == IPPROTO_ICMPV6) {
			struct icmpv6_hdr *inner_icmp_hdr =
			    (struct icmpv6_hdr *)(inner_ipv6_hdr + 1);

			if (inner_icmp_hdr->type == IPV6_ICMP_PACKET_TOO_BIG) {
				// handle ICMP fragmentation responses
				struct icmpv6_too_big_hdr *too_big_hdr =
					(struct icmpv6_too_big_hdr *)(inner_icmp_hdr + 1);
				struct ipv6_hdr *orig_ipv6_hdr =
			   		(struct ipv6_hdr *)(too_big_hdr + 1);

				// both port and IP are reversed, since we're looking at
				// a packet we sent inside an ICMP response.
			   	// use the original source port as the 'hash' to match.
				hash_ptr = ((uint16_t *)(orig_ipv6_hdr + 1)) + 1;
				saddr = (uint8_t *)&orig_ipv6_hdr->dst_addr;
			} else {
				// handle ICMP echo requests.
				// _ip is already fine, but use the flow label as 'hash'
				hash_ptr = (uint16_t *)&inner_ipv6_hdr->vtc_flow;
			}
		}

		flow_hash = htons(*hash_ptr);
		siphash((uint8_t *)&pkt_hash, saddr,
			sizeof(inner_ipv6_hdr->src_addr), table->secure_key);

		gue_ipproto = IPPROTO_IPV6;
	} else {
		glb_log_info("lcore: -> packet wasn't IPv4 or IPv6, not "
			     "forwarding.");
		return -1;
	}

	// Match packets onto the via (first hop) and alt (second hop)
	uint64_t hash_idx = pkt_hash & GLB_FMT_TABLE_HASHMASK;
	struct glb_fwd_config_content_table_entry *table_entry =
	    &table->entries[hash_idx];
	uint32_t primary_idx = table_entry->primary;
	uint32_t secondary_idx = table_entry->secondary;
	struct glb_fwd_config_content_table_backend *primary =
	    &table->backends[primary_idx];
	struct glb_fwd_config_content_table_backend *secondary =
	    &table->backends[secondary_idx];
	uint32_t via_i, alt_i;

	via_i = primary->ipv4_addr;
	alt_i = secondary->ipv4_addr;

	// glb_log_info("lcore: -> classified p=%d,s=%d
	// via=%08x,alt=%08x", primary_idx, secondary_idx, via_i,
	// alt_i);
	p_s->hop_count = 1; // we only have one chained routing hop, 'alt'
	p_s->via_i = via_i;
	p_s->alt_i = alt_i;
	p_s->flow_hash = flow_hash;
	p_s->ip_total_length = ip_total_length;
	p_s->pkt_hash = pkt_hash;
	p_s->gue_ipproto = gue_ipproto;

	return 0;
}

int glb_encapsulate_packet(struct ether_hdr *eth_hdr,
			   struct ether_hdr orig_eth_hdr,
			   primary_secondary *p_s)
{

	uint32_t via_i = p_s->via_i;
	uint32_t alt_i = p_s->alt_i;
	uint16_t flow_hash = p_s->flow_hash;
	uint16_t ip_total_length = p_s->ip_total_length;
	uint64_t pkt_hash = p_s->pkt_hash;
	int gue_ipproto = p_s->gue_ipproto;

	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ipv4_hdr + 1);
	struct glb_gue_hdr *gue_hdr = (struct glb_gue_hdr *)(udp_hdr + 1);

	*eth_hdr = orig_eth_hdr;
	eth_hdr->d_addr = g_director_config->gateway_ether_addr;
	eth_hdr->s_addr = g_director_config->local_ether_addr;
	eth_hdr->ether_type = htons(ETHER_TYPE_IPv4);

	ipv4_hdr->version_ihl = IP_VHL_DEF;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->total_length =
	    htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) +
		  sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * p_s->hop_count) +
		  ip_total_length);
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->fragment_offset = IP_DN_FRAGMENT_FLAG;
	ipv4_hdr->time_to_live = IP_DEFTTL;
	ipv4_hdr->next_proto_id = IPPROTO_UDP;
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->src_addr = g_director_config->local_ip_addr;
	ipv4_hdr->dst_addr = via_i;

	// glb_log_info("lcore: -> XXX pkt_hash=%016lx, flow_hash=%d",
	// pkt_hash, flow_hash);

	/* Use the packet's entry hash and the low_hash (mostly TCP source port) to
	 * generate the UDP source port. This ties each flow to an approximately 
	 * random RX queue on the proxy hosts. Always set the high bit so we're 
	 * using a very non-confusing (ephemeral) port number.
	 */
	udp_hdr->src_port = htons(0x8000 | ((pkt_hash ^ flow_hash) & 0x7fff));
	udp_hdr->dst_port = htons(DIRECTOR_GUE_PORT);
	udp_hdr->dgram_len =
	    htons(sizeof(struct udp_hdr) +
	      sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * p_s->hop_count) +
		  ip_total_length);
	udp_hdr->dgram_cksum = 0;

	gue_hdr->private_type = 0;
	gue_hdr->next_hop = 0;
	gue_hdr->hop_count = p_s->hop_count;
	/* hlen is essentially just private data, which is 1x 32 bits, plus the number of hops */
	gue_hdr->version_control_hlen = 1 + p_s->hop_count;
	gue_hdr->protocol = gue_ipproto;
	gue_hdr->flags  = 0;
	/* alt_i is already encoded in network byte order (same as via_i above) */
	gue_hdr->hops[0] = alt_i;

	return 0;
}
