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

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_fwd_config.h"
#include "log.h"
#include "siphash24.h"

#define DIRECTOR_GUE_PORT 19523 /* 'LB' + 1 */

/* Adds 2 hops for the given route context, based on the hash configuration provided.
 * There must be at least 2 free slots in the hop list.
 */
static int glb_add_packet_route(struct glb_fwd_config_content_table *table, glb_route_context *route_context, glb_director_hash_fields *hash_field_cfg)
{
	uint64_t pkt_hash = glb_compute_hash(route_context, table->secure_key, hash_field_cfg);

	// Match packets onto the via (first hop) and alt (second hop)
	uint64_t hash_idx = pkt_hash & GLB_FMT_TABLE_HASHMASK;
	struct glb_fwd_config_content_table_entry *table_entry = &table->entries[hash_idx];
	uint32_t primary_idx = table_entry->primary;
	uint32_t secondary_idx = table_entry->secondary;
	struct glb_fwd_config_content_table_backend *primary = &table->backends[primary_idx];
	struct glb_fwd_config_content_table_backend *secondary = &table->backends[secondary_idx];

	// include both hops as viable servers, in order.
	if (unlikely(route_context->hop_count + 2 > GLB_MAX_HOPS)) {
		return -1;
	}

	if (likely(route_context->hop_count == 0)) {
		// use the first calculated route as the hash for rx queue hinting/etc
		route_context->pkt_hash = pkt_hash;
	}

	route_context->ipv4_hops[route_context->hop_count] = primary->ipv4_addr;
	route_context->ipv4_hops[route_context->hop_count + 1] = secondary->ipv4_addr;
	route_context->hop_count += 2;

	return 0;
}

int glb_calculate_packet_route(struct glb_fwd_config_ctx *ctx, unsigned int table_id,
			  void *packet_data, glb_route_context *route_context)
{
	struct glb_fwd_config_content_table *table = &ctx->raw_config->tables[table_id];

	// prepare the context for reading data
	route_context->packet_data = packet_data;
	route_context->linearisation_space_offset = 0;

	// do the thing
	if (glb_extract_packet_fields(route_context) != 0) {
		return -1;
	}
	route_context->hop_count = 0;

	// Add the route using the default hash fields.
	if (glb_add_packet_route(table, route_context, &g_director_config->hash_fields) != 0) {
		return -1;
	}

	/* If we have an alternative hash field list (for migrating safely), add those too.
	 * Since these will be at the end, they will be "drained" and connections will
	 * shuffle over to the new hashed servers.
	 */
	if (g_director_config->use_alt_hash_fields) {
		if (glb_add_packet_route(table, route_context, &g_director_config->alt_hash_fields) != 0) {
			return -1;
		}
	}

	return 0;
}

/* Fills in the encapsulation data, starting at the ethernet header.
 * Expects that `eth_hdr` points to ROUTE_CONTEXT_ENCAP_SIZE(ctx) bytes of free space
 * before the inner/original IP packet header begins.
 */
int glb_encapsulate_packet(struct ether_hdr *eth_hdr, glb_route_context *route_context)
{

	uint16_t flow_hash = route_context->flow_hash_hint;
	uint16_t inner_ip_total_length = route_context->ip_total_length;
	uint64_t pkt_hash = route_context->pkt_hash;
	int gue_ipproto = route_context->gue_ipproto;

	struct pdnet_ipv4_hdr *ipv4_hdr = (struct pdnet_ipv4_hdr *)(eth_hdr + 1);
	struct pdnet_udp_hdr *udp_hdr = (struct pdnet_udp_hdr *)(ipv4_hdr + 1);
	struct glb_gue_hdr *gue_hdr = (struct glb_gue_hdr *)(udp_hdr + 1);

	/* Take the first hop to use as the IP dst_addr, then ignore it from GUE list.
	 * We support including all hops, since ROUTE_CONTEXT_ENCAP_SIZE(ctx) uses
	 * the same calculation to size our buffer for this function.
	 */
	uint32_t first_hop_ip = route_context->ipv4_hops[0];
	uint32_t remaining_hop_count = route_context->hop_count - 1;

	eth_hdr->d_addr = g_director_config->gateway_ether_addr;
	eth_hdr->s_addr = g_director_config->local_ether_addr;
	eth_hdr->ether_type = htons(ETHER_TYPE_IPv4);

	ipv4_hdr->version = PDNET_IPV4_VERSION;
	ipv4_hdr->ihl = PDNET_IPV4_HEADER_LEN;
	ipv4_hdr->dscp = 0;
	ipv4_hdr->ecn = 0;
	ipv4_hdr->total_length =
	    htons(sizeof(struct pdnet_ipv4_hdr) + sizeof(struct pdnet_udp_hdr) +
		  sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * remaining_hop_count) +
		  inner_ip_total_length);
	ipv4_hdr->identification = 0;
	ipv4_hdr->fragment_offset = htons(PDNET_IPV4_FLAG_DF);
	ipv4_hdr->time_to_live = PDNET_IPV4_DEFAULT_TTL;
	ipv4_hdr->next_proto = PDNET_IP_PROTO_UDP;
	ipv4_hdr->checksum = 0;
	ipv4_hdr->src_addr = g_director_config->local_ip_addr;
	ipv4_hdr->dst_addr = first_hop_ip;

	// glb_log_info("lcore: -> XXX pkt_hash=%016lx, flow_hash=%d",
	// pkt_hash, flow_hash);

	/* Use the packet's entry hash and the low_hash (mostly TCP source port) to
	 * generate the UDP source port. This ties each flow to an approximately 
	 * random RX queue on the proxy hosts. Always set the high bit so we're 
	 * using a very non-confusing (ephemeral) port number.
	 */
	udp_hdr->src_port = htons(0x8000 | ((pkt_hash ^ flow_hash) & 0x7fff));
	udp_hdr->dst_port = htons(DIRECTOR_GUE_PORT);
	udp_hdr->length =
	    htons(sizeof(struct pdnet_udp_hdr) +
	      sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * remaining_hop_count) +
		  inner_ip_total_length);
	udp_hdr->checksum = 0;

	gue_hdr->private_type = 0;
	gue_hdr->next_hop = 0;
	gue_hdr->hop_count = remaining_hop_count;
	/* hlen is essentially just private data, which is 1x 32 bits, plus the number of hops */
	gue_hdr->version_control_hlen = 1 + remaining_hop_count;
	gue_hdr->protocol = gue_ipproto;
	gue_hdr->flags  = 0;
	/* hops are already encoded in network byte order (same as first_hop_ip above) */
	memcpy(&gue_hdr->hops[0], &route_context->ipv4_hops[1], sizeof(uint32_t) * remaining_hop_count);

	return 0;
}
