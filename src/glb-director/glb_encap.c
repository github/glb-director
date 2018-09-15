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

#define safely_get_next_header(route_context, type) ( (const type *)_safely_get_next_header(route_context, sizeof(type)) )
static inline const void *_safely_get_next_header(glb_route_context *route_context, int len)
{
	// get some safe space that we can linearlise packet data into in case it's segmented
	uint8_t *safe_space = &route_context->linearisation_space[route_context->linearisation_space_offset];
	route_context->linearisation_space_offset += len;
	if (unlikely(route_context->linearisation_space_offset > MAX_PARSED_HEADER_SIZE)) {
		return NULL;
	}

	const void *hdr = encap_packet_data_read(route_context->packet_data,
		route_context->offset, // skip headers pulled so far
		len, // pull as many bytes as requested
		safe_space // provide some safe space to linearise data to if required
	);

	route_context->offset += len;

	return hdr;
}

/* Extracts IPv4 src/dst IP and TCP/UDP src/dst port.
 * Also handles returning ICMP fragmentation packets and reads the inner IP/TCP header.
 */
static int extract_packet_fields_ipv4(glb_route_context *route_context)
{
	// extract the IPv4 header
	const struct ipv4_hdr *ipv4_hdr = safely_get_next_header(route_context, struct ipv4_hdr);
	if (unlikely(ipv4_hdr == NULL)) {
		glb_log_info("lcore: -> unexpected: could not retrieve IPv4 header, but expected it to exist");
		return -1;
	}

	route_context->ip_total_length = ntohs(ipv4_hdr->total_length);

	// special case ICMP, where we need to handle frag and echo
	if (unlikely(ipv4_hdr->next_proto_id == IPPROTO_ICMP)) {
		const struct icmp_hdr *icmp_hdr = safely_get_next_header(route_context, struct icmp_hdr);
		if (unlikely(icmp_hdr == NULL)) {
			glb_log_info("lcore: -> unexpected: could not retrieve ICMP header, but expected it to exist");
			return -1;
		}

		if (icmp_hdr->icmp_type == IPV4_ICMP_DESTINATION_UNREACHABLE) {
			// handle ICMP fragmentation responses
			const struct ipv4_hdr *orig_ipv4_hdr = safely_get_next_header(route_context, struct ipv4_hdr);
			const struct l4_ports_hdr *orig_l4_hdr = safely_get_next_header(route_context, struct l4_ports_hdr);
			if (unlikely(orig_ipv4_hdr == NULL || orig_l4_hdr == NULL)) {
				glb_log_info("lcore: -> unexpected: could not retrieve inner IPv4/L4 header, but expected it to exist");
				return -1;
			}

			// both port and IP are reversed, since we're looking at
			// a packet _we_ sent being returned back to us inside an ICMP response.
			// we reverse them all here so we match the same.
			route_context->src_addr.ipv4 = orig_ipv4_hdr->dst_addr;
			route_context->dst_addr.ipv4 = orig_ipv4_hdr->src_addr;
			route_context->src_port = orig_l4_hdr->dst_port;
			route_context->dst_port = orig_l4_hdr->src_port;

			// re-use the client's source port to spread across queues
			route_context->flow_hash_hint = ntohs(route_context->src_port);
		} else {
			// ICMP echo requests don't have ports, but otherwise the IP header is correct.
			route_context->src_addr.ipv4 = ipv4_hdr->src_addr;
			route_context->dst_addr.ipv4 = ipv4_hdr->dst_addr;
			route_context->src_port = 0;
			route_context->dst_port = 0;

			// ICMP echo requests are stateless, so spread using the packet ID
			route_context->flow_hash_hint = ntohs(ipv4_hdr->packet_id);
		}
	} else {
		const struct l4_ports_hdr *orig_l4_hdr = safely_get_next_header(route_context, struct l4_ports_hdr);
		if (unlikely(orig_l4_hdr == NULL)) {
			glb_log_info("lcore: -> unexpected: could not retrieve L4 header, but expected it to exist");
			return -1;
		}

		// the simple case: pull all the fields
		route_context->src_addr.ipv4 = ipv4_hdr->src_addr;
		route_context->dst_addr.ipv4 = ipv4_hdr->dst_addr;
		route_context->src_port = orig_l4_hdr->src_port;
		route_context->dst_port = orig_l4_hdr->dst_port;

		// re-use the client's source port to spread across queues
		route_context->flow_hash_hint = ntohs(route_context->src_port);
	}

	// GUE uses IP protocols, so IPv4 is "IPIP" (in this case, IP/GUE/IP)
	route_context->gue_ipproto = IPPROTO_IPIP;

	return 0;
}

/* Extracts IPv6 src/dst IP and TCP/UDP src/dst port.
 * Also handles returning ICMP fragmentation packets and reads the inner IP/TCP header.
 */
static int extract_packet_fields_ipv6(glb_route_context *route_context)
{
	// extract the IPv6 header
	const struct ipv6_hdr *ipv6_hdr = safely_get_next_header(route_context, struct ipv6_hdr);
	if (unlikely(ipv6_hdr == NULL)) {
		glb_log_info("lcore: -> unexpected: could not retrieve IPv6 header, but expected it to exist");
		return -1;
	}

	route_context->ip_total_length = sizeof(struct ipv6_hdr) + ntohs(ipv6_hdr->payload_len);

	// special case ICMP, where we need to handle frag and echo
	if (unlikely(ipv6_hdr->proto == IPPROTO_ICMPV6)) {
		const struct icmpv6_hdr *icmp_hdr = safely_get_next_header(route_context, struct icmpv6_hdr);
		if (unlikely(icmp_hdr == NULL)) {
			glb_log_info("lcore: -> unexpected: could not retrieve ICMPv6 header, but expected it to exist");
			return -1;
		}

		if (icmp_hdr->type == IPV6_ICMP_PACKET_TOO_BIG) {
			// handle ICMP fragmentation responses
			safely_get_next_header(route_context, struct icmpv6_too_big_hdr);
			const struct ipv6_hdr *orig_ipv6_hdr = safely_get_next_header(route_context, struct ipv6_hdr);
			const struct l4_ports_hdr *orig_l4_hdr = safely_get_next_header(route_context, struct l4_ports_hdr);
			if (unlikely(orig_ipv6_hdr == NULL || orig_l4_hdr == NULL)) {
				glb_log_info("lcore: -> unexpected: could not retrieve inner IPv6/L4 header, but expected it to exist");
				return -1;
			}

			// both port and IP are reversed, since we're looking at
			// a packet _we_ sent being returned back to us inside an ICMP response.
			// we reverse them all here so we match the same.
			memcpy(route_context->src_addr.ipv6, orig_ipv6_hdr->dst_addr, IPV6_ADDR_SIZE);
			memcpy(route_context->dst_addr.ipv6, orig_ipv6_hdr->src_addr, IPV6_ADDR_SIZE);
			route_context->src_port = orig_l4_hdr->dst_port;
			route_context->dst_port = orig_l4_hdr->src_port;

			// re-use the client's source port to spread across queues
			route_context->flow_hash_hint = ntohs(route_context->src_port);
		} else {
			// ICMP echo requests don't have ports, but otherwise the IP header is correct.
			memcpy(route_context->src_addr.ipv6, ipv6_hdr->src_addr, IPV6_ADDR_SIZE);
			memcpy(route_context->dst_addr.ipv6, ipv6_hdr->dst_addr, IPV6_ADDR_SIZE);
			route_context->src_port = 0;
			route_context->dst_port = 0;

			// ICMP echo requests are stateless, so spread using the packet ID
			route_context->flow_hash_hint = ntohs(ipv6_hdr->vtc_flow);
		}
	} else {
		const struct l4_ports_hdr *orig_l4_hdr = safely_get_next_header(route_context, struct l4_ports_hdr);
		if (unlikely(orig_l4_hdr == NULL)) {
			glb_log_info("lcore: -> unexpected: could not retrieve L4 header, but expected it to exist");
			return -1;
		}

		// the simple case: pull all the fields
		memcpy(route_context->src_addr.ipv6, ipv6_hdr->src_addr, IPV6_ADDR_SIZE);
		memcpy(route_context->dst_addr.ipv6, ipv6_hdr->dst_addr, IPV6_ADDR_SIZE);
		route_context->src_port = orig_l4_hdr->src_port;
		route_context->dst_port = orig_l4_hdr->dst_port;

		// re-use the client's source port to spread across queues
		route_context->flow_hash_hint = ntohs(route_context->src_port);
	}

	route_context->gue_ipproto = IPPROTO_IPV6;

	return 0;
}

/* Extracts ethernet proto, then passes on to the appropriate _ipv4/_ipv6 function to process
 * the inner headers.
 */
static int extract_packet_fields(glb_route_context *route_context)
{
	// extract the ethernet header to retrieve the ether_type
	const struct ether_hdr *eth_hdr = safely_get_next_header(route_context, struct ether_hdr);
	if (unlikely(eth_hdr == NULL)) {
		glb_log_info("lcore: -> unexpected: could not retrieve ethernet header");
		return -1;
	}

	route_context->ether_type = ntohs(eth_hdr->ether_type);

	if (likely(route_context->ether_type == ETHER_TYPE_IPv4)) {
		return extract_packet_fields_ipv4(route_context);
	} else if (likely(route_context->ether_type == ETHER_TYPE_IPv6)) {
		return extract_packet_fields_ipv6(route_context);
	} else {
		glb_log_info("lcore: -> unexpected: unknown ethertype (%04x), should not have matched", eth_hdr->ether_type);
		return -1;
	}
}

/* Adds 2 hops for the given route context, based on the hash configuration provided.
 * There must be at least 2 free slots in the hop list.
 */
static int glb_add_packet_route(struct glb_fwd_config_content_table *table, glb_route_context *route_context, glb_director_hash_fields *hash_field_cfg)
{
	uint8_t hash_buf[MAX_HASH_DATA_SIZE];
	int hash_len = 0;

	if (likely(route_context->ether_type == ETHER_TYPE_IPv4)) {
		if (hash_field_cfg->src_addr) {
			memcpy(&hash_buf[hash_len], &route_context->src_addr.ipv4, sizeof(route_context->src_addr.ipv4));
			hash_len += sizeof(route_context->src_addr.ipv4);
		}

		if (hash_field_cfg->dst_addr) {
			memcpy(&hash_buf[hash_len], &route_context->dst_addr.ipv4, sizeof(route_context->dst_addr.ipv4));
			hash_len += sizeof(route_context->dst_addr.ipv4);
		}
	} else if (likely(route_context->ether_type == ETHER_TYPE_IPv6)) {
		if (hash_field_cfg->src_addr) {
			memcpy(&hash_buf[hash_len], route_context->src_addr.ipv6, sizeof(route_context->src_addr.ipv6));
			hash_len += sizeof(route_context->src_addr.ipv6);
		}

		if (hash_field_cfg->dst_addr) {
			memcpy(&hash_buf[hash_len], route_context->dst_addr.ipv6, sizeof(route_context->dst_addr.ipv6));
			hash_len += sizeof(route_context->dst_addr.ipv6);
		}
	} else {
		glb_log_info("lcore: -> packet wasn't IPv4 or IPv6, not forwarding.");
		return -1;
	}

	if (hash_field_cfg->src_port) {
		memcpy(&hash_buf[hash_len], &route_context->src_port, sizeof(route_context->src_port));
		hash_len += sizeof(route_context->src_port);
	}

	if (hash_field_cfg->dst_port) {
		memcpy(&hash_buf[hash_len], &route_context->dst_port, sizeof(route_context->dst_port));
		hash_len += sizeof(route_context->dst_port);
	}

	uint64_t pkt_hash = 0;
	siphash((uint8_t *)&pkt_hash, hash_buf, hash_len, table->secure_key);

	// Match packets onto the via (first hop) and alt (second hop)
	uint64_t hash_idx = pkt_hash & GLB_FMT_TABLE_HASHMASK;
	struct glb_fwd_config_content_table_entry *table_entry = &table->entries[hash_idx];
	uint32_t primary_idx = table_entry->primary;
	uint32_t secondary_idx = table_entry->secondary;
	struct glb_fwd_config_content_table_backend *primary = &table->backends[primary_idx];
	struct glb_fwd_config_content_table_backend *secondary = &table->backends[secondary_idx];

	// include both hops as viable servers, in order.
	if (unlikely(route_context->hop_count + 2 > MAX_HOPS)) {
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
	route_context->offset = 0;
	route_context->linearisation_space_offset = 0;

	// do the thing
	if (extract_packet_fields(route_context) != 0) {
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

	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ipv4_hdr + 1);
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

	ipv4_hdr->version_ihl = IP_VHL_DEF;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->total_length =
	    htons(sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) +
		  sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * remaining_hop_count) +
		  inner_ip_total_length);
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->fragment_offset = IP_DN_FRAGMENT_FLAG;
	ipv4_hdr->time_to_live = IP_DEFTTL;
	ipv4_hdr->next_proto_id = IPPROTO_UDP;
	ipv4_hdr->hdr_checksum = 0;
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
	udp_hdr->dgram_len =
	    htons(sizeof(struct udp_hdr) +
	      sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * remaining_hop_count) +
		  inner_ip_total_length);
	udp_hdr->dgram_cksum = 0;

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
