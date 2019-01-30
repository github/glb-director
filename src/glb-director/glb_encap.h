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

#include <rte_ether.h>
#include <rte_ip.h>

#define IPV6_ADDR_SIZE 16

struct glb_fwd_config_ctx;
struct glb_fwd_config_content_table;

struct icmpv6_hdr {
	uint8_t type, code;
	uint16_t checksum;
} __attribute__((__packed__));

struct icmpv6_too_big_hdr {
	uint32_t mtu;
} __attribute__((__packed__));

struct l4_ports_hdr {
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((__packed__));

/* Incoming packets can either be:
 *   Ethernet / IP(v4/v6) / TCP|UDP / ...
 *   Ethernet / IP(v4/v6) / ICMP / IP(v4/v6) / TCP|UDP ...
 *
 * We take the latter as the worst case.
 * IPv6 header is longer than IPv4, so we account for that.
 * We only read the src/dst port of the TCP/UDP header.
 */
#define MAX_PARSED_HEADER_SIZE ( \
	sizeof(struct ether_hdr) + \
	sizeof(struct ipv6_hdr) + \
	sizeof(struct icmpv6_hdr) + sizeof(struct icmpv6_too_big_hdr) + \
	sizeof(struct ipv6_hdr) + \
	sizeof(struct l4_ports_hdr) \
)

/* The maximum amount of data we can hash on.
 * IPv6 addresses are biggest, so we use those, plus src/dst port.
 */
#define MAX_HASH_DATA_SIZE ( \
	IPV6_ADDR_SIZE + \
	IPV6_ADDR_SIZE + \
	sizeof(uint16_t) + \
	sizeof(uint16_t) \
)

#define MAX_HOPS 4

typedef struct {
	// aiding simple header extraction by maintaining state
	uint8_t linearisation_space[MAX_PARSED_HEADER_SIZE];
	uint32_t linearisation_space_offset;
	void *packet_data;
	uint32_t offset;

	// extracted fields
	uint16_t ether_type;

	uint16_t ip_total_length;

	union {
		uint32_t ipv4;
		uint8_t ipv6[IPV6_ADDR_SIZE];
	} src_addr;

	union {
		uint32_t ipv4;
		uint8_t ipv6[IPV6_ADDR_SIZE];
	} dst_addr;

	uint16_t src_port;
	uint16_t dst_port;

	// a hint used to spread flows across different RX queues via UDP source port.
	uint16_t flow_hash_hint;

	// mapped based on IPv4/IPv6
	uint8_t gue_ipproto;

	// calculated hops
	uint8_t hop_count;
	uint32_t ipv4_hops[MAX_HOPS];
	
	uint64_t pkt_hash;
} glb_route_context;

const void *encap_packet_data_read(void *packet_data, uint32_t off, uint32_t len, void *buf);

int glb_calculate_packet_route(struct glb_fwd_config_ctx *ctx, unsigned int table_id,
			  void *packet_data, glb_route_context *route_context);

/* Returns the size required to encapsulate a packet for the given route context.
 * Note that space is included for N-1 hops because the first hop is used as dst_addr.
 */
#define ROUTE_CONTEXT_ENCAP_SIZE(route_context)                 \
	(sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +   \
	 sizeof(struct udp_hdr) + sizeof(struct glb_gue_hdr) +  \
	 (sizeof(uint32_t) * ((route_context)->hop_count - 1)))

int glb_encapsulate_packet(struct ether_hdr *eth_hdr, glb_route_context *route_context);

struct glb_gue_hdr {
	uint8_t version_control_hlen;
	uint8_t protocol;
	uint16_t flags;

	// GUE private data.
	// we only support holding GLB GUE chained routing
	uint16_t private_type; // will be 0
	uint8_t next_hop;
	uint8_t hop_count;

	uint32_t hops[];
} __attribute__((__packed__));
