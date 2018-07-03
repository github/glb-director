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

struct glb_fwd_config_ctx;
struct glb_fwd_config_content_table;

typedef struct {
	uint8_t hop_count;
	uint32_t via_i;
	uint32_t alt_i;
	uint16_t flow_hash;
	uint16_t ip_total_length;
	uint64_t pkt_hash;
	uint8_t gue_ipproto;
} primary_secondary;

int get_primary_secondary(struct glb_fwd_config_ctx *ctx, unsigned int table_id,
			  struct ether_hdr *eth_hdr, primary_secondary *p_s);

int glb_encapsulate_packet(struct ether_hdr *eth_hdr,
			   struct ether_hdr orig_eth_hdr,
			   primary_secondary *p_s);

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
} __attribute__((__packed__));;

struct icmpv6_hdr {
	uint8_t type, code;
	uint16_t checksum;
} __attribute__((__packed__));

struct icmpv6_too_big_hdr {
	uint32_t mtu;
} __attribute__((__packed__));
