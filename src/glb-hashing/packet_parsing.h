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

#ifndef PACKET_PARSING_H
#define PACKET_PARSING_H

#include <stdint.h>

#include <glb-hashing/pdnet.h>
#include <glb-hashing/glb_gue.h>
#include <glb-hashing/glb_siphash24.h>

/* Returns the size required to encapsulate a packet for the given route context.
 * Note that space is included for N-1 hops because the first hop is used as dst_addr.
 */
#define ROUTE_CONTEXT_ENCAP_SIZE(route_context)                 \
	(sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv4_hdr) +   \
	 sizeof(struct pdnet_udp_hdr) + sizeof(struct glb_gue_hdr) +  \
	 (sizeof(uint32_t) * ((route_context)->hop_count - 1)))

/* Incoming packets can either be:
 *   Ethernet / IP(v4/v6) / TCP|UDP / ...
 *   Ethernet / IP(v4/v6) / ICMP / IP(v4/v6) / TCP|UDP ...
 *
 * We take the latter as the worst case.
 * IPv6 header is longer than IPv4, so we account for that.
 * We only read the src/dst port of the TCP/UDP header.
 */
#define MAX_PARSED_HEADER_SIZE ( \
	sizeof(struct pdnet_ethernet_hdr) + \
	sizeof(struct pdnet_ipv6_hdr) + \
	sizeof(struct pdnet_icmpv6_hdr) + sizeof(struct pdnet_icmpv6_too_big_hdr) + \
	sizeof(struct pdnet_ipv6_hdr) + \
	sizeof(struct pdnet_l4_ports_hdr) \
)

/* The maximum amount of data we can hash on.
 * IPv6 addresses are biggest, so we use those, plus src/dst port.
 */
#define MAX_HASH_DATA_SIZE ( \
	PDNET_IPV6_ADDR_SIZE + \
	PDNET_IPV6_ADDR_SIZE + \
	sizeof(uint16_t) + \
	sizeof(uint16_t) \
)

#define GLB_MAX_HOPS 4

typedef struct __attribute__((aligned)) {
	// aiding simple header extraction by maintaining state
#ifdef GLB_PACKET_PARSING_LINEARISER
	uint8_t linearisation_space[MAX_PARSED_HEADER_SIZE];
	uint32_t linearisation_space_offset;
	void *packet_data;
#else
#  ifdef GLB_PACKET_PARSING_RAW
    uint8_t *packet_start;
    uint8_t *packet_end;
#  else
#    error "Either GLB_PACKET_PARSING_LINEARISER or GLB_PACKET_PARSING_RAW must be defined"
#  endif
#endif

	// extracted fields
	uint16_t ether_type;
    struct pdnet_mac_addr orig_dst_mac;

	uint16_t ip_total_length;

	union {
		uint32_t ipv4;
		struct pdnet_ipv6_addr ipv6;
	} src_addr;

	union {
		uint32_t ipv4;
		struct pdnet_ipv6_addr ipv6;
	} dst_addr;

	uint16_t src_port;
	uint16_t dst_port;

	// a hint used to spread flows across different RX queues via UDP source port.
	uint16_t flow_hash_hint;

	// mapped based on IPv4/IPv6
	uint8_t gue_ipproto;
    uint8_t original_ipproto;

	// calculated hops
	uint8_t hop_count;
	uint32_t ipv4_hops[GLB_MAX_HOPS];
	
	uint64_t pkt_hash;
} glb_route_context;

#ifdef GLB_PACKET_PARSING_LINEARISER
static __always_inline const void *_safely_get_header(glb_route_context *route_context, uint32_t offset, int len)
{
	// get some safe space that we can linearlise packet data into in case it's segmented
	uint8_t *safe_space = &route_context->linearisation_space[route_context->linearisation_space_offset];
	route_context->linearisation_space_offset += len;
	if (unlikely(route_context->linearisation_space_offset > MAX_PARSED_HEADER_SIZE)) {
		return NULL;
	}

	const void *hdr = encap_packet_data_read(route_context->packet_data,
		offset, // skip headers pulled so far
		len, // pull as many bytes as requested
		safe_space // provide some safe space to linearise data to if required
	);

	return hdr;
}
#define SAFELY_GET_HEADER_OR_RETURN(dst, route_context, offset, type) do { \
    dst = ( (const type *)_safely_get_header(route_context, offset, sizeof(type)) ); \
    if (dst == NULL) return -1; \
    } while (0)
#else
#define SAFELY_GET_HEADER_OR_RETURN(dst, route_context, offset, type) do { \
    dst = (const type *)((route_context)->packet_start + (offset)); \
    if ((uint8_t *)((dst) + 1) > (route_context)->packet_end) return -1; \
    } while (0)
#endif

/* Extracts IPv4 src/dst IP and TCP/UDP src/dst port.
 * Also handles returning ICMP fragmentation packets and reads the inner IP/TCP header.
 */
static __always_inline int extract_packet_fields_ipv4(glb_route_context *route_context)
{
	// extract the IPv4 header
	const struct pdnet_ipv4_hdr *ipv4_hdr;
    SAFELY_GET_HEADER_OR_RETURN(ipv4_hdr, route_context, sizeof(struct pdnet_ethernet_hdr), struct pdnet_ipv4_hdr);

	route_context->ip_total_length = ntohs(ipv4_hdr->total_length);
    route_context->original_ipproto = ipv4_hdr->next_proto;
    
	// special case ICMP, where we need to handle frag and echo
	if (unlikely(ipv4_hdr->next_proto == PDNET_IP_PROTO_ICMPV4)) {
		const struct pdnet_icmpv4_hdr *icmp_hdr;
        SAFELY_GET_HEADER_OR_RETURN(
            icmp_hdr,
            route_context,
            sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv4_hdr),
            struct pdnet_icmpv4_hdr
        );
        
		if (icmp_hdr->type == PDNET_ICMPV4_TYPE_DESTINATION_UNREACHABLE) {
			// handle ICMP fragmentation responses
			const struct pdnet_ipv4_hdr *orig_ipv4_hdr;
            SAFELY_GET_HEADER_OR_RETURN(
                orig_ipv4_hdr,
                route_context,
                sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv4_hdr) + sizeof(struct pdnet_icmpv4_hdr),
                struct pdnet_ipv4_hdr
            );
			const struct pdnet_l4_ports_hdr *orig_l4_hdr;
            SAFELY_GET_HEADER_OR_RETURN(
                orig_l4_hdr,
                route_context,
                sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv4_hdr) + sizeof(struct pdnet_icmpv4_hdr) + sizeof(struct pdnet_ipv4_hdr),
                struct pdnet_l4_ports_hdr
            );

			// both port and IP are reversed, since we're looking at
			// a packet _we_ sent being returned back to us inside an ICMP response.
			// we reverse them all here so we match the same.
			route_context->src_addr.ipv4 = orig_ipv4_hdr->dst_addr;
			route_context->dst_addr.ipv4 = orig_ipv4_hdr->src_addr;
			route_context->src_port = orig_l4_hdr->dst_port;
			route_context->dst_port = orig_l4_hdr->src_port;

			// re-use the client's source port to spread across queues
			route_context->flow_hash_hint = ntohs(route_context->src_port);

            // also steal the inner ipproto from the inner header
            route_context->original_ipproto = orig_ipv4_hdr->next_proto;
		} else {
			// ICMP echo requests don't have ports, but otherwise the IP header is correct.
			route_context->src_addr.ipv4 = ipv4_hdr->src_addr;
			route_context->dst_addr.ipv4 = ipv4_hdr->dst_addr;
			route_context->src_port = 0;
			route_context->dst_port = 0;

			// ICMP echo requests are stateless, so spread using the packet ID
			route_context->flow_hash_hint = ntohs(ipv4_hdr->identification);
		}
	} else {
		const struct pdnet_l4_ports_hdr *orig_l4_hdr;
        SAFELY_GET_HEADER_OR_RETURN(
            orig_l4_hdr,
            route_context,
            sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv4_hdr),
            struct pdnet_l4_ports_hdr
        );

		// the simple case: pull all the fields
		route_context->src_addr.ipv4 = ipv4_hdr->src_addr;
		route_context->dst_addr.ipv4 = ipv4_hdr->dst_addr;
		route_context->src_port = orig_l4_hdr->src_port;
		route_context->dst_port = orig_l4_hdr->dst_port;

		// re-use the client's source port to spread across queues
		route_context->flow_hash_hint = ntohs(route_context->src_port);
	}

	// GUE uses IP protocols, so IPv4 is "IPIP" (in this case, IP/GUE/IP)
	route_context->gue_ipproto = PDNET_IP_PROTO_IPIPV4;

	return 0;
}

/* Extracts IPv6 src/dst IP and TCP/UDP src/dst port.
 * Also handles returning ICMP fragmentation packets and reads the inner IP/TCP header.
 */
static __always_inline int extract_packet_fields_ipv6(glb_route_context *route_context)
{
	// extract the IPv6 header
	const struct pdnet_ipv6_hdr *ipv6_hdr;
    SAFELY_GET_HEADER_OR_RETURN(ipv6_hdr, route_context, sizeof(struct pdnet_ethernet_hdr), struct pdnet_ipv6_hdr);

#ifdef EBPF_VERIFIER_GUARD
    if ((uint8_t *)(ipv6_hdr + 1) > route_context->packet_end) return -1;
#endif

	route_context->ip_total_length = sizeof(struct pdnet_ipv6_hdr) + ntohs(ipv6_hdr->payload_len);
    route_context->original_ipproto = ipv6_hdr->next_proto;

	// special case ICMP, where we need to handle frag and echo
	if (unlikely(ipv6_hdr->next_proto == PDNET_IP_PROTO_ICMPV6)) {
		const struct pdnet_icmpv6_hdr *icmp_hdr;
        SAFELY_GET_HEADER_OR_RETURN(
            icmp_hdr,
            route_context,
            sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv6_hdr),
            struct pdnet_icmpv6_hdr
        );

		if (icmp_hdr->type == PDNET_ICMPV6_TYPE_PACKET_TOO_BIG) {
			// handle ICMP fragmentation responses
            struct _inner_ipv6_l4 {
                // we need to munge this into one "header" otherwise LLVM tries to be too smart
                // and notices the first one's NULL check is a tautology because of the second one,
                // which leaves the first unbounded and breaks the eBPF verifier. smart, but not
                // quite smart enough.
                struct pdnet_ipv6_hdr orig_ipv6_hdr;
                struct pdnet_l4_ports_hdr orig_l4_hdr;
            } __attribute__((__packed__));
			/* there is a `struct pdnet_icmpv6_too_big_hdr` here that we don't need, so we just read past it */
			const struct _inner_ipv6_l4 *orig_pkt;
            SAFELY_GET_HEADER_OR_RETURN(
                orig_pkt,
                route_context,
                sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv6_hdr) + 
                    sizeof(struct pdnet_icmpv6_hdr) + sizeof(struct pdnet_icmpv6_too_big_hdr),
                struct _inner_ipv6_l4
            );

#ifdef EBPF_VERIFIER_GUARD
            if ((uint8_t *)(orig_pkt + 1) > route_context->packet_end) return -1;
#endif

			// both port and IP are reversed, since we're looking at
			// a packet _we_ sent being returned back to us inside an ICMP response.
			// we reverse them all here so we match the same.
			// memcpy(&route_context->src_addr.ipv6, &orig_ipv6_hdr->dst_addr, PDNET_IPV6_ADDR_SIZE);
			// memcpy(&route_context->dst_addr.ipv6, &orig_ipv6_hdr->src_addr, PDNET_IPV6_ADDR_SIZE);
            route_context->src_addr.ipv6 = orig_pkt->orig_ipv6_hdr.dst_addr;
            route_context->dst_addr.ipv6 = orig_pkt->orig_ipv6_hdr.src_addr;
			route_context->src_port = orig_pkt->orig_l4_hdr.dst_port;
			route_context->dst_port = orig_pkt->orig_l4_hdr.src_port;

			// re-use the client's source port to spread across queues
			route_context->flow_hash_hint = ntohs(route_context->src_port);

            // also steal the inner ipproto from the inner header
            route_context->original_ipproto = orig_pkt->orig_ipv6_hdr.next_proto;
		} else {
			// ICMP echo requests don't have ports, but otherwise the IP header is correct.
			// memcpy(&route_context->src_addr.ipv6, &ipv6_hdr->src_addr, PDNET_IPV6_ADDR_SIZE);
			// memcpy(&route_context->dst_addr.ipv6, &ipv6_hdr->dst_addr, PDNET_IPV6_ADDR_SIZE);
            route_context->src_addr.ipv6 = ipv6_hdr->src_addr;
            route_context->dst_addr.ipv6 = ipv6_hdr->dst_addr;
			route_context->src_port = 0;
			route_context->dst_port = 0;

			// ICMP echo requests are stateless, so spread using the packet ID
			route_context->flow_hash_hint = ntohs(pdnet_ipv6_hdr_get_flow(ipv6_hdr) & 0xffff);
		}
	} else {
		const struct pdnet_l4_ports_hdr *orig_l4_hdr;
        SAFELY_GET_HEADER_OR_RETURN(
            orig_l4_hdr,
            route_context,
            sizeof(struct pdnet_ethernet_hdr) + sizeof(struct pdnet_ipv6_hdr),
            struct pdnet_l4_ports_hdr
        );

		// the simple case: pull all the fields
		// memcpy(&route_context->src_addr.ipv6, &ipv6_hdr->src_addr, PDNET_IPV6_ADDR_SIZE);
		// memcpy(&route_context->dst_addr.ipv6, &ipv6_hdr->dst_addr, PDNET_IPV6_ADDR_SIZE);
        route_context->src_addr.ipv6 = ipv6_hdr->src_addr;
        route_context->dst_addr.ipv6 = ipv6_hdr->dst_addr;
		route_context->src_port = orig_l4_hdr->src_port;
		route_context->dst_port = orig_l4_hdr->dst_port;

		// re-use the client's source port to spread across queues
		route_context->flow_hash_hint = ntohs(route_context->src_port);
	}

	route_context->gue_ipproto = PDNET_IP_PROTO_IPIPV6;

	return 0;
}

/* Extracts ethernet proto, then passes on to the appropriate _ipv4/_ipv6 function to process
 * the inner headers.
 */
static __always_inline int glb_extract_packet_fields(glb_route_context *route_context)
{
    /* set all the variables to be safe */
	route_context->ip_total_length = 0;
    route_context->src_addr.ipv4 = 0;
    route_context->dst_addr.ipv4 = 0;
    route_context->src_port = 0;
    route_context->dst_port = 0;
    route_context->flow_hash_hint = 0;
    route_context->gue_ipproto = 0;
    route_context->original_ipproto = 0;
    route_context->hop_count = 0;
	route_context->pkt_hash = 0;

	// extract the ethernet header to retrieve the ether_type
	const struct pdnet_ethernet_hdr *eth_hdr;
    SAFELY_GET_HEADER_OR_RETURN(eth_hdr, route_context, 0, struct pdnet_ethernet_hdr);

	route_context->ether_type = ntohs(eth_hdr->ether_type);
    route_context->orig_dst_mac = eth_hdr->dst_addr;

	if (likely(route_context->ether_type == PDNET_ETHER_TYPE_IPV4)) {
		return extract_packet_fields_ipv4(route_context);
	} else if (likely(route_context->ether_type == PDNET_ETHER_TYPE_IPV6)) {
		return extract_packet_fields_ipv6(route_context);
	} else {
		glb_log_info("lcore: -> unexpected: unknown ethertype (%04x), should not have matched", eth_hdr->ether_type);
		return -1;
	}

    return 0;
}

static __always_inline uint8_t *_glb_hash_push_uint16(uint8_t *hash_buf, uint16_t val) {
	uint16_t *dst = (uint16_t *)hash_buf;
	*dst = val;
	return (uint8_t *)&dst[1];
}

static __always_inline uint8_t *_glb_hash_push_uint32(uint8_t *hash_buf, uint32_t val) {
	uint32_t *dst = (uint32_t *)hash_buf;
	*dst = val;
	return (uint8_t *)&dst[1];
}

static __always_inline uint8_t *_glb_hash_push_ipv6(uint8_t *hash_buf, struct pdnet_ipv6_addr val) {
	struct pdnet_ipv6_addr *dst = (struct pdnet_ipv6_addr *)hash_buf;
	*dst = val;
	return (uint8_t *)&dst[1];
}

static __always_inline uint64_t glb_compute_hash(glb_route_context *route_context, uint8_t *secret, glb_director_hash_fields *hash_field_cfg)
{
	/* glb_siphash requires that this is exactly GLB_SIPHASH_REQUIRED_IN_SIZE bytes long and zeroed out before adding real data */
	uint8_t hash_buf[GLB_SIPHASH_REQUIRED_IN_SIZE];
	memset(hash_buf, 0, GLB_SIPHASH_REQUIRED_IN_SIZE);
    uint8_t *hash_curr = hash_buf;
	int hash_len = 0;

	if (likely(route_context->ether_type == PDNET_ETHER_TYPE_IPV4)) {
		if (hash_field_cfg->src_addr) {
			// memcpy(&hash_buf[hash_len], &route_context->src_addr.ipv4, sizeof(route_context->src_addr.ipv4));
            hash_curr = _glb_hash_push_uint32(hash_curr, route_context->src_addr.ipv4);
			hash_len += sizeof(route_context->src_addr.ipv4);
		}

		if (hash_field_cfg->dst_addr) {
			// memcpy(&hash_buf[hash_len], &route_context->dst_addr.ipv4, sizeof(route_context->dst_addr.ipv4));
            hash_curr = _glb_hash_push_uint32(hash_curr, route_context->dst_addr.ipv4);
			hash_len += sizeof(route_context->dst_addr.ipv4);
		}
	} else if (likely(route_context->ether_type == PDNET_ETHER_TYPE_IPV6)) {
		if (hash_field_cfg->src_addr) {
#ifdef EBPF_VERIFIER_GUARD
            if (hash_curr + sizeof(route_context->src_addr.ipv6) > hash_buf + MAX_HASH_DATA_SIZE) return -1;
#endif
			// memcpy(&hash_buf[hash_len], &route_context->src_addr.ipv6, sizeof(route_context->src_addr.ipv6));
            hash_curr = _glb_hash_push_ipv6(hash_curr, route_context->src_addr.ipv6);
			hash_len += sizeof(route_context->src_addr.ipv6);
		}

		if (hash_field_cfg->dst_addr) {
#ifdef EBPF_VERIFIER_GUARD
            if (hash_curr + sizeof(route_context->dst_addr.ipv6) > hash_buf + MAX_HASH_DATA_SIZE) return -1;
#endif
			// memcpy(&hash_buf[hash_len], &route_context->dst_addr.ipv6, sizeof(route_context->dst_addr.ipv6));
            hash_curr = _glb_hash_push_ipv6(hash_curr, route_context->dst_addr.ipv6);
			hash_len += sizeof(route_context->dst_addr.ipv6);
		}
	} else {
		glb_log_info("lcore: -> packet wasn't IPv4 or IPv6, not forwarding.");
		return -1;
	}

	if (hash_field_cfg->src_port) {
		// memcpy(&hash_buf[hash_len], &route_context->src_port, sizeof(route_context->src_port));
        hash_curr = _glb_hash_push_uint16(hash_curr, route_context->src_port);
		hash_len += sizeof(route_context->src_port);
	}

	if (hash_field_cfg->dst_port) {
		// memcpy(&hash_buf[hash_len], &route_context->dst_port, sizeof(route_context->dst_port));
        hash_curr = _glb_hash_push_uint16(hash_curr, route_context->dst_port);
		hash_len += sizeof(route_context->dst_port);
	}

#ifdef EBPF_VERIFIER_GUARD
    if (!(hash_len > 0 && hash_len <= MAX_HASH_DATA_SIZE))
        return -1;
#endif

    uint64_t pkt_hash = 0;
    glb_siphash((uint8_t *)&pkt_hash, hash_buf, hash_len, secret);
    return pkt_hash;
}

#endif /* PACKET_PARSING_H */
