/*
   theojulienne/pdnet - A set of common IP structures for common L4 interactions.

   Copyright (c) 2020 Theo Julienne.

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef PDNET_H
#define PDNET_H

#include <stdint.h>
#include <endian.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#  undef USE_BIG_ENDIAN
#else
#  define USE_BIG_ENDIAN
#endif

/* Ethernet */
#define PDNET_MAC_ADDR_SIZE 6
struct pdnet_mac_addr {
    uint8_t addr[PDNET_MAC_ADDR_SIZE];
} __attribute__((__packed__));

struct pdnet_ethernet_hdr {
    struct pdnet_mac_addr dst_addr;
    struct pdnet_mac_addr src_addr;
    uint16_t ether_type;
} __attribute__((__packed__));

/* IPv4 */
typedef uint32_t pdnet_ipv4_addr;
struct pdnet_ipv4_hdr {
#ifdef USE_BIG_ENDIAN
    uint8_t version : 4;
    uint8_t ihl : 4;

    uint8_t dscp : 6;
    uint8_t ecn : 2;
#else
    uint8_t ihl : 4;
    uint8_t version : 4;

    uint8_t ecn : 2;
    uint8_t dscp : 6;
#endif

    uint16_t total_length;
    uint16_t identification;

    uint16_t fragment_offset;

    uint8_t time_to_live;
    uint8_t next_proto;
    uint16_t checksum;

    pdnet_ipv4_addr src_addr;
    pdnet_ipv4_addr dst_addr;
} __attribute__((__packed__));

/* the length of the above IP header in 32bit words */
#define PDNET_IPV4_HEADER_LEN 5

#define PDNET_IPV4_DEFAULT_TTL 64

#define PDNET_IPV4_VERSION 4

#define PDNET_IPV4_FLAG_DF (2 << 13) /* skip past the 13 bits of actual fragment_offset */

/* IPv6 */
#define PDNET_IPV6_ADDR_SIZE 16
struct pdnet_ipv6_addr {
    uint8_t addr[PDNET_IPV6_ADDR_SIZE];
} __attribute__((__packed__));
struct pdnet_ipv6_hdr {
#ifdef USE_BIG_ENDIAN
    uint8_t version : 4;
    uint8_t tc_hi : 4;
#else
    uint8_t tc_hi : 4;
    uint8_t version : 4;
#endif

#ifdef USE_BIG_ENDIAN
    uint8_t tc_lo : 4;
    uint8_t flow_hi : 4;
#else
    uint8_t flow_hi : 4;
    uint8_t tc_lo : 4;
#endif

    uint16_t flow_lo;

    uint16_t payload_len;
    uint8_t next_proto;
    uint8_t hop_limit;

    struct pdnet_ipv6_addr src_addr;
    struct pdnet_ipv6_addr dst_addr;
} __attribute__((__packed__));

#define pdnet_ipv6_hdr_get_flow(hdr) ((hdr->flow_hi << 16) | hdr->flow_lo)

#define PDNET_IPV6_VERSION 6

/* TCP/UDP generic port section */
struct pdnet_l4_ports_hdr {
    uint16_t src_port;
    uint16_t dst_port;
} __attribute__((__packed__));

/* TCP */
struct pdnet_tcp_hdr {
    uint16_t src_port;
    uint16_t dst_port;

    uint32_t seq_num;
    uint32_t ack_num;

#ifdef USE_BIG_ENDIAN
    uint8_t data_offset : 4;
    uint8_t reserved : 3;
    uint8_t ns : 1;
#else
    uint8_t ns : 1;
    uint8_t reserved : 3;
    uint8_t data_offset : 4;
#endif

    uint8_t cwr : 1;
    uint8_t ece : 1;
    uint8_t urg : 1;
    uint8_t ack : 1;
    uint8_t psh : 1;
    uint8_t rst : 1;
    uint8_t syn : 1;
    uint8_t fin : 1;

    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((__packed__));

/* UDP */
struct pdnet_udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((__packed__));

/* ICMPv4 */
struct pdnet_icmpv4_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;

    union {
        uint32_t type_specific;
        struct {
            uint16_t unused;
            uint16_t next_hop_mtu;
        } destination_unreachable;
    };
} __attribute__((__packed__));

#define PDNET_ICMPV4_TYPE_ECHO_REPLY 0
#define PDNET_ICMPV4_TYPE_DESTINATION_UNREACHABLE 3
#  define PDNET_ICMPV4_CODE_FRAGMENTATION_REQUIRED 4
#define PDNET_ICMPV4_TYPE_ECHO_REQUEST 8
#define PDNET_ICMPV4_TYPE_TIME_EXCEEDED 11

/* ICMPv6 */
struct pdnet_icmpv6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
} __attribute__((__packed__));

#define PDNET_ICMPV6_TYPE_DESTINATION_UNREACHABLE 1
#define PDNET_ICMPV6_TYPE_PACKET_TOO_BIG 2
#define PDNET_ICMPV6_TYPE_TIME_EXCEEDED 3
#define PDNET_ICMPV6_TYPE_PARAMETER_PROBLEM 4

struct pdnet_icmpv6_too_big_hdr {
	uint32_t mtu;
} __attribute__((__packed__));

/* Ethernet and IP protocols for the above headers */

#define PDNET_ETHER_TYPE_IPV4 0x0800
#define PDNET_ETHER_TYPE_IPV6 0x86DD

#define PDNET_IP_PROTO_ICMPV4 0x01
#define PDNET_IP_PROTO_IPIPV4   0x04
#define PDNET_IP_PROTO_IPIPV6 0x29
#define PDNET_IP_PROTO_TCP    0x06
#define PDNET_IP_PROTO_UDP    0x11
#define PDNET_IP_PROTO_ICMPV6 0x3A

#endif /* PDNET_H */
