/*
 * Rule and trace formats definitions.
 */

enum { PROTO_FIELD_IPV4,
       SRC_FIELD_IPV4,
       DST_FIELD_IPV4,
       SRCP_FIELD_IPV4,
       DSTP_FIELD_IPV4,

       ICMP_INNER_SRC_FIELD_IPV4,
       ICMP_INNER_SRCP_FIELD_IPV4,
       ICMP_INNER_DSTP_FIELD_IPV4,

       NUM_FIELDS_IPV4 };

/*
 * That effectively defines order of IPV4 classifications:
 *  - PROTO
 *  - SRC IP ADDRESS
 *  - DST IP ADDRESS
 *  - PORTS (SRC and DST)
 */
enum { RTE_ACL_IPV4_PROTO,
       RTE_ACL_IPV4_SRC,
       RTE_ACL_IPV4_DST,
       RTE_ACL_IPV4_PORTS,
       RTE_ACL_IPV4_UNUSED,
       RTE_ACL_IPV4_INNER_UNUSED1,
       RTE_ACL_IPV4_INNER_UNUSED2,
       RTE_ACL_IPV4_INNER_UNUSED3,
       RTE_ACL_IPV4_INNER_SRC,
       RTE_ACL_IPV4_INNER_DST,
       RTE_ACL_IPV4_INNER_PORTS,
       RTE_ACL_IPV4_NUM };

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
    {
	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	.size = sizeof(uint8_t),
	.field_index = PROTO_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_PROTO,
	.offset = 0,
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_SRC,
	.offset = offsetof(struct ipv4_hdr, src_addr) -
		  offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_DST,
	.offset = offsetof(struct ipv4_hdr, dst_addr) -
		  offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = SRCP_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_PORTS,
	.offset =
	    sizeof(struct ipv4_hdr) - offsetof(struct ipv4_hdr, next_proto_id),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = DSTP_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_PORTS,
	.offset = sizeof(struct ipv4_hdr) -
		  offsetof(struct ipv4_hdr, next_proto_id) + sizeof(uint16_t),
    },
    // support for ICMP introspection
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = ICMP_INNER_SRC_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_INNER_SRC,
	.offset = sizeof(struct ipv4_hdr) -
		  offsetof(struct ipv4_hdr, next_proto_id) + sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over to inner IP header
		  offsetof(struct ipv4_hdr, src_addr),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = ICMP_INNER_SRCP_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_INNER_PORTS,
	.offset = sizeof(struct ipv4_hdr) -
		  offsetof(struct ipv4_hdr, next_proto_id) + sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over to inner IP header
		  sizeof(struct ipv4_hdr),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = ICMP_INNER_DSTP_FIELD_IPV4,
	.input_index = RTE_ACL_IPV4_INNER_PORTS,
	.offset = sizeof(struct ipv4_hdr) -
		  offsetof(struct ipv4_hdr, next_proto_id) + sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over to inner IP header
		  sizeof(struct ipv4_hdr) + sizeof(uint16_t),
    },
};

#define IPV6_ADDR_LEN 16
#define IPV6_ADDR_U16 (IPV6_ADDR_LEN / sizeof(uint16_t))
#define IPV6_ADDR_U32 (IPV6_ADDR_LEN / sizeof(uint32_t))

enum { PROTO_FIELD_IPV6,
       SRC1_FIELD_IPV6,
       SRC2_FIELD_IPV6,
       SRC3_FIELD_IPV6,
       SRC4_FIELD_IPV6,
       DST1_FIELD_IPV6,
       DST2_FIELD_IPV6,
       DST3_FIELD_IPV6,
       DST4_FIELD_IPV6,
       SRCP_FIELD_IPV6,
       DSTP_FIELD_IPV6,

       ICMP_INNER_SRC1_FIELD_IPV6,
       ICMP_INNER_SRC2_FIELD_IPV6,
       ICMP_INNER_SRC3_FIELD_IPV6,
       ICMP_INNER_SRC4_FIELD_IPV6,
       ICMP_INNER_SRCP_FIELD_IPV6,
       ICMP_INNER_DSTP_FIELD_IPV6,

       NUM_FIELDS_IPV6 };

enum { RTE_ACL_IPV6_PROTO,
       RTE_ACL_IPV6_SRC1,
       RTE_ACL_IPV6_SRC2,
       RTE_ACL_IPV6_SRC3,
       RTE_ACL_IPV6_SRC4,
       RTE_ACL_IPV6_DST1,
       RTE_ACL_IPV6_DST2,
       RTE_ACL_IPV6_DST3,
       RTE_ACL_IPV6_DST4,
       RTE_ACL_IPV6_PORTS,

       RTE_ACL_IPV6_INNER_ICMP_MTU,
       RTE_ACL_IPV6_INNER_IPV6_PREAMBLE_1, // IPv6 inside ICMPv6 start
       RTE_ACL_IPV6_INNER_IPV6_PREAMBLE_2,
       RTE_ACL_IPV6_INNER_SRC1,
       RTE_ACL_IPV6_INNER_SRC2,
       RTE_ACL_IPV6_INNER_SRC3,
       RTE_ACL_IPV6_INNER_SRC4,
       RTE_ACL_IPV6_INNER_DST1,
       RTE_ACL_IPV6_INNER_DST2,
       RTE_ACL_IPV6_INNER_DST3,
       RTE_ACL_IPV6_INNER_DST4,
       RTE_ACL_IPV6_INNER_PORTS,

       RTE_ACL_IPV6_NUM };

struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
    {
	.type = RTE_ACL_FIELD_TYPE_BITMASK,
	.size = sizeof(uint8_t),
	.field_index = PROTO_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_PROTO,
	.offset = 0,
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC1_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_SRC1,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC2_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_SRC2,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto) + sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC3_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_SRC3,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto) + 2 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = SRC4_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_SRC4,
	.offset = offsetof(struct ipv6_hdr, src_addr) -
		  offsetof(struct ipv6_hdr, proto) + 3 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST1_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_DST1,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST2_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_DST2,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto) + sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST3_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_DST3,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto) + 2 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = DST4_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_DST4,
	.offset = offsetof(struct ipv6_hdr, dst_addr) -
		  offsetof(struct ipv6_hdr, proto) + 3 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = SRCP_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_PORTS,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = DSTP_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_PORTS,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint16_t),
    },

    // support for ICMP introspection
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = ICMP_INNER_SRC1_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_INNER_SRC1,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over the ICMPv6 header
		  offsetof(struct ipv6_hdr, src_addr),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = ICMP_INNER_SRC2_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_INNER_SRC2,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over the ICMPv6 header
		  offsetof(struct ipv6_hdr, src_addr) + sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = ICMP_INNER_SRC3_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_INNER_SRC3,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over the ICMPv6 header
		  offsetof(struct ipv6_hdr, src_addr) + 2 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_MASK,
	.size = sizeof(uint32_t),
	.field_index = ICMP_INNER_SRC4_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_INNER_SRC4,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over the ICMPv6 header
		  offsetof(struct ipv6_hdr, src_addr) + 3 * sizeof(uint32_t),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = ICMP_INNER_SRCP_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_INNER_PORTS,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over the ICMPv6 header
		  sizeof(struct ipv6_hdr),
    },
    {
	.type = RTE_ACL_FIELD_TYPE_RANGE,
	.size = sizeof(uint16_t),
	.field_index = ICMP_INNER_DSTP_FIELD_IPV6,
	.input_index = RTE_ACL_IPV6_INNER_PORTS,
	.offset = sizeof(struct ipv6_hdr) - offsetof(struct ipv6_hdr, proto) +
		  sizeof(uint32_t) +
		  sizeof(uint32_t) + // skip over the ICMPv6 header
		  sizeof(struct ipv6_hdr) + sizeof(uint16_t),
    },
};