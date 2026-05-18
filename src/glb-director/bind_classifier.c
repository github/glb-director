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

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rte_acl.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_ring.h>
#include <rte_string_fns.h>

#include "bind_classifier.h"
#include "bind_classifier_rules.h"
#include "config.h"
#include "glb_fwd_config.h"
#include "glb_director_config.h"
#include "log.h"

/* define a structure for the rule with up to 5 fields. */

RTE_ACL_RULE_DEF(acl_ipv4_rule, RTE_DIM(ipv4_defs));
RTE_ACL_RULE_DEF(acl_ipv6_rule, RTE_DIM(ipv6_defs));

#define ICMP_TYPE_CODE(type, code) (((type) << 8) | ((code) << 0))
#define ICMPV4_FRAGMENTATION_REQUIRED ICMP_TYPE_CODE(3, 4)
#define ICMPV4_ECHO_REQUEST ICMP_TYPE_CODE(8, 0)
#define ICMPV6_PACKET_TOO_BIG ICMP_TYPE_CODE(2, 0)
#define ICMPV6_ECHO_REQUEST ICMP_TYPE_CODE(128, 0)

#define ACL_SET_FIELD_GENERIC(rule, field_id, value_type, match_value_or_start, mask_range_type, match_mask_or_range) \
	{ \
		rule->field[field_id] \
		    .value.value_type = (match_value_or_start); \
		rule->field[field_id] \
		    .mask_range.mask_range_type = (match_mask_or_range); \
	}

#define ACL_SET_FIELD_BITMASK(rule, field_id, value_type, match_value_or_start, match_mask_or_range) \
			ACL_SET_FIELD_GENERIC((rule), (field_id), value_type, (match_value_or_start), u32, (match_mask_or_range))

#define ACL_SET_FIELD_PORT_RANGE(rule, field_id, match_value_or_start, match_mask_or_range) \
			ACL_SET_FIELD_GENERIC((rule), (field_id), u16, (match_value_or_start), u16, (match_mask_or_range))

#define ACL_SET_FIELD_PORT_EXACT(rule, field_id, exact_port) \
			ACL_SET_FIELD_PORT_RANGE((rule), (field_id), (exact_port), (exact_port))

#define ACL_SET_FIELD_IPV4_CIDR(rule, field_id, match_value_or_start, match_mask_or_range) \
			ACL_SET_FIELD_GENERIC((rule), (field_id), u32, (match_value_or_start), u32, (match_mask_or_range))

#define ACL_SET_FIELD_IPV6_PART_CIDR ACL_SET_FIELD_IPV4_CIDR

/* Fills the `ip` string for the given bind.
 * `ip` must be MAX_INET_ADDR_STRLEN in length.
 */
#define MAX_INET_ADDR_STRLEN 64
static void get_ip_from_bind(struct glb_fwd_config_content_table_bind *bind, char *ip) {
	if (bind->family == FAMILY_IPV4) {
		inet_ntop(AF_INET, &(bind->ipv4_addr), ip, MAX_INET_ADDR_STRLEN);
	} else {
		inet_ntop(AF_INET6, bind->ipv6_addr, ip, INET6_ADDRSTRLEN);
	}
}

/* Since we match 32bit values, we need to convert an IPv6 CIDR range (0..128)
 * to 4x 32bit ranges. Essentially for the values (0..32) we want to use the
 * value at offset=0, then we want to keep that at 32 while we use the value
 * at offset=1 to count the next 32 values.
 */
static inline int ipv6_cidr_offset(int ip_bits, int offset) {
	// find the range of bits that are in use here
	// e.g. 0 will use the values 0-32
	int offset_start = offset * 32;
	int offset_end = (offset+1) * 32;

	// specifies a bigger mask than our range, so specify all of our bits set
	if (ip_bits >= offset_end)
		return 32;

	// specifies a smaller mask than our range, so specify no bits set
	if (ip_bits < offset_start)
		return 0;

	// range ends somewhere in here, extract that part (lower 5 bits, 0..31)
	return ip_bits & 0x1f;
}

/* Adds filters for a typical packet destined for the given bind.
 */
static void add_acl_typical_bind_packet(int table_id,
	struct glb_fwd_config_content_table_bind *bind,
	struct acl_ipv4_rule acl4_rules[], uint32_t *curr_bind_v4,
	struct acl_ipv6_rule acl6_rules[], uint32_t *curr_bind_v6)
{
	char ip[MAX_INET_ADDR_STRLEN];
	get_ip_from_bind(bind, ip);

	glb_log_info("Creating bind classifier: %s:[%d-%d] (proto: %d)",
	    ip, bind->port_start, bind->port_end, bind->proto);

	if (bind->family == FAMILY_IPV4) {
		/* Match IPv4 packets */
		struct acl_ipv4_rule *rule = &acl4_rules[*curr_bind_v4];
		(*curr_bind_v4)++;

		rule->data.userdata = CLASSIFIED_BITMASK | table_id;
		rule->data.category_mask = 1;
		rule->data.priority = 1;

		// IPv4 protocol (TCP or UDP depending on the bind)
		ACL_SET_FIELD_BITMASK(rule, PROTO_FIELD_IPV4, u8, bind->proto, 0xff);

		// IPv4 destination address
		ACL_SET_FIELD_IPV4_CIDR(rule, DST_FIELD_IPV4, htonl(bind->ipv4_addr), bind->ip_bits);

		// IPv4 TCP/UDP src port (any port)
		ACL_SET_FIELD_PORT_RANGE(rule, SRCP_FIELD_IPV4, 0, 0xffff);

		// IPv4 TCP/UDP destination port
		ACL_SET_FIELD_PORT_RANGE(rule, DSTP_FIELD_IPV4, bind->port_start, bind->port_end);

		// ignore inner ICMP src addr and src/dst ports since this isn't ICMP
		ACL_SET_FIELD_IPV4_CIDR(rule, ICMP_INNER_SRC_FIELD_IPV4, 0, 0);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_SRCP_FIELD_IPV4, 0, 0xffff);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_DSTP_FIELD_IPV4, 0, 0xffff);
	} else {
		/* Match IPv6 packets */
		struct acl_ipv6_rule *rule = &acl6_rules[*curr_bind_v6];
		(*curr_bind_v6)++;

		rule->data.userdata = CLASSIFIED_BITMASK | table_id;
		rule->data.category_mask = 1;
		rule->data.priority = 1;

		// IPv6 protocol
		ACL_SET_FIELD_BITMASK(rule, PROTO_FIELD_IPV6, u8, bind->proto, 0xff);

		// destination IPv6
		uint32_t *ipv6_addr = (uint32_t *)&bind->ipv6_addr[0];
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST1_FIELD_IPV6, htonl(ipv6_addr[0]), ipv6_cidr_offset(bind->ip_bits, 0));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST2_FIELD_IPV6, htonl(ipv6_addr[1]), ipv6_cidr_offset(bind->ip_bits, 1));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST3_FIELD_IPV6, htonl(ipv6_addr[2]), ipv6_cidr_offset(bind->ip_bits, 2));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST4_FIELD_IPV6, htonl(ipv6_addr[3]), ipv6_cidr_offset(bind->ip_bits, 3));

		// src port (any port)
		ACL_SET_FIELD_PORT_RANGE(rule, SRCP_FIELD_IPV6, 0, 0xffff);

		// destination port
		ACL_SET_FIELD_PORT_RANGE(rule, DSTP_FIELD_IPV6, bind->port_start, bind->port_end);

		// ICMP fragmentation original source IP and src/dst ports -- UNUSED HERE
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC1_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC2_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC3_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC4_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_SRCP_FIELD_IPV6, 0, 0xffff);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_DSTP_FIELD_IPV6, 0, 0xffff);
	}
}

/* Adds filters that match ICMP fragmentation / "too big" return packets from
 * a router that received a packet from us that was part of the main flow.
 *
 * Of note is that we match the ports inside the ICMP packet, which contain a
 * packet sent by GLB, so the src/dst are swapped.
 */
static void add_acl_return_icmp_fragmentation(int table_id,
	struct glb_fwd_config_content_table_bind *bind,
	struct acl_ipv4_rule acl4_rules[], uint32_t *curr_bind_v4,
	struct acl_ipv6_rule acl6_rules[], uint32_t *curr_bind_v6)
{
	char ip[MAX_INET_ADDR_STRLEN];
	get_ip_from_bind(bind, ip);

	glb_log_info(
	    "Creating ICMP fragmentation needed bind classifier: %s:[%d-%d] (proto: ICMP)",
	    ip, bind->port_start, bind->port_end);

	if (bind->family == FAMILY_IPV4) {
		/* Match IPv4 packets */
		struct acl_ipv4_rule *rule = &acl4_rules[*curr_bind_v4];
		(*curr_bind_v4)++;

		rule->data.userdata = CLASSIFIED_BITMASK | table_id;
		rule->data.category_mask = 1;
		rule->data.priority = 1;

		// IPv4 protocol (ICMP, related to TCP/UDP packet from main match)
		ACL_SET_FIELD_BITMASK(rule, PROTO_FIELD_IPV4, u8, IPPROTO_ICMP, 0xff);

		// IPv4 destination address
		ACL_SET_FIELD_IPV4_CIDR(rule, DST_FIELD_IPV4, htonl(bind->ipv4_addr), bind->ip_bits);

		// normally src port (so use port filter), actually location of ICMP type/code
		ACL_SET_FIELD_PORT_EXACT(rule, SRCP_FIELD_IPV4, ICMPV4_FRAGMENTATION_REQUIRED);

		// normally destination port, so just ignore the value and match anything
		ACL_SET_FIELD_PORT_RANGE(rule, DSTP_FIELD_IPV4, 0, 0xffff);

		// ICMP original source IP (normally dest IP)
		ACL_SET_FIELD_IPV4_CIDR(rule, ICMP_INNER_SRC_FIELD_IPV4, htonl(bind->ipv4_addr), bind->ip_bits);

		// ICMP original source port (normally dest port)
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_SRCP_FIELD_IPV4, bind->port_start, bind->port_end);

		// ignore inner ICMP dst port since we don't care here
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_DSTP_FIELD_IPV4, 0, 0xffff);
	} else {
		/* Match IPv6 packets */
		struct acl_ipv6_rule *rule = &acl6_rules[*curr_bind_v6];
		(*curr_bind_v6)++;

		rule->data.userdata = CLASSIFIED_BITMASK | table_id;
		rule->data.category_mask = 1;
		rule->data.priority = 1;

		// IPv6 protocol
		ACL_SET_FIELD_BITMASK(rule, PROTO_FIELD_IPV6, u8, IPPROTO_ICMPV6, 0xff);

		// destination IPv6
		uint32_t *ipv6_addr = (uint32_t *)&bind->ipv6_addr[0];
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST1_FIELD_IPV6, htonl(ipv6_addr[0]), ipv6_cidr_offset(bind->ip_bits, 0));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST2_FIELD_IPV6, htonl(ipv6_addr[1]), ipv6_cidr_offset(bind->ip_bits, 1));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST3_FIELD_IPV6, htonl(ipv6_addr[2]), ipv6_cidr_offset(bind->ip_bits, 2));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST4_FIELD_IPV6, htonl(ipv6_addr[3]), ipv6_cidr_offset(bind->ip_bits, 3));

		// normally src port (so use port range match), actually location of ICMP type/code
		ACL_SET_FIELD_PORT_EXACT(rule, SRCP_FIELD_IPV6, ICMPV6_PACKET_TOO_BIG);

		// destination port
		ACL_SET_FIELD_PORT_RANGE(rule, DSTP_FIELD_IPV6, 0, 0xffff);

		// ICMP fragmentation contains original IP header:
		//   source IP: the destination IP we usually match, since it's reflected
		//      (note this one should be the same as we matches in the destination above)
		//   source port: the destination port we usually match, since it's reflected
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC1_FIELD_IPV6, htonl(ipv6_addr[0]), ipv6_cidr_offset(bind->ip_bits, 0));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC2_FIELD_IPV6, htonl(ipv6_addr[1]), ipv6_cidr_offset(bind->ip_bits, 1));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC3_FIELD_IPV6, htonl(ipv6_addr[2]), ipv6_cidr_offset(bind->ip_bits, 2));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC4_FIELD_IPV6, htonl(ipv6_addr[3]), ipv6_cidr_offset(bind->ip_bits, 3));
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_SRCP_FIELD_IPV6, bind->port_start, bind->port_end);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_DSTP_FIELD_IPV6, 0, 0xffff);
	}
}

/* Adds filters for the ICMP echo request packet that would be destined for
 * the same IP as the given bind.
 *
 * Of note is that we have no port to match on, so we accept that any bind
 * may match the ICMP echo request for a given IP in the case there are multiple.
 */
static void add_acl_icmp_echo_request(int table_id,
	struct glb_fwd_config_content_table_bind *bind,
	struct acl_ipv4_rule acl4_rules[], uint32_t *curr_bind_v4,
	struct acl_ipv6_rule acl6_rules[], uint32_t *curr_bind_v6)
{
	char ip[MAX_INET_ADDR_STRLEN];
	get_ip_from_bind(bind, ip);

	glb_log_info(
    	"Creating ICMP echo response bind classifier: %s (proto: ICMP)",
    	ip);

	if (bind->family == FAMILY_IPV4) {
		/* Match IPv4 packets */
		struct acl_ipv4_rule *rule = &acl4_rules[*curr_bind_v4];
		(*curr_bind_v4)++;

		rule->data.userdata = CLASSIFIED_BITMASK | table_id;
		rule->data.category_mask = 1;
		rule->data.priority = 1;

		// IPv4 protocol
		ACL_SET_FIELD_BITMASK(rule, PROTO_FIELD_IPV4, u8, IPPROTO_ICMP, 0xff);

		// IPv4 destination address
		ACL_SET_FIELD_IPV4_CIDR(rule, DST_FIELD_IPV4, htonl(bind->ipv4_addr), bind->ip_bits);

		// normally src port (so use port filter), actually location of ICMP type/code
		ACL_SET_FIELD_PORT_EXACT(rule, SRCP_FIELD_IPV4, ICMPV4_ECHO_REQUEST);

		// normally destination port, so just ignore the value and match anything
		ACL_SET_FIELD_PORT_RANGE(rule, DSTP_FIELD_IPV4, 0, 0xffff);

		// ignore inner ICMP src addr and src/dst ports since this is ICMP echo
		ACL_SET_FIELD_IPV4_CIDR(rule, ICMP_INNER_SRC_FIELD_IPV4, 0, 0);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_SRCP_FIELD_IPV4, 0, 0xffff);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_DSTP_FIELD_IPV4, 0, 0xffff);
	} else {
		/* Match IPv6 packets */
		struct acl_ipv6_rule *rule = &acl6_rules[*curr_bind_v6];
		(*curr_bind_v6)++;

		rule->data.userdata = CLASSIFIED_BITMASK | table_id;
		rule->data.category_mask = 1;
		rule->data.priority = 1;

		// IPv6 protocol
		ACL_SET_FIELD_BITMASK(rule, PROTO_FIELD_IPV6, u8, IPPROTO_ICMPV6, 0xff);

		// destination IPv6
		uint32_t *ipv6_addr = (uint32_t *)&bind->ipv6_addr[0];
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST1_FIELD_IPV6, htonl(ipv6_addr[0]), ipv6_cidr_offset(bind->ip_bits, 0));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST2_FIELD_IPV6, htonl(ipv6_addr[1]), ipv6_cidr_offset(bind->ip_bits, 1));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST3_FIELD_IPV6, htonl(ipv6_addr[2]), ipv6_cidr_offset(bind->ip_bits, 2));
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, DST4_FIELD_IPV6, htonl(ipv6_addr[3]), ipv6_cidr_offset(bind->ip_bits, 3));

		// normally src port, actually location of ICMP type/code
		ACL_SET_FIELD_PORT_EXACT(rule, SRCP_FIELD_IPV6, ICMPV6_ECHO_REQUEST);

		// destination port
		ACL_SET_FIELD_PORT_RANGE(rule, DSTP_FIELD_IPV6, 0, 0xffff);

		// ICMP fragmentation original source IP and src/dst ports -- UNUSED HERE
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC1_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC2_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC3_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_IPV6_PART_CIDR(rule, ICMP_INNER_SRC4_FIELD_IPV6, 0, 0);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_SRCP_FIELD_IPV6, 0, 0xffff);
		ACL_SET_FIELD_PORT_RANGE(rule, ICMP_INNER_DSTP_FIELD_IPV6, 0, 0xffff);
	}
}

static void add_acls_for_bind(int table_id,
	struct glb_fwd_config_content_table_bind *bind,
	struct acl_ipv4_rule acl4_rules[], uint32_t *curr_bind_v4,
	struct acl_ipv6_rule acl6_rules[], uint32_t *curr_bind_v6)
{
	add_acl_typical_bind_packet(table_id, bind, acl4_rules, curr_bind_v4, acl6_rules, curr_bind_v6);
	add_acl_return_icmp_fragmentation(table_id, bind, acl4_rules, curr_bind_v4, acl6_rules, curr_bind_v6);

	if (g_director_config->forward_icmp_ping_responses) {
		add_acl_icmp_echo_request(table_id, bind, acl4_rules, curr_bind_v4, acl6_rules, curr_bind_v6);
	}
}

int create_bind_classifier(struct glb_fwd_config_content *config,
			   struct rte_acl_ctx **ipv4_ctx_ptr,
			   struct rte_acl_ctx **ipv6_ctx_ptr)
{
	int ret;
	uint32_t t, b;

	/* determine how many total binds we have */
	uint32_t num_total_binds = 0;
	for (t = 0; t < config->num_tables; t++) {
		struct glb_fwd_config_content_table *table = &config->tables[t];
		num_total_binds += table->num_binds;
	}

	if (num_total_binds == 0) {
		glb_log_info("No binds found in configuration");
		*ipv4_ctx_ptr = NULL;
		*ipv6_ctx_ptr = NULL;
		return 0;
	}

	if (!g_director_config->forward_icmp_ping_responses) {
		// matching normal and ICMP frag packets
		num_total_binds *= 2;
	} else {
		// matching normal and ICMP frag packets, plus ICMP echo packets.
		// we'll add a rule for every bind, and send it to the first that
		// matches for the IP. note there's no "right table/backend" for
		// this, since ICMP echo packets don't have a port.
		num_total_binds *= 3;
	}

	/* AC context creation parameters. */

	static int classifier_num = 0;
	char name_v4[64];
	char name_v6[64];
	sprintf(name_v4, "glb_classifier_v4_%d", classifier_num);
	sprintf(name_v6, "glb_classifier_v6_%d", classifier_num);
	classifier_num++;

	struct rte_acl_param prm_v4 = {
	    .name = name_v4,
	    .socket_id = SOCKET_ID_ANY,
	    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv4_defs)),
	    .max_rule_num = num_total_binds, /* maximum number of rules in the
						AC context. */
	};

	struct rte_acl_param prm_v6 = {
	    .name = name_v6,
	    .socket_id = SOCKET_ID_ANY,
	    .rule_size = RTE_ACL_RULE_SZ(RTE_DIM(ipv6_defs)),
	    .max_rule_num = num_total_binds, /* maximum number of rules in the
						AC context. */
	};

	/* create an empty AC context  */
	struct rte_acl_ctx *acx4, *acx6;

	if ((acx4 = rte_acl_create(&prm_v4)) == NULL) {
		glb_log_info("rte_acl_create (v4) failed");
		/* handle context create failure. */
		return 1;
	}

	if ((acx6 = rte_acl_create(&prm_v6)) == NULL) {
		glb_log_info("rte_acl_create (v6) failed");
		/* handle context create failure. */
		return 1;
	}

	/* Prepare the rules */
	struct acl_ipv4_rule acl4_rules[num_total_binds];
	memset(acl4_rules, 0, sizeof(acl4_rules));

	struct acl_ipv6_rule acl6_rules[num_total_binds];
	memset(acl6_rules, 0, sizeof(acl6_rules));

	uint32_t curr_bind_v4 = 0;
	uint32_t curr_bind_v6 = 0;
	for (t = 0; t < config->num_tables; t++) {
		struct glb_fwd_config_content_table *table = &config->tables[t];
		for (b = 0; b < table->num_binds; b++) {
			struct glb_fwd_config_content_table_bind *bind =
			    &table->binds[b];

			add_acls_for_bind(t, bind, acl4_rules, &curr_bind_v4, acl6_rules, &curr_bind_v6);
		}
	}

	/* add rules to the context */

	if (curr_bind_v4 > 0) {
		ret = rte_acl_add_rules(acx4, (struct rte_acl_rule *)acl4_rules,
					curr_bind_v4);
		if (ret != 0) {
			glb_log_info("rte_acl_add_rules (v4) failed");
			/* handle error at adding ACL rules. */
			return 1;
		}
	}

	if (curr_bind_v6 > 0) {
		ret = rte_acl_add_rules(acx6, (struct rte_acl_rule *)acl6_rules,
					curr_bind_v6);
		if (ret != 0) {
			glb_log_info("rte_acl_add_rules (v6) failed");
			/* handle error at adding ACL rules. */
			return 1;
		}
	}

	/* prepare AC build config. */
	struct rte_acl_config cfg4, cfg6;

	cfg4.num_categories = 1;
	cfg4.num_fields = RTE_DIM(ipv4_defs);
	cfg4.max_size = 0x800000;
	memcpy(cfg4.defs, ipv4_defs, sizeof(ipv4_defs));

	cfg6.num_categories = 1;
	cfg6.num_fields = RTE_DIM(ipv6_defs);
	cfg6.max_size = 0x800000;
	memcpy(cfg6.defs, ipv6_defs, sizeof(ipv6_defs));

	/* build the runtime structures for added rules, with 2 categories. */

	if (curr_bind_v4 > 0) {
		ret = rte_acl_build(acx4, &cfg4);
		if (ret != 0) {
			/* handle error at build runtime structures for ACL
			 * context. */
			glb_log_info("rte_acl_build (v4) failed: %d", ret);
			return 1;
		}

		*ipv4_ctx_ptr = acx4;
	} else {
		*ipv4_ctx_ptr = NULL;
	}

	if (curr_bind_v6 > 0) {
		ret = rte_acl_build(acx6, &cfg6);
		if (ret != 0) {
			/* handle error at build runtime structures for ACL
			 * context. */
			glb_log_info("rte_acl_build (v6) failed: %d", ret);
			return 1;
		}

		*ipv6_ctx_ptr = acx6;
	} else {
		*ipv6_ctx_ptr = NULL;
	}

	return 0;
}

int classify_to_tables(struct rte_acl_ctx *classifier_v4,
		       struct rte_acl_ctx *classifier_v6,
		       struct rte_mbuf **pkts_burst, uint32_t *classifications,
		       unsigned int num_packets)
{
	const unsigned lcore_id = rte_lcore_id();
	const uint8_t *pkts_data_v4[num_packets];
	const uint8_t *pkts_data_v6[num_packets];
	uint8_t pkts_remap_v4[num_packets];
	uint8_t pkts_remap_v6[num_packets];
	uint32_t classifications_v4[num_packets];
	uint32_t classifications_v6[num_packets];
	uint8_t num_v4 = 0, num_v6 = 0;
	uint8_t i;

	for (i = 0; i < num_packets; i++) {
		struct rte_mbuf *pkt = pkts_burst[i];
		struct ether_hdr *eth_hdr =
		    rte_pktmbuf_mtod(pkt, struct ether_hdr *);
		int ether_type = ntohs(eth_hdr->ether_type);

		// glb_log_info("lcore-%u: pkt %d type is %x", lcore_id,
		// i, ether_type);

		if (ether_type == ETHER_TYPE_IPv4) {
			pkts_data_v4[num_v4] = rte_pktmbuf_mtod_offset(
			    pkt, uint8_t *,
			    sizeof(struct ether_hdr) +
				offsetof(struct ipv4_hdr, next_proto_id));
			pkts_remap_v4[num_v4] = i;
			num_v4++;
		} else if (ether_type == ETHER_TYPE_IPv6) {
			pkts_data_v6[num_v6] = rte_pktmbuf_mtod_offset(
			    pkt, uint8_t *,
			    sizeof(struct ether_hdr) +
				offsetof(struct ipv6_hdr, proto));
			pkts_remap_v6[num_v6] = i;
			num_v6++;
		}

		classifications[i] = 0;
	}

	// glb_log_info("lcore-%u: ready to classify %d v4 and %d v6
	// packets", lcore_id, num_v4, num_v6);

	if (num_v4 > 0 && classifier_v4 == NULL) {
		glb_log_error("lcore-%u: !!! no v4 classifier loaded, dropping "
			      "packets !!!",
			      lcore_id);
	} else if (num_v4 > 0) {
		int ret = rte_acl_classify(classifier_v4, pkts_data_v4,
					   classifications_v4, num_v4, 1);
		if (ret != 0) {
			return ret;
		}

		for (i = 0; i < num_v4; i++) {
			classifications[pkts_remap_v4[i]] =
			    classifications_v4[i];
		}
	}

	if (num_v6 > 0 && classifier_v6 == NULL) {
		glb_log_error("lcore-%u: !!! no v6 classifier loaded, dropping "
			      "packets !!!",
			      lcore_id);
	} else if (num_v6 > 0) {
		int ret = rte_acl_classify(classifier_v6, pkts_data_v6,
					   classifications_v6, num_v6, 1);
		if (ret != 0) {
			return ret;
		}

		for (i = 0; i < num_v6; i++) {
			classifications[pkts_remap_v6[i]] =
			    classifications_v6[i];
		}
	}

	return 0;
}
