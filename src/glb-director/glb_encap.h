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
