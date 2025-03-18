#define KBUILD_MODNAME "glb-director-xdp"

#include <uapi/asm-generic/types.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>

// we don't want to use userspace library defs here, instead map to the kernel-provided ones
#define htons __constant_htons
#define ntohs __constant_ntohs

#include <stdint.h>
#include <string.h>

#include "bpf_helpers.h"
#include "glb_stats.h"
#include "glb_encap_limits.h"

#include <glb-hashing/glb_gue.h>
#include <glb-hashing/pdnet.h>

#ifdef ENABLE_TRACE
#define glb_bpf_printk(...) bpf_printk(__VA_ARGS__)
// rewrite core GLB calls to the bpf version
#define glb_log_info(fmt, ...) glb_bpf_printk(fmt "\n", ##__VA_ARGS__)
#else
#define glb_bpf_printk(...)
static __always_inline void glb_log_info(const char *format, ...) {
	/* not implemented, but required by glb-hashing */
}
#endif

typedef struct {
	uint8_t src_addr;
	uint8_t dst_addr;
	uint8_t src_port;
	uint8_t dst_port;
} __attribute__((packed)) glb_director_hash_fields;

#define GLB_PACKET_PARSING_RAW /* use the start->end variety, which matches XDP */
#define EBPF_VERIFIER_GUARD /* enable EBPF verifier guards where the verifier needs some help */
#include <glb-hashing/packet_parsing.h>

#define GLB_FMT_TABLE_HASHMASK 0xffff

/* xdpcap integration */
#include "xdpcap_hook.h"
struct bpf_map_def SEC("maps") xdpcap_hook = XDPCAP_HOOK();

typedef struct glb_bind {
	uint32_t ipv4;
	struct pdnet_ipv6_addr ipv6;
	uint16_t proto;
	uint16_t port;
} __attribute__((__packed__)) glb_bind_t;

struct bpf_map_def SEC("maps") config_bits = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = 6, // maximum size stored
	.max_entries = 5,

	/*
	0: 6 byes of gateway dst MAC
	1: 4 bytes of source IP
	2: 1 byte of icmp forwarding bool
	3: 4 bytes of glb_director_hash_fields
	4: 4 bytes of glb_director_hash_fields (alt)
	*/
};

struct bpf_map_def SEC("maps") glb_binds = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct glb_bind),
	.value_size = sizeof(uint32_t),
	.max_entries = BPF_MAX_BINDS,
};

struct bpf_map_def SEC("maps") glb_tables = {
	.type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size = sizeof(uint32_t),
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") glb_table_secrets = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(uint32_t),
#define GLB_FMT_SECURE_KEY_BYTES 16
	.value_size = GLB_FMT_SECURE_KEY_BYTES,
	.max_entries = 4096,
};

struct bpf_map_def SEC("maps") glb_global_packet_counters = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(struct glb_global_stats),
	/* we don't actually need an array, but PERCPU_* only has multi-element types */
	.max_entries = 1,
};

static __always_inline uint16_t compute_ipv4_checksum(void *iph) {
	uint16_t *iph16 = (uint16_t *)iph;

	// to avoid poorly clang unrolled loops in eBPF, just manually add
	// the 10 shorts (20 bytes header)
	uint64_t csum = 
		iph16[0] + iph16[1] + iph16[2] + iph16[3] + iph16[4] +
		iph16[5] + iph16[6] + iph16[7] + iph16[8] + iph16[9];
	
	// since we have a fixed size (no options) ip header, the maximum sum above is
	// (0xffff * 10) = 0x9fff6; 0xfff6 + 0x9 = 0xffff. which means
	// we can lazily just perform the 'carry' folding once for ipv4 (no options).
	csum = (csum & 0xffff) + (csum >> 16);

	return ~csum;
}


/* Fills in the encapsulation data, starting at the ethernet header.
 * Expects that `eth_hdr` points to ROUTE_CONTEXT_ENCAP_SIZE(ctx) bytes of free space
 * before the inner/original IP packet header begins.
 */
static __always_inline int glb_encapsulate_packet(struct pdnet_ethernet_hdr *eth_hdr, void *data_end, glb_route_context *route_context, struct glb_global_stats *g_stats)
{
	if (route_context == NULL)
		return XDP_DROP;
	
	uint16_t flow_hash = route_context->flow_hash_hint;
	uint16_t inner_ip_total_length = route_context->ip_total_length;
	uint64_t pkt_hash = route_context->pkt_hash;
	int gue_ipproto = route_context->gue_ipproto;

	/* Take the first hop to use as the IP dst_addr, then ignore it from GUE list.
	 * We support including all hops, since ROUTE_CONTEXT_ENCAP_SIZE(ctx) uses
	 * the same calculation to size our buffer for this function.
	 */
	uint32_t first_hop_ip = route_context->ipv4_hops[0];
	uint32_t remaining_hop_count = route_context->hop_count - 1;

	uint32_t config_bit = 0;
	struct pdnet_mac_addr *gw_mac = (struct pdnet_mac_addr *)bpf_map_lookup_elem(&config_bits, &config_bit);
	if (gw_mac == NULL) {
		g_stats->ErrorMissingGatewayMAC++;
		return XDP_DROP;
	}
	eth_hdr->src_addr = route_context->orig_dst_mac;
	eth_hdr->dst_addr = *gw_mac;
	eth_hdr->ether_type = htons(PDNET_ETHER_TYPE_IPV4);

	struct pdnet_ipv4_hdr *ipv4_hdr = (struct pdnet_ipv4_hdr *)(eth_hdr + 1);
#ifdef EBPF_VERIFIER_GUARD
	if ((void *)(ipv4_hdr + 1) > data_end) return XDP_DROP;
#endif

	config_bit = 1;
	uint32_t *src_ip = (uint32_t *)bpf_map_lookup_elem(&config_bits, &config_bit);
	if (src_ip == NULL) {
		g_stats->ErrorMissingSourceAddress++;
		return XDP_DROP;
	}
	
	glb_bpf_printk("  src_ip: 0x%x\n", *src_ip);

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
	ipv4_hdr->src_addr = *src_ip;
	ipv4_hdr->dst_addr = first_hop_ip;

	ipv4_hdr->checksum = compute_ipv4_checksum(ipv4_hdr);

	struct pdnet_udp_hdr *udp_hdr = (struct pdnet_udp_hdr *)(ipv4_hdr + 1);
#ifdef EBPF_VERIFIER_GUARD
	if ((void *)(udp_hdr + 1) > data_end) return XDP_DROP;
#endif

	/* Use the packet's entry hash and the low_hash (mostly TCP source port) to
	 * generate the UDP source port. This ties each flow to an approximately 
	 * random RX queue on the proxy hosts. Always set the high bit so we're 
	 * using a very non-confusing (ephemeral) port number.
	 */
	udp_hdr->src_port = htons(0x8000 | ((pkt_hash ^ flow_hash) & 0x7fff));
	udp_hdr->dst_port = htons(GLB_GUE_PORT);
	udp_hdr->length =
	    htons(sizeof(struct pdnet_udp_hdr) +
	      sizeof(struct glb_gue_hdr) + 
		  (sizeof(uint32_t) * remaining_hop_count) +
		  inner_ip_total_length);
	udp_hdr->checksum = 0;

	struct glb_gue_hdr *gue_hdr = (struct glb_gue_hdr *)(udp_hdr + 1);

#ifdef EBPF_VERIFIER_GUARD
	if ((void *)(gue_hdr + 1) > data_end) return XDP_DROP;
#endif

	gue_hdr->private_type = 0;
	gue_hdr->next_hop = 0;
	gue_hdr->hop_count = remaining_hop_count;
	/* hlen is essentially just private data, which is 1x 32 bits, plus the number of hops */
	gue_hdr->version_control_hlen = 1 + remaining_hop_count;
	gue_hdr->protocol = gue_ipproto;
	gue_hdr->flags  = 0;
#ifdef EBPF_VERIFIER_GUARD
	if ((void *)&gue_hdr->hops[remaining_hop_count] > data_end) return XDP_DROP;
#endif
	/* hops are already encoded in network byte order (same as first_hop_ip above)
	 * We can have at most GLB_MAX_HOPS, with one being the first (used above), so
	 * this has (GLB_MAX_HOPS-1) hops to potentially copy.
	 * 
	 * This will need to be updated if GLB_MAX_HOPS ever changes from 4, which is
	 * the current value to account for 2 servers with a primary hash and another 2
	 * servers with a second hash (used for changing hash).
	 * 
	 * This is unrolled manually to make less jumpy/cleaner eBPF output.
	 */
	if (remaining_hop_count >= 1 && (void *)(&gue_hdr->hops[1]) <= data_end) gue_hdr->hops[0] = route_context->ipv4_hops[1];
	if (remaining_hop_count >= 2 && (void *)(&gue_hdr->hops[2]) <= data_end) gue_hdr->hops[1] = route_context->ipv4_hops[2];
	if (remaining_hop_count >= 3 && (void *)(&gue_hdr->hops[3]) <= data_end) gue_hdr->hops[2] = route_context->ipv4_hops[3];

	glb_bpf_printk("  encaped!\n");

	g_stats->Encapsulated++;
	g_stats->EncapsulatedBytes += ntohs(ipv4_hdr->total_length) + sizeof(struct pdnet_ethernet_hdr);
	return XDP_TX;
}

static __always_inline int xdp_glb_director_process(struct xdp_md *ctx) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	// cat /sys/kernel/debug/tracing/trace_pipe
	glb_bpf_printk("Greetings\n");

	uint32_t stat = 0;
	struct glb_global_stats *g_stats = bpf_map_lookup_elem(&glb_global_packet_counters, &stat);
	if (g_stats == NULL) return XDP_PASS; /* this should always succeed, but we must bail if not for eBPF verifier */
	g_stats->Processed++;
	
	int rc = XDP_PASS;

	glb_route_context route_context;
	memset(&route_context, 0, sizeof(glb_route_context));
	route_context.packet_start = data;
	route_context.packet_end = data_end;
	rc = glb_extract_packet_fields(&route_context);
	glb_bpf_printk("  parse rc = %d\n", rc);
	if (rc != 0) {
		g_stats->UnknownFormat++;
		return XDP_PASS;
	}

	glb_bpf_printk("  dst_addr: 0x%x\n", route_context.dst_addr.ipv4);
	glb_bpf_printk("  src_addr: 0x%x\n", route_context.src_addr.ipv4);
	glb_bpf_printk("  dst_port: 0x%x\n", route_context.dst_port);
	glb_bpf_printk("  src_port: 0x%x\n", route_context.src_port);
	
	struct glb_bind bind;
	memset(&bind, 0, sizeof(struct glb_bind));
	if (route_context.ether_type == PDNET_ETHER_TYPE_IPV4)
		bind.ipv4 = route_context.dst_addr.ipv4;
	else
		bind.ipv6 = route_context.dst_addr.ipv6;
	bind.port = route_context.dst_port;
	bind.proto = route_context.original_ipproto;

	glb_bpf_printk("  bind ipv4: 0x%x\n", bind.ipv4);
	glb_bpf_printk("  bind port: 0x%x\n", bind.port);
	glb_bpf_printk("  bind proto: 0x%x\n", bind.proto);

	uint32_t *table_id_ptr = (uint32_t *)bpf_map_lookup_elem(&glb_binds, &bind);
	if (table_id_ptr == NULL) {
		g_stats->NoMatchingBind++;
		return XDP_PASS;
	}

	g_stats->Matched++;
	
	uint32_t table_id = *table_id_ptr;
	glb_bpf_printk("  bind maps to table id: %d\n", table_id);

	struct bpf_map_def *table = (struct bpf_map_def *)bpf_map_lookup_elem(&glb_tables, &table_id);
	glb_bpf_printk("  bind maps to table fd: 0x%p\n", table);
	if (table == NULL) {
		g_stats->ErrorTable++;
		return XDP_PASS; // we don't know
	}

	uint8_t *secret = (uint8_t *)bpf_map_lookup_elem(&glb_table_secrets, &table_id);
	glb_bpf_printk("  table secret: 0x%p\n", secret);
	if (secret == NULL) {
		g_stats->ErrorSecret++;
		return XDP_PASS; // we don't have a valid secret, bail
	}

	uint32_t config_bit = 3;
	glb_director_hash_fields *hf_cfg_ptr = (glb_director_hash_fields *)bpf_map_lookup_elem(&config_bits, &config_bit);
	if (hf_cfg_ptr == NULL) {
		g_stats->ErrorHashConfig++;
		return XDP_PASS;
	}

	// glb_bpf_printk("  dst_addr: 0x%x\n", route_context.dst_addr.ipv4);
	// glb_bpf_printk("  src_addr: 0x%x\n", route_context.src_addr.ipv4);
	// glb_bpf_printk("  dst_port: 0x%x\n", route_context.dst_port);
	// glb_bpf_printk("  src_port: 0x%x\n", route_context.src_port);

	uint64_t hash = glb_compute_hash(&route_context, secret, hf_cfg_ptr);
	glb_bpf_printk("  hashes to: 0x%llx\n", hash);

	uint32_t tableRowIndex = hash & GLB_FMT_TABLE_HASHMASK;
	uint32_t *tableRow = (uint32_t *)bpf_map_lookup_elem(table, &tableRowIndex);

	glb_bpf_printk("  which is tableRow %d: 0x%p\n", tableRowIndex, tableRow);

	if (tableRow == NULL) {
		g_stats->ErrorMissingRow++;
		return XDP_PASS; // we don't know
	}

	glb_bpf_printk("  table primary: %d\n", tableRow[0]);
	glb_bpf_printk("  table secondary: %d\n", tableRow[1]);

	route_context.pkt_hash = hash;
	route_context.ipv4_hops[0] = tableRow[0];
	route_context.ipv4_hops[1] = tableRow[1];
	route_context.hop_count = 2;

	/* now optionally do the second one. FIXME: this shouldn't be copy-pasta */

	config_bit = 4;
	glb_director_hash_fields *hf_cfg_alt_ptr = (glb_director_hash_fields *)bpf_map_lookup_elem(&config_bits, &config_bit);
	if (hf_cfg_alt_ptr == NULL) {
		g_stats->ErrorHashConfig++;
		return XDP_PASS;
	}

	if (hf_cfg_alt_ptr->dst_addr || hf_cfg_alt_ptr->dst_port || hf_cfg_alt_ptr->src_addr || hf_cfg_alt_ptr->src_port) {
		uint64_t hash = glb_compute_hash(&route_context, secret, hf_cfg_alt_ptr);
		glb_bpf_printk("  hashes (alt) to: 0x%llx\n", hash);

		uint32_t tableRowIndex = hash & GLB_FMT_TABLE_HASHMASK;
		uint32_t *tableRow = (uint32_t *)bpf_map_lookup_elem(table, &tableRowIndex);

		glb_bpf_printk("  which is tableRow (alt) %d: 0x%p\n", tableRowIndex, tableRow);

		if (tableRow == NULL) {
			g_stats->ErrorMissingRow++;
			return XDP_PASS; // we don't know
		}

		glb_bpf_printk("  table (alt) primary: %d\n", tableRow[0]);
		glb_bpf_printk("  table (alt) secondary: %d\n", tableRow[1]);

		route_context.ipv4_hops[2] = tableRow[0];
		route_context.ipv4_hops[3] = tableRow[1];
		route_context.hop_count = 4;
	}

	/** copy paste hax right now below here **/

	// encapsulate!
	// we want to essentially remove (add to our start) an eth and add (subtract from our start) all the bits we need.
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(struct pdnet_ethernet_hdr) - (int)ROUTE_CONTEXT_ENCAP_SIZE(&route_context))) {
		g_stats->ErrorCreatingSpace++;
		return XDP_DROP;
	}

	/* these must be retrieved again after the adjust_head */
	data = (void*)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if (data + ROUTE_CONTEXT_ENCAP_SIZE(&route_context) > data_end) /* this is just to let the compiler know we checked for safety */
		return XDP_DROP;
	
	return glb_encapsulate_packet(data, data_end, &route_context, g_stats);
}

SEC("xdp/xdp_glb_director")
int xdp_glb_director(struct xdp_md *ctx) {
	return xdpcap_exit(ctx, &xdpcap_hook, xdp_glb_director_process(ctx));
}

char _license[] SEC("license") = "GPL";
