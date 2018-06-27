#include <arpa/inet.h>
#include <pcap.h>

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_encap_pcap.h"
#include "glb_fwd_config.h"
#include "log.h"

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#define INBOUND_HEADER_SIZE_L3 \
	(sizeof(struct ipv4_hdr) + \
	 sizeof(struct tcp_hdr))

#define INBOUND_HEADER_SIZE_L2 \
	(sizeof(struct ether_hdr) + INBOUND_HEADER_SIZE_L3)

#define ENCAP_HEADER_SIZE(num_chained_hops)                 \
	(sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) +   \
	 sizeof(struct udp_hdr) + sizeof(struct glb_gue_hdr) +  \
	 (sizeof(uint32_t) * num_chained_hops))

int glb_encapsulate_packet_pcap(struct glb_fwd_config_ctx *ctx, u_char *pkt,
				unsigned int table_id)
{

	if (table_id >= ctx->raw_config->num_tables) {
		glb_log_info("lcore: -> matched a table that was out of range");
		return -1;
	}

	struct ether_hdr *eth_hdr;
	eth_hdr = (struct ether_hdr *)pkt;

	struct ipv4_hdr *orig_ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	char orig_src_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(orig_ipv4_hdr->src_addr), orig_src_ip,
		  INET_ADDRSTRLEN);

	char orig_dst_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(orig_ipv4_hdr->dst_addr), orig_dst_ip,
		  INET_ADDRSTRLEN);

	primary_secondary p_s;

	int ret = 0;
	ret = get_primary_secondary(ctx, table_id, eth_hdr, &p_s);

	if (ret != 0) {
		glb_log_info(
		    "lcore: -> failed to get primary/secondary mapping");
		return -1;
	}

	struct ether_hdr bak_eth_hdr = *eth_hdr;

	/* simulate rte_pktmbuf_adj taking away the old ethernet header
	 * and rte_pktmbuf_prepend adding in the new encapsulation headers.
	 * essentially, take the inbound IP+TCP headers and put them after
	 * space for ENCAP_HEADER_SIZE(..)
	 */
	u_char encap_copy[ENCAP_HEADER_SIZE(p_s.hop_count) + INBOUND_HEADER_SIZE_L3];
	memcpy(&encap_copy[ENCAP_HEADER_SIZE(p_s.hop_count)], orig_ipv4_hdr, INBOUND_HEADER_SIZE_L3);
	eth_hdr = (struct ether_hdr *)&encap_copy;

	if (glb_encapsulate_packet(eth_hdr, bak_eth_hdr, &p_s) != 0) {
		return -1;
	}

	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	struct udp_hdr *udp_hdr = (struct udp_hdr *)(ipv4_hdr + 1);
	struct glb_gue_hdr *gue_hdr = (struct glb_gue_hdr *)(udp_hdr + 1);

	char via_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ipv4_hdr->dst_addr), via_ip, INET_ADDRSTRLEN);

	char alt_ip[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(gue_hdr->hops[0]), alt_ip, INET_ADDRSTRLEN);

	glb_log_info(
	    "[packet] src: %s, flow_hash:%d, dst: %s, hash:%016lx, via_ip: %s alt_ip: "
	    "%s, fou_port:%d",
	    orig_src_ip, p_s.flow_hash, orig_dst_ip, p_s.pkt_hash, via_ip,
	    alt_ip, udp_hdr->dst_port);

	return 0;
}

void glb_pcap_handler(configuration args[], const struct pcap_pkthdr *pkthdr,
		      const u_char *pkt)
{
	glb_log_info("[glb-pcap-mode] start packet processing");

	int ret;
	int table_id = args[0].table_id;
	struct glb_fwd_config_ctx *ctx = args[0].ctx;
	u_char copy_pkt[INBOUND_HEADER_SIZE_L2];

	if (pkthdr->caplen < INBOUND_HEADER_SIZE_L2 || pkthdr->caplen > pkthdr->len) {
		glb_log_info(
		    "[glb-pcap-mode] error: bad pcap caplen (%d, packet "
		    "len: %d), skipping ...",
		    pkthdr->caplen, pkthdr->len);
	} else {
		glb_log_info("[glb-pcap-mode] caplen %d", pkthdr->caplen);
		glb_log_info("[glb-pcap-mode] len %d", pkthdr->len);
		glb_log_info("[glb-pcap-mode] memcpy %lu", INBOUND_HEADER_SIZE_L2);

		memcpy(copy_pkt, pkt, INBOUND_HEADER_SIZE_L2);

		glb_log_info("[glb-pcap-mode] encap");
		ret = glb_encapsulate_packet_pcap(ctx, copy_pkt, table_id);

		if (ret != 0) {
			glb_log_info("packet encap failed! (ts: %ld.%06ld)",
				     pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
		}

		glb_log_info("[glb-pcap-mode] end packet processing");
	}
}
