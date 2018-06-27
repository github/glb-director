int glb_encapsulate_packet_dpdk(struct glb_fwd_config_ctx *ctx,
				struct rte_mbuf *pkt, unsigned int table_id);

int glb_checksum_offloading(struct rte_mbuf *pkt, struct ether_hdr *eth_hdr);
