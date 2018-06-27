#include <pcap.h>

typedef struct {
	int table_id;
	struct glb_fwd_config_ctx *ctx;
} configuration;

void glb_pcap_handler(configuration args[], const struct pcap_pkthdr *pkthdr,
		      const u_char *pkt);

int glb_encapsulate_packet_pcap(struct glb_fwd_config_ctx *ctx, u_char *pkt,
				unsigned int table_id);
