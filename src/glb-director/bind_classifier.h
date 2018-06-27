#include <rte_acl.h>
#include <rte_mbuf.h>

#define CLASSIFIED_BITMASK 0x100000
#define CLASSIFIED(x) ((x)&CLASSIFIED_BITMASK)
#define CLASSIFIED_TABLE(x) ((x)-CLASSIFIED_BITMASK)

struct glb_fwd_config_content;

int create_bind_classifier(struct glb_fwd_config_content *config,
			   struct rte_acl_ctx **ipv4_ctx_ptr,
			   struct rte_acl_ctx **ipv6_ctx_ptr);
int classify_to_tables(struct rte_acl_ctx *classifier_v4,
		       struct rte_acl_ctx *classifier_v6,
		       struct rte_mbuf **pkts_burst, uint32_t *classifications,
		       unsigned int num_packets);
