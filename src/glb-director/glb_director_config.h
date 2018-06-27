#ifndef _GLB_DIRECTOR_CONFIG_H
#define _GLB_DIRECTOR_CONFIG_H
#include <rte_ether.h>

#define MAX_FLOW_PATHS 32
#define PER_CORE_MAX_FLOW_PATHS MAX_FLOW_PATHS

#define CORE_WORKLOAD_NONE 0
#define CORE_WORKLOAD_RX   (1 << 0)
#define CORE_WORKLOAD_TX   (1 << 1)
#define CORE_WORKLOAD_DIST (1 << 2)
#define CORE_WORKLOAD_WORK (1 << 3)
#define CORE_WORKLOAD_KNI  (1 << 4)

typedef struct {
	int rx_port_id;
	int rx_queue_id;

	int tx_port_id;
	int tx_queue_id;
} glb_director_flow_path;

typedef struct {
	uint32_t workloads;

	// for rx/tx
	uint32_t num_flow_paths;
	glb_director_flow_path flow_paths[MAX_FLOW_PATHS];

	// for distributors
	uint32_t num_dist_workers;

	// for workers
	uint32_t source_dist_core;
} glb_director_lcore_config;

typedef struct {
	struct ether_addr local_ether_addr;

	struct ether_addr gateway_ether_addr;
	uint32_t local_ip_addr;

	int kni_enabled;
	uint32_t kni_ip;

	uint8_t nb_queues;

	char forwarding_table_path[PATH_MAX];

	uint32_t num_flow_paths;
	glb_director_flow_path flow_paths[MAX_FLOW_PATHS];

	glb_director_lcore_config lcore_configs[RTE_MAX_LCORE];

	int forward_icmp_ping_responses;
} glb_director_config;

glb_director_config *
glb_director_config_load_file(const char *config_file,
			      const char *forwarding_table);

extern glb_director_config *g_director_config;
#endif
