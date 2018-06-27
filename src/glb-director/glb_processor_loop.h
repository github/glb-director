#include <rte_distributor.h>

#include "glb_kni.h"
#include "glb_director_config.h"

typedef enum {
	GLB_CONTROL_MSG_RELOAD_UNUSED = 0,
	GLB_CONTROL_MSG_RELOAD_CONFIG = 1,
} glb_processor_control_msg_cmd;

struct glb_processor_control_msg {
	glb_processor_control_msg_cmd cmd;

	union {
		struct {
			struct glb_fwd_config_ctx *new_config_ctx;
		} reload_msg;
	};
};

/*
 * total_packet_count == (
	director_packet_count + classification_failures + eth_rx_errors +
 kni_packet_count
 )
 * director_packet_count == (
	encap_successes + encap_failures
 )
 * director_packet_count == eth_tx_packets_sent
 * kni_packet_count == kni_tx_packets_sent
 */
struct processor_metrics {
	rte_atomic64_t total_packet_count;
	rte_atomic64_t director_packet_count;
	rte_atomic64_t classification_failures;
	rte_atomic64_t eth_rx_errors;
	rte_atomic64_t kni_packet_count;
	rte_atomic64_t encap_failures;
	rte_atomic64_t encap_successes;
	rte_atomic64_t eth_tx_packets_sent;
	rte_atomic64_t kni_tx_packets_sent;
	rte_atomic64_t reload_count;
} __rte_cache_aligned;

struct glb_processor_ctx {
	struct glb_fwd_config_ctx *config_ctx;
	struct rte_ring *control_msg_ring;

	unsigned int num_ports;

	// notification flags for this core
	rte_atomic32_t director_stop;

	// metrics for this core
	struct processor_metrics metrics;

	glb_director_lcore_config lcore_config;

	// distributor used by both dist and worker workloads
	struct rte_distributor *dist;
	// for workers, their worker ID (unique, sequential from 0)
	unsigned int dist_worker_id;
};

int main_loop_processor(void *arg);
