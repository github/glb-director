#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <rte_eth_bond.h>
#include <stdarg.h>
#include <stdbool.h>
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

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_distributor.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_kni.h>
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
#include <rte_udp.h>

#include "bind_classifier.h"
#include "config.h"
#include "glb_control_loop.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_fwd_config.h"
#include "glb_kni.h"
#include "glb_processor_loop.h"
#include "shared_opt.h"
#include "util.h"

char config_file[256];
char forwarding_table[256];

int port_num_queues[MAX_KNI_PORTS];

glb_kni *kni_ports[MAX_KNI_PORTS] = {NULL};

/* Use an array of pointers rather than a contiguous array of structs
 * so that the pointers can be allocated separately, keeping them core-local.
 */
struct glb_processor_ctx *glb_lcore_contexts[RTE_MAX_LCORE] = {NULL};
struct rte_mempool *glb_processor_msg_pool = NULL;

/* Options for configuring ethernet port */
struct rte_eth_conf port_conf = {
    .rxmode =
	{
	    .header_split = 0,   /* Header Split disabled */
	    .hw_ip_checksum = 1, /* IP checksum offload disabled */
	    .hw_vlan_filter = 0, /* VLAN filtering disabled */
	    .jumbo_frame = 0,    /* Jumbo Frame Support disabled */
	    .hw_strip_crc = 1,   /* CRC stripped by hardware */
	    .mq_mode = ETH_MQ_RX_RSS,
	},
    .txmode =
	{
	    .mq_mode = ETH_MQ_TX_NONE,
	},
    .rx_adv_conf = {.rss_conf = {
			.rss_key = NULL, .rss_hf = ETH_RSS_UDP | ETH_RSS_TCP,
		    }}};

/* Initialise a single port on an Ethernet device */
static void init_port(uint8_t port, uint32_t num_queues, struct rte_mempool *pktmbuf_pool)
{
	int ret;
	uint32_t i;

	port_num_queues[port] = num_queues;

	/* Initialise device and RX/TX queues */
	glb_log_info("Initialising port %u with %u queues...", (unsigned)port,
		     (unsigned)num_queues);
	fflush(stdout);
	ret = rte_eth_dev_configure(port, num_queues, num_queues, &port_conf);
	if (ret < 0)
		glb_log_error_and_exit("Could not configure port%u (%d)",
				       (unsigned)port, ret);

	struct rte_eth_dev_info nic_info;
	rte_eth_dev_info_get(DEFAULT_ETH_DEV, &nic_info);
	struct rte_eth_rxconf rxconf = nic_info.default_rxconf;
	rxconf.rx_drop_en = 1;

	for (i = 0; i < num_queues; i++) {
		ret = rte_eth_rx_queue_setup(port, i, NB_RXD,
					     rte_eth_dev_socket_id(port),
					     &rxconf, pktmbuf_pool);
		if (ret < 0)
			glb_log_error_and_exit(
			    "Could not setup up RX queue for "
			    "port%u (%d)",
			    (unsigned)port, ret);

		ret = rte_eth_tx_queue_setup(port, i, NB_TXD,
					     rte_eth_dev_socket_id(port), NULL);

		if (ret < 0)
			glb_log_error_and_exit(
			    "Could not setup up TX queue for "
			    "port%u (%d)",
			    (unsigned)port, ret);
	}

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		glb_log_error_and_exit("Could not start port%u (%d)",
				       (unsigned)port, ret);
}

uint32_t kni_ip = 0;

int main(int argc, char **argv)
{
	int ret = 0, i;
	unsigned core;
	uint8_t nb_sys_ports;
	int lcore_id, nb_switching_cores;
	uint8_t physical_num_queues;

	/* Associate signal_hanlder function with USR signals */
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGRTMIN, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Initialise EAL */
	glb_log_info("Initialising EAL ...");
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		glb_log_error_and_exit("Could not initialise EAL (%d)", ret);

	argc -= ret;
	argv += ret;

	/* Find any command line options */
	get_options(config_file, forwarding_table, argc, argv);

	g_director_config =
	    glb_director_config_load_file(config_file, forwarding_table);
	glb_log_info("Loaded GLB configuration ...");

	if (g_director_config == NULL) {
		glb_log_error_and_exit("Could not load configuration.");
		return -1;
	}

	glb_log_info("lcore status:");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id)) {
			glb_log_info("-> core %d is enabled", lcore_id);
		}
	}

	/* Find out how many NIC ports we have, validate that it's reasonable */
	nb_sys_ports = rte_eth_dev_count();
	if (nb_sys_ports == 0) {
		glb_log_error_and_exit("No supported Ethernet device found");
		return -1;
	}
	glb_log_info("Ethernet devices: %d", nb_sys_ports);

	nb_switching_cores = rte_lcore_count();
	if (nb_switching_cores == 0) {
		glb_log_error_and_exit("No execution units found.");
		return -1;
	}
	glb_log_info("Swithcing cores: %d", nb_switching_cores);

	/* Create the mbuf pool */
	struct rte_mempool *pktmbuf_pool =
	    rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, MEMPOOL_CACHE_SZ, 0,
				    MBUF_DATA_SZ, rte_socket_id());

	if (pktmbuf_pool == NULL) {
		glb_log_error_and_exit("Could not initialise mbuf pool");
		return -1;
	}
	glb_log_info("Created pktmbuf_pool ...");

	struct rte_eth_dev_info nic_info;
	rte_eth_dev_info_get(DEFAULT_ETH_DEV, &nic_info);

	glb_log_info("NIC %d info:", DEFAULT_ETH_DEV);
	glb_log_info("-> Driver used: %s", nic_info.driver_name);
	glb_log_info("-> Port has: max_rx_queues=%d, max_tx_queues=%d",
		     nic_info.max_rx_queues, nic_info.max_tx_queues);

	physical_num_queues = g_director_config->nb_queues;

	if ((physical_num_queues > nic_info.max_rx_queues) ||
	    (physical_num_queues > nic_info.max_tx_queues)) {
		glb_log_error_and_exit(
		    "Could not use specified number of cores (%d) "
		    "with a NIC supporting only %d/%d queues.",
		    physical_num_queues, nic_info.max_rx_queues,
		    nic_info.max_tx_queues);
		return -1;
	}

	glb_log_info(
	    "Initialising with %d ethernet ports and %d lcores over %d "
	    "queues",
	    nb_sys_ports, rte_lcore_count(), physical_num_queues);

	for (i = 0; i < nb_sys_ports; i++) {
		init_port(i, physical_num_queues, pktmbuf_pool);
	}

	if (g_director_config->kni_enabled) {
		rte_kni_init(nb_sys_ports);
	}

	/* Pre-allocate the control message mbuf pool */
	glb_processor_msg_pool = rte_mempool_create(
	    "glb_processor_msg_pool", 0xff,
	    sizeof(struct glb_processor_control_msg), 0, 0, NULL, NULL,
	    NULL, NULL, SOCKET_ID_ANY, 0);
	if (glb_processor_msg_pool == NULL) {
		glb_log_error_and_exit(
		    "Could not create control msg mbuf pool.");
		return -1;
	}

	glb_log_info("Loading GLB config...");
	struct glb_fwd_config_ctx *config_ctx = load_glb_fwd_config();

	if (config_ctx == NULL) {
		glb_log_error_and_exit("Failed to parse configuration.");
	}

	if (config_ctx->bind_classifier_v4 == NULL &&
	    config_ctx->bind_classifier_v6 == NULL) {
		glb_log_error(
		    "No bind classifiers found, are you missing binds?");
	}

	glb_log_info("GLB config context: %p", config_ctx);
	glb_fwd_config_dump(config_ctx);

	/* Helpfully print out the MAC of the NIC */
	char mac[128];
	rte_eth_macaddr_get(0, &g_director_config->local_ether_addr);
	ether_format_addr(mac, sizeof(mac),
			  &g_director_config->local_ether_addr);
	glb_log_info(" -> MAC Address: %s", mac);

	/* Prepare the context for each core */
	int kni_index = 0;
	RTE_LCORE_FOREACH(core)
	{
		/* Allocate the context core-local and use RTE_CACHE_LINE_SIZE alignment
		 * to ensure we don't get contention between cores.
		 */
		struct glb_processor_ctx *ctx = rte_malloc_socket(
			"glb-lcore-context",
			sizeof(struct glb_processor_ctx),
			RTE_CACHE_LINE_SIZE,
			rte_lcore_to_socket_id(core)
		);
		if (ctx == NULL) {
			glb_log_error_and_exit("Failed to allocate lcore context.");
		}

		glb_lcore_contexts[core] = ctx;

		ctx->num_ports = nb_sys_ports;
		ctx->config_ctx = config_ctx;

		ctx->lcore_config = g_director_config->lcore_configs[core];

		ctx->dist = NULL;

		rte_atomic32_clear(&ctx->director_stop);

		rte_atomic64_clear(&ctx->metrics.total_packet_count);
		rte_atomic64_clear(&ctx->metrics.director_packet_count);
		rte_atomic64_clear(&ctx->metrics.classification_failures);
		rte_atomic64_clear(&ctx->metrics.eth_rx_errors);
		rte_atomic64_clear(&ctx->metrics.kni_packet_count);
		rte_atomic64_clear(&ctx->metrics.encap_failures);
		rte_atomic64_clear(&ctx->metrics.encap_successes);
		rte_atomic64_clear(&ctx->metrics.eth_tx_packets_sent);
		rte_atomic64_clear(&ctx->metrics.kni_tx_packets_sent);
		rte_atomic64_clear(&ctx->metrics.reload_count);

		// set up for processor lcores
		if (core != rte_get_master_lcore()) {
			glb_log_info("lcore %u setup with workloads 0x%04x", core, ctx->lcore_config.workloads);

			if ((ctx->lcore_config.workloads & CORE_WORKLOAD_KNI) != 0) {
				for (kni_index = 0; kni_index < nb_sys_ports; kni_index++) {
					kni_ports[kni_index] = glb_kni_new(kni_index, 0, core, pktmbuf_pool);
					if (kni_ports[kni_index] == NULL) {
						glb_log_error_and_exit(
						    "Could not create KNI for "
						    "lcore %d.",
						    core);
						return -1;
					}
				}
			}

			if ((ctx->lcore_config.workloads & CORE_WORKLOAD_DIST) != 0) {
				// create the distributor to be linked up to workers on a second pass below
				char dist_name[64];
				sprintf(dist_name, "glb_dist_%i", core);
				ctx->dist = rte_distributor_create(
					dist_name,
					rte_lcore_to_socket_id(core),
					ctx->lcore_config.num_dist_workers,
					RTE_DIST_ALG_BURST
				);
				if (ctx->dist == NULL) {
					glb_log_error_and_exit(
					    "Could not create rte_distributor for "
					    "lcore %d.",
					    core);
					return -1;
				}
			}

			// prepare buffer for control msgs from master lcore
			char ring_name[64];
			sprintf(ring_name, "glb_control_msg_ring_%i", core);
			ctx->control_msg_ring = rte_ring_create(
			    ring_name, 0x10, rte_lcore_to_socket_id(core), 0);
			if (ctx->control_msg_ring == NULL) {
				glb_log_error_and_exit(
				    "Could not create control_msg_ring for "
				    "lcore %d.",
				    core);
				return -1;
			}
		}
	}

	// second pass
	unsigned int worker_ids[RTE_MAX_LCORE];
	memset(worker_ids, 0, sizeof(worker_ids));
	RTE_LCORE_FOREACH_SLAVE(core)
	{
		struct glb_processor_ctx *ctx = glb_lcore_contexts[core];

		if ((ctx->lcore_config.workloads & CORE_WORKLOAD_WORK) != 0) {
			// grab the pre-created (above) distributor and assign it to this core as a work source
			int src = ctx->lcore_config.source_dist_core;

			glb_log_info("lcore %u configured to source from distributor lcore %u", core, src);

			ctx->dist = glb_lcore_contexts[src]->dist;
			ctx->dist_worker_id = worker_ids[src];
			worker_ids[src]++;
		}
	}

	/* Launch per-lcore function on every lcore */
	RTE_LCORE_FOREACH_SLAVE(i)
	{
		rte_eal_remote_launch(main_loop_processor, glb_lcore_contexts[i], i);
	}
	main_loop_control(NULL);
	RTE_LCORE_FOREACH_SLAVE(i)
	{
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}

	glb_log_info("workload lcores have exited");

	if (g_director_config->kni_enabled) {
		for (i = 0; i < nb_sys_ports; i++) {
			glb_log_info("  releasing kni on port %d", i);
			glb_kni_release(kni_ports[i]);
		}
	}

	return 0;
}
