#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include <signal.h>
#include <unistd.h>

#include "config.h"
#include "glb_control_loop.h"
#include "glb_director_config.h"
#include "glb_fwd_config.h"
#include "glb_processor_loop.h"
#include "glb_kni.h"
#include "log.h"
#include "statsd-client.h"

#define STATSD_IP "127.0.0.1"
#define STATSD_PORT 28125
#define STATSD_NS "glb_director_ng"

int reload_count = 0;
rte_atomic32_t director_stop = RTE_ATOMIC32_INIT(0);
rte_atomic32_t reload_requested = RTE_ATOMIC32_INIT(0);

extern struct glb_processor_ctx *glb_lcore_contexts[RTE_MAX_LCORE];

extern glb_kni *kni_ports[MAX_KNI_PORTS];

void signal_handler(int signum)
{
	/* handle reload request */
	if (signum == SIGUSR1) {
		glb_log_info("SIGUSER1 received, requesting state reload.");
		reload_count++;
		rte_atomic32_test_and_set(&reload_requested);
	}

	/* handle signals that trigger graceful termination */
	if (signum == SIGRTMIN || signum == SIGINT || signum == SIGTERM) {
		glb_log_info(
		    "Signal %d received, processing is going to stop", signum);
		rte_atomic32_test_and_set(&director_stop);
	}
}

struct glb_fwd_config_ctx *load_glb_fwd_config(void)
{
	return create_glb_fwd_config(g_director_config->forwarding_table_path);
}

static void
enqueue_reload_control_msg(struct glb_fwd_config_ctx *new_config_ctx)
{
	uint8_t i;
	int ret;
	struct glb_processor_control_msg *msg;
	struct glb_processor_ctx *context;
	RTE_LCORE_FOREACH_SLAVE(i)
	{
		msg = NULL;
		ret = rte_mempool_get(glb_processor_msg_pool, (void **)&msg);
		if (ret != 0 || msg == NULL) {
			glb_log_info("got ret=%d, msg=%p when trying to get a "
				     "control buffer from pool.",
				     ret, msg);
			continue;
		}

		msg->cmd = GLB_CONTROL_MSG_RELOAD_CONFIG;
		msg->reload_msg.new_config_ctx =
		    glb_fwd_config_ctx_incref(new_config_ctx);

		// enqueue the message
		context = glb_lcore_contexts[i];
		ret = rte_ring_enqueue(context->control_msg_ring, msg);
		if (ret != 0) {
			glb_log_info(
			    "failed to enqueue control message, ret=%d.", ret);
			rte_mempool_put(glb_processor_msg_pool, msg);
			continue;
		}
	}
}

static inline void send_logs_metrics(statsd_link *link)
{
	static struct rte_eth_stats prev_eth_stats[RTE_MAX_ETHPORTS];
	static int first_stats_run = 1;
	struct rte_eth_stats curr_eth_stats[RTE_MAX_ETHPORTS];

	char tag[64];
	unsigned port_id, num_stats, i, core;

	unsigned master_lcore = rte_get_master_lcore();
	unsigned num_ports = glb_lcore_contexts[master_lcore]->num_ports;

	struct rte_eth_dev_info nic_info;
	rte_eth_dev_info_get(DEFAULT_ETH_DEV, &nic_info);

	// retrieve all per-port stats
	// http://www.dpdk.org/doc/api/structrte__eth__stats.html
	for (port_id = 0; port_id < num_ports; port_id++) {
		rte_eth_stats_get(port_id, &curr_eth_stats[port_id]);
	}

	// the first time we need to set prev=curr so we don't emit old stats
	if (first_stats_run) {
		memcpy(prev_eth_stats, curr_eth_stats, sizeof(struct rte_eth_stats) * num_ports);
		first_stats_run = 0;
	}

#define SEND_DELTA_METRIC(METRIC_NAME, FIELD_ACCESSOR) \
	statsd_count(link, METRIC_NAME, \
		(curr_eth_stats[port_id]. FIELD_ACCESSOR \
			- prev_eth_stats[port_id]. FIELD_ACCESSOR), \
		1, tag);

	// for each of our ports, compute the delta
	for (port_id = 0; port_id < num_ports; port_id++) {
		sprintf(tag, "port:%02u", port_id);

		SEND_DELTA_METRIC("port.packets.rx", ipackets);
		SEND_DELTA_METRIC("port.packets.tx", opackets);
		SEND_DELTA_METRIC("port.bytes.rx", ibytes);
		SEND_DELTA_METRIC("port.bytes.tx", obytes);
		SEND_DELTA_METRIC("port.packets.rx_missed", imissed);
		SEND_DELTA_METRIC("port.packets.rx_errors", ierrors);
		SEND_DELTA_METRIC("port.packets.tx_errors", oerrors);
		SEND_DELTA_METRIC("port.packets.rx_nombuf", rx_nombuf);

		/*
			    printf("port-%u:"
				   " ipackets: %" PRIu64 " opackets: %" PRIu64
				   " ibytes: %" PRIu64 " obytes: %" PRIu64
				   " imissed: %" PRIu64 " ierrors: %" PRIu64
				   " oerrors: %" PRIu64 " rx_nombuf: %" PRIu64
		   "", port_id, eth_stats.ipackets, eth_stats.opackets,
				   eth_stats.ibytes, eth_stats.obytes,
		   eth_stats.imissed, eth_stats.ierrors, eth_stats.oerrors,
				   eth_stats.rx_nombuf);
			    */

		num_stats = RTE_MIN((unsigned int)RTE_ETHDEV_QUEUE_STAT_CNTRS,
				    nic_info.max_rx_queues);
		for (i = 0; i < num_stats; i++) {
			sprintf(tag, "port:%02u,queue:%02u", port_id, i);

			SEND_DELTA_METRIC("queue.packets.rx", q_ipackets[i]);
			SEND_DELTA_METRIC("queue.packets.rx_errors", q_errors[i]);
			SEND_DELTA_METRIC("queue.bytes.rx", q_ibytes[i]);

			/*
			       glb_log_info(
				       "port-%u, queue-%u:"
				       " q_ipackets: %" PRIu64 " q_ibytes: %"
			   PRIu64
				       "",
				       port_id, i, eth_stats.q_ipackets[i],
				       eth_stats.q_ibytes[i]);
			*/
		}

		num_stats = RTE_MIN((unsigned int)RTE_ETHDEV_QUEUE_STAT_CNTRS,
				    nic_info.max_tx_queues);

		for (i = 0; i < num_stats; i++) {
			sprintf(tag, "port:%02u,queue:%02u", port_id, i);

			SEND_DELTA_METRIC("queue.packets.tx", q_opackets[i]);
			SEND_DELTA_METRIC("queue.bytes.tx", q_obytes[i]);

			/*
			glb_log_info(
				"port-%u, queue-%u:"
				" q_opackets: %" PRIu64 " q_obytes: %" PRIu64
				" q_errors: %" PRIu64 "",
				port_id, i, eth_stats.q_opackets[i],
				eth_stats.q_obytes[i],
				eth_stats.q_errors[i] // based on usage in the
						      // dpdk repo this is tx
			);
			*/
		}
	}

	// now set prev=curr to remember these values for the next delta
	memcpy(prev_eth_stats, curr_eth_stats, sizeof(struct rte_eth_stats) * num_ports);

#define SEND_RESET_METRIC(METRIC_NAME, FIELD_ACCESSOR) \
	{ \
		uint64_t value = rte_atomic64_read( \
			&glb_lcore_contexts[core]->metrics. FIELD_ACCESSOR); \
		rte_atomic64_sub(&glb_lcore_contexts[core]->metrics. FIELD_ACCESSOR, value); \
		statsd_count(link, METRIC_NAME, value, 1, tag); \
	}

	RTE_LCORE_FOREACH(core)
	{
		// per-core metrics
		sprintf(tag, "core:%02u", core);

		SEND_RESET_METRIC("core.packets.total", total_packet_count);
		SEND_RESET_METRIC("core.packets.matched", director_packet_count);
		SEND_RESET_METRIC("core.packets.unmatched", classification_failures);
		SEND_RESET_METRIC("core.packets.rx_errors", eth_rx_errors);
		SEND_RESET_METRIC("core.packets.kni", kni_packet_count);
		SEND_RESET_METRIC("core.packets.encap.success", encap_successes);
		SEND_RESET_METRIC("core.packets.encap.failure", encap_failures);
		SEND_RESET_METRIC("core.packets.eth_tx_sent", eth_tx_packets_sent);
		SEND_RESET_METRIC("core.packets.kni_tx_sent", kni_tx_packets_sent);

		SEND_RESET_METRIC("core.config_reload_count", reload_count);

		/*
		glb_log_info(
		    "lcore-%u:"
		    " total_packet_count: %" PRIu64
		    " director_packet_count: %" PRIu64
		    " classification_failures: %" PRIu64
		    " eth_rx_errors: %" PRIu64 " kni_packet_count: %" PRIu64
		    " encap_failures: %" PRIu64 " encap_successes: %" PRIu64
		    " eth_tx_packets_sent: %" PRIu64
		    " kni_tx_packets_sent: %" PRIu64 " reload_count: %" PRIu64
		    " master-lcore: %u",
		    core,
		    rte_atomic64_read(
			&contexts[core].metrics.total_packet_count),
		    rte_atomic64_read(
			&contexts[core].metrics.director_packet_count),
		    rte_atomic64_read(
			&contexts[core].metrics.classification_failures),
		    rte_atomic64_read(&contexts[core].metrics.eth_rx_errors),
		    rte_atomic64_read(&contexts[core].metrics.kni_packet_count),
		    rte_atomic64_read(&contexts[core].metrics.encap_failures),
		    rte_atomic64_read(&contexts[core].metrics.encap_successes),
		    rte_atomic64_read(
			&contexts[core].metrics.eth_tx_packets_sent),
		    rte_atomic64_read(
			&contexts[core].metrics.kni_tx_packets_sent),
		    rte_atomic64_read(&contexts[core].metrics.reload_count),
		    master_lcore);
		*/
	}
}

int main_loop_control(void *arg)
{
	(void)(arg);
	const unsigned lcore_id = rte_lcore_id();
	unsigned i;

#ifndef CLI_MODE
	struct glb_processor_ctx *main_ctx = glb_lcore_contexts[rte_get_master_lcore()];
	unsigned port_id;
#endif

#ifdef STATSD
	static unsigned stat_wait = 0;
#endif

	glb_log_info("lcore-%u: running main_loop_control", lcore_id);

#ifdef STATSD
	statsd_link *link;

	glb_log_info("starting statsd ...");
	link = statsd_init_with_namespace(STATSD_IP, STATSD_PORT, STATSD_NS);
#endif

	while (1) {
		if (rte_atomic32_read(&director_stop) == 1) {
			// notify all worker contexts
			RTE_LCORE_FOREACH_SLAVE(i)
			{
				rte_atomic32_test_and_set(&glb_lcore_contexts[i]->director_stop);
			}

			// stop our main loop, termination requested
			break;
		}

		if (rte_atomic32_read(&reload_requested) == 1) {
			// reset before we start processing, so a subsequent
			// request resets it to 1 again
			rte_atomic32_set(&reload_requested, 0);

			glb_log_info("lcore-%u: Reload requested", lcore_id);
			struct glb_fwd_config_ctx *new_config_ctx =
			    load_glb_fwd_config();

			// set the reload count for the master proc using the
			// value on the stack
			rte_atomic64_set(&glb_lcore_contexts[rte_get_master_lcore()]
					      ->metrics.reload_count,
					 reload_count);

			glb_log_info("lcore-%u: new config:", lcore_id);
			glb_fwd_config_dump(new_config_ctx);
			// enqueue control messages to each worker thread
			enqueue_reload_control_msg(new_config_ctx);

			// once all messages are enqueued, free our control ref
			// to it
			glb_fwd_config_ctx_decref(new_config_ctx);
		}

#ifdef STATSD
		stat_wait++;
		if (stat_wait >= 10) {
			send_logs_metrics(link);
			stat_wait = 0;
		}
#endif

		// handle KNI requests here, makes them delayed but keeps out of request pipeline
#ifndef CLI_MODE
		if (g_director_config->kni_enabled) {
			for (port_id = 0; port_id < main_ctx->num_ports; port_id++) {
				glb_kni *kni_port = kni_ports[port_id];
				glb_kni_handle_request(kni_port);
			}
		}
#endif

		sleep(1);
	}

	return 0;
}
