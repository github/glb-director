/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018 GitHub.
 * Copyright (c) 2016 Intel Corporation. (original DPDK example code)
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <inttypes.h>

#include <rte_acl.h>
#include <rte_atomic.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_distributor.h>

#include "bind_classifier.h"
#include "config.h"
#include "glb_control_loop.h"
#include "glb_encap_dpdk.h"
#include "glb_fwd_config.h"
#include "glb_kni.h"
#include "glb_processor_loop.h"
#include "log.h"
#include "util.h"

#define TARGET_DROP (0x0)
#define TARGET_KNI (0x1)
#define TARGET_FLOW_PATH(fp_id) (0x2 | (fp_id << 8))
#define GET_TARGET_FLOW_PATH(target) (target >> 8)

extern glb_kni *kni_ports[MAX_KNI_PORTS];

// enable extra flow debugging, useful during development
// #define TRACE_PACKET_FLOW

static inline int processor_base_workload(struct glb_processor_ctx *ctx)
{
	// check for control messages on our control ring
	struct glb_processor_control_msg *msg = NULL;
	int ret = rte_ring_dequeue(ctx->control_msg_ring, (void **)&msg);
	if (unlikely(ret == 0 && msg != NULL)) {
		// got a control message, process it
		if (msg->cmd == GLB_CONTROL_MSG_RELOAD_CONFIG) {
			glb_fwd_config_ctx_decref(ctx->config_ctx);

			// holds a ref already, steal it
			ctx->config_ctx =
			    msg->reload_msg.new_config_ctx; 

			glb_log_debug("lcore-%u: loaded new config",
			     rte_lcore_id());

			rte_atomic64_inc(&ctx->metrics.reload_count);
		}

		// now return the message to the pool
		rte_mempool_put(glb_processor_msg_pool, msg);
	}

	return rte_atomic32_read(&ctx->director_stop);
}

static inline void processor_base_kni(struct glb_processor_ctx *ctx)
{
	unsigned int i;
	for (i = 0; i < ctx->num_ports; i++) {
		glb_kni_lcore_flush(kni_ports[i]);
	}
}

/*
 * RX bursts on each flow path defined on this core.
 * Expects pkts_burst to be big enough to hold PKT_BURST_SZ packets for EACH flow path.
 * Returns the total number of mbufs received across all flow paths.
 */
static inline uint32_t processor_burst_rx_on_flows(struct glb_processor_ctx *ctx, struct rte_mbuf **pkts_burst)
{
	glb_director_lcore_config *lcore_config = &ctx->lcore_config;
	uint16_t nb_rx;

	unsigned int f = 0, i = 0;

	uint32_t total_rx = 0;

	for (f = 0; f < lcore_config->num_flow_paths; f++) {
		glb_director_flow_path *flow_path = &lcore_config->flow_paths[f];

		nb_rx = rte_eth_rx_burst(flow_path->rx_port_id, flow_path->rx_queue_id, &pkts_burst[total_rx], PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			glb_log_error("Error receiving from eth");
			rte_atomic64_add(&ctx->metrics.eth_rx_errors, nb_rx);
			return 0;
		}

		if (unlikely(nb_rx == 0))
			continue;

#ifdef TRACE_PACKET_FLOW
		glb_log_debug("lcore-%u: received %d packets on flow path id %d",
		     rte_lcore_id(), nb_rx, f);
#endif

		for (i = 0; i < nb_rx; i++) {
			// remember which flow this came from
			pkts_burst[total_rx + i]->udata64 = TARGET_FLOW_PATH(f);
		}

		rte_atomic64_add(&ctx->metrics.total_packet_count, nb_rx);
		total_rx += nb_rx;
	}

	return total_rx;
}

typedef struct {
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	unsigned int num_packets;
} packet_burst;

static inline int flush_packet_burst(struct glb_processor_ctx *ctx, glb_director_flow_path *flow_path, packet_burst *burst)
{
	if (likely(burst->num_packets > 0)) {
		uint16_t sent =
		    rte_eth_tx_burst(flow_path->tx_port_id, flow_path->tx_queue_id,
				     burst->pkts_burst, burst->num_packets);
		burst_free_missed_mbufs(burst->pkts_burst,
					burst->num_packets, sent);

#ifdef TRACE_PACKET_FLOW
		glb_log_debug(
		    "lcore-%u: -> %d packets bursting to "
		    "ethernet TX queue (%d actually "
		    "sent)",
		    rte_lcore_id(), burst->num_packets, sent);
#endif

		rte_atomic64_add(
		    &ctx->metrics.eth_tx_packets_sent,
		    sent);

		burst->num_packets = 0;

		return sent;
	}

	return 0;
}

#define CORE_WORKLOAD_RX_DIST_TX (CORE_WORKLOAD_RX | CORE_WORKLOAD_DIST | CORE_WORKLOAD_TX)
static inline int processor_rx_dist_tx(struct glb_processor_ctx *ctx)
{
	glb_director_lcore_config *lcore_config = &ctx->lcore_config;
	uint32_t perform_kni = ((lcore_config->workloads & CORE_WORKLOAD_KNI) != 0);

	unsigned int i = 0;

	struct rte_distributor *dist = ctx->dist;

	struct rte_mbuf *pkts_burst[PKT_BURST_SZ * lcore_config->num_flow_paths];

	// create a TX burst for KNI and then each available flow path.
	packet_burst per_path_tx_bursts[lcore_config->num_flow_paths];
	memset(per_path_tx_bursts, 0, sizeof(per_path_tx_bursts));

	glb_log_info("lcore-%u: running processor_rx_dist_tx",
		     rte_lcore_id());

	while (likely(processor_base_workload(ctx) == 0)) {
		if (unlikely(perform_kni)) {
			processor_base_kni(ctx);
		}

		// RX across all flow paths on this core
		uint32_t nb_rx = processor_burst_rx_on_flows(ctx, pkts_burst);

#ifdef TRACE_PACKET_FLOW
		if (nb_rx > 0)
			glb_log_debug("lcore-%u: rx %d total, ready to distirbute",
			     rte_lcore_id(), nb_rx);
#endif

		// DIST these packets across worker cores
		// even if there are none, gives us a chance to collect more returns
		rte_distributor_process(dist, pkts_burst, nb_rx);

		const uint16_t nb_ret = rte_distributor_returned_pkts(dist,
                                        pkts_burst, PKT_BURST_SZ * lcore_config->num_flow_paths);

		if (unlikely(nb_ret == 0))
			continue;

#ifdef TRACE_PACKET_FLOW
		glb_log_debug("lcore-%u: received %d total from workers, processing",
		     rte_lcore_id(), nb_ret);
#endif

		// shard out the returned packets over their flow paths
		for (i = 0; i < nb_ret; i++) {
			struct rte_mbuf *pkt = pkts_burst[i];
			int target = pkt->udata64;
			
			if (unlikely(target == TARGET_KNI && perform_kni)) {
				if (perform_kni) {
					// FIXME: make this a burst, not 1 by 1
					uint16_t sent = glb_kni_safe_tx_burst(
					    kni_ports[pkt->port], &pkt, 1);
					burst_free_missed_mbufs(&pkt, 1, sent);

#ifdef TRACE_PACKET_FLOW
					glb_log_debug(
					    "lcore-%u: -> %d packets bursting to "
					    "KNI (%d actually queued)",
					    rte_lcore_id(), 1, sent);
#endif

					rte_atomic64_add(
					    &ctx->metrics.kni_tx_packets_sent,
					    sent);
				}
			} else if (unlikely(target == TARGET_KNI || target == TARGET_DROP)) {
				// KNI isn't enabled or packet should be dropped, burn the packet
				rte_pktmbuf_free(pkt);
			} else {
				// find where we're sending this
				int flow_path_id = GET_TARGET_FLOW_PATH(target);
				packet_burst *pb = &per_path_tx_bursts[flow_path_id];

				pb->pkts_burst[pb->num_packets] = pkt;
				pb->num_packets++;

#ifdef TRACE_PACKET_FLOW
				glb_log_debug("lcore-%u: flow path %d has %d packets queued for tx burst",
				     rte_lcore_id(), flow_path_id, pb->num_packets);
#endif

				if (unlikely(pb->num_packets == PKT_BURST_SZ)) {
					glb_director_flow_path *flow_path = &lcore_config->flow_paths[flow_path_id];
					flush_packet_burst(ctx, flow_path, pb);
				}
			}
		}

		// TX out to each flow path that has data
		for (i = 0; i < lcore_config->num_flow_paths; i++) {
			glb_director_flow_path *flow_path = &lcore_config->flow_paths[i];
			flush_packet_burst(ctx, flow_path, &per_path_tx_bursts[i]);
		}
	}

	rte_distributor_flush(ctx->dist);
	rte_distributor_clear_returns(ctx->dist);

	return 0;
}

static inline int processor_worker(struct glb_processor_ctx *ctx)
{
	unsigned int i;
	int ret;

	struct rte_distributor *dist = ctx->dist;
	const unsigned int worker_id = ctx->dist_worker_id;
	
	// distributor receives up to 8 packets, which seems to be implicit in DPDK's API
	struct rte_mbuf *pkts_burst[8] __rte_cache_aligned;
	uint32_t classifications[8];
	unsigned int num_pkts = 0;

	glb_log_info("lcore-%u: running processor_worker",
		     rte_lcore_id());
	glb_log_info("lcore-%u: packet classifier v4: %p", rte_lcore_id(),
		     ctx->config_ctx->bind_classifier_v4);
	glb_log_info("lcore-%u: packet classifier v6: %p", rte_lcore_id(),
		     ctx->config_ctx->bind_classifier_v6);

	for (i = 0; i < 8; i++)
		pkts_burst[i] = NULL;

	while (1) {
		// retrieve a burst of packets to work on, returning the last burst
		num_pkts = rte_distributor_get_pkt(dist, worker_id, pkts_burst, pkts_burst, num_pkts);

		// run this here to give the bind classifier the best chance to update before it's used (next)
		if (unlikely(processor_base_workload(ctx) != 0)) {
			// free all our mbufs, since the distributor will be going away too
			burst_free_mbufs(pkts_burst, num_pkts);
			break;
		}

		ret = classify_to_tables(ctx->config_ctx->bind_classifier_v4,
					ctx->config_ctx->bind_classifier_v6, pkts_burst,
					classifications, num_pkts);
		if (unlikely(ret != 0)) {
			glb_log_info(
			    "lcore-%u: !!! failed to classify, "
			    "not forwarding packets !!!",
			    rte_lcore_id());
			for (i = 0; i < num_pkts; i++) {
				// mark as destined for drop, don't forward
				pkts_burst[i]->udata64 = TARGET_DROP;
			}
			rte_atomic64_add(
			    &ctx->metrics.classification_failures,
			    num_pkts);
			continue;
		}

		for (i = 0; i < num_pkts; i++) {
#ifdef TRACE_PACKET_FLOW
			rte_pktmbuf_dump(stdout, pkts_burst[i], 54);
#endif
			if (unlikely(!CLASSIFIED(classifications[i]))) {
#ifdef TRACE_PACKET_FLOW
				glb_log_debug(
				    "lcore-%u: -> %d/%d didn't get "
				    "classified, send to KNI",
				    rte_lcore_id(), i, num_pkts);
#endif

				pkts_burst[i]->udata64 = TARGET_KNI;
				rte_atomic64_inc(&ctx->metrics.kni_packet_count);
			} else {
				int table = CLASSIFIED_TABLE(classifications[i]);
				struct rte_mbuf *pkt = pkts_burst[i];

#ifdef TRACE_PACKET_FLOW
				glb_log_debug(
				    "lcore-%u: -> %d/%d classified as "
				    "table %d",
				    rte_lcore_id(), i, num_pkts, table);
#endif

				rte_atomic64_inc(&ctx->metrics.director_packet_count);

				if (likely(glb_encapsulate_packet_dpdk(ctx->config_ctx, pkt, table) == 0)) {
					// the target is left as-is (the default for the flow path)
					// and the mbuf now contains the correctly encap'ed packet.
					// nothing more to do here.
					rte_atomic64_inc(&ctx->metrics.encap_successes);
#ifdef TRACE_PACKET_FLOW
					glb_log_debug(
					    "lcore-%u: ->  -> encap success",
					    rte_lcore_id());
#endif
				} else {
					// free the packet, we're dropping it
					pkts_burst[i]->udata64 = TARGET_DROP;
					rte_atomic64_add(&ctx->metrics.encap_failures, 1);
#ifdef TRACE_PACKET_FLOW
					glb_log_debug(
					    "lcore-%u: ->  -> encap failure",
					    rte_lcore_id());
#endif
				}

#ifdef TRACE_PACKET_FLOW
				glb_log_debug(
				    "lcore-%u: ->  -> target is %d",
				    rte_lcore_id(), pkts_burst[i]->udata64);
#endif
			}
		}
	}

	return 0;
}

int main_loop_processor(void *arg)
{
	struct glb_processor_ctx *ctx = (struct glb_processor_ctx *)arg;
	glb_director_lcore_config *lcore_config = &ctx->lcore_config;
	uint32_t lcore_workloads = lcore_config->workloads;

	glb_log_info("lcore-%u: running main_loop_processor",
		     rte_lcore_id());

	// do the actual work designated to this lcore
	if ((lcore_workloads & CORE_WORKLOAD_RX_DIST_TX) == 
		CORE_WORKLOAD_RX_DIST_TX) {
		return processor_rx_dist_tx(ctx);
	}

	if ((lcore_workloads & CORE_WORKLOAD_WORK) != 0) {
		return processor_worker(ctx);
	}

	return 0;
}
