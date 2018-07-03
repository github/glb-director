/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018 GitHub.
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
