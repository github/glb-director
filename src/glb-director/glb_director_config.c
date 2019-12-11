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

#include <arpa/inet.h>
#include <unistd.h>
#include "stdlib.h"

#include <jansson.h>

#include "log.h"

#ifdef PCAP_MODE
/* use local copy since we aren't linked against dpdk in pcap mode */
#include "cmdline_parse_etheraddr.h"
#endif

#ifndef PCAP_MODE
#include <cmdline_parse_etheraddr.h>
#endif

#include "config.h"
#include "glb_director_config.h"

static int parse_hash_fields(const char *field_name, glb_director_hash_fields *out, json_t *cfg);

glb_director_config *g_director_config = NULL;

/* Convert a json_t *array containing a list of JSON integers to a C array.
 * If the array is larger than `max_out`, only the first `max_out` entries will be returned.
 * The caller should validate array sizes before calling this function if required.
 */
static inline unsigned json_int_array_to_c(json_t *array, uint32_t *out, unsigned max_out) {
	if (array == NULL || !json_is_array(array))
		return 0;

	unsigned i, o;
	for (i = 0, o = 0; i < json_array_size(array) && o < max_out; i++) {
		json_t *port_id = json_array_get(array, i);
		if (!json_is_number(port_id)) continue;

		out[o] = json_integer_value(port_id);
		o++;
	}

	return o;
}

glb_director_config *glb_director_config_load_file(const char *config_file,
						   const char *forwarding_table)
{
	glb_director_config *cfg = malloc(sizeof(glb_director_config));

	if (cfg == NULL) {
		return NULL;
	}

	memset(cfg, 0, sizeof(glb_director_config));

	if (access(config_file, F_OK) == -1) {
		glb_log_error_and_exit(
		    "Configuration filename must be provided: "
		    "--config-file <json-config-file>");
	}

	if (access(forwarding_table, F_OK) == -1) {
		glb_log_error_and_exit(
		    "Forwarding table filename must be provided: "
		    "--forwarding-table <binary-file>");
	}

	strncpy(cfg->forwarding_table_path, forwarding_table, PATH_MAX);

	json_error_t error;
	json_t *root = json_load_file(config_file, 0, &error);
	if (root == NULL) {
		glb_log_error_and_exit("Failed to parse %s", config_file);
	}

	json_t *item;
	int ret;

	item = json_object_get(root, "statsd_port");
	if (item != NULL && json_is_string(item)) {
		uint16_t port;
		port = atoi(json_string_value(item));
		cfg->statsd_port = port;
	} else {
		cfg->statsd_port = STATSD_PORT_DEFAULT;
	}
	
	item = json_object_get(root, "outbound_gateway_mac");
	if (item != NULL && json_is_string(item)) {
		ret = cmdline_parse_etheraddr(NULL, json_string_value(item),
					      (void *)&cfg->gateway_ether_addr,
					      sizeof(struct ether_addr));
		if (ret <= 0) {
			glb_log_error(
			    "Could not parse gateway MAC address from "
			    "'%s' (%d)",
			    json_string_value(item), ret);
			json_decref(root);
			free(cfg);
			return NULL;
		}
	} else {
		json_decref(root);
		glb_log_error_and_exit(
		    "outbound_gateway_mac missing from configuration");
	}

	item = json_object_get(root, "outbound_src_ip");
	if (item != NULL && json_is_string(item)) {
		if (!inet_pton(AF_INET, json_string_value(item),
			       &cfg->local_ip_addr)) {
			glb_log_error(
			    "Could not parse local IP address from '%s'",
			    json_string_value(item));
			json_decref(root);
			free(cfg);
			return NULL;
		}
	} else {
		json_decref(root);
		glb_log_error_and_exit(
		    "outbound_src_ip missing from configuration");
	}

	item = json_object_get(root, "kni_ip");
	if (item != NULL && json_is_string(item)) {
		if (!inet_pton(AF_INET, json_string_value(item),
			       &cfg->kni_ip)) {
			glb_log_error(
			    "Could not parse local IP address from '%s'",
			    json_string_value(item));
			json_decref(root);
			free(cfg);
			return NULL;
		}
	} else {
		cfg->kni_ip = 0;
	}

	item = json_object_get(root, "num_worker_queues");
	if (item != NULL && json_is_integer(item)) {
		cfg->nb_queues = json_integer_value(item);
	} else {
		cfg->nb_queues = 1;
	}

	item = json_object_get(root, "forward_icmp_ping_responses");
	if (item != NULL && json_is_false(item)) {
		cfg->forward_icmp_ping_responses = 0;
	} else {
		cfg->forward_icmp_ping_responses = 1;
	}

	item = json_object_get(root, "rx_drop_en");
	if (item != NULL && json_is_false(item)) {
		cfg->rx_drop_en = 0;
	} else {
		cfg->rx_drop_en = 1;
	}

	json_t *flow_paths = json_object_get(root, "flow_paths");
	unsigned f;
	if (flow_paths == NULL) {
		glb_log_error("flow_paths not configured");
		json_decref(root);
		free(cfg);
		return NULL;
	}

	cfg->num_flow_paths = json_array_size(flow_paths);
	for (f = 0; f < cfg->num_flow_paths; f++) {
		json_t *flow_path = json_array_get(flow_paths, f);

		cfg->flow_paths[f].rx_port_id =
			json_integer_value(json_object_get(flow_path, "rx_port"));
		cfg->flow_paths[f].rx_queue_id =
			json_integer_value(json_object_get(flow_path, "rx_queue"));
		cfg->flow_paths[f].tx_port_id =
			json_integer_value(json_object_get(flow_path, "tx_port"));
		cfg->flow_paths[f].tx_queue_id =
			json_integer_value(json_object_get(flow_path, "tx_queue"));
	}

	json_t *lcores = json_object_get(root, "lcores");
	int c;
	if (lcores == NULL) {
		glb_log_error("lcores not configured");
		json_decref(root);
		free(cfg);
		return NULL;
	}

	cfg->kni_enabled = 0;

	for (c = 0; c < RTE_MAX_LCORE; c++) {
		char name[32];
		snprintf(name, sizeof(name), "lcore-%d", c);
		json_t *core = json_object_get(lcores, name);
		if (core == NULL) continue;

		uint32_t workloads = CORE_WORKLOAD_NONE;

		if (json_is_true(json_object_get(core, "rx")))
			workloads |= CORE_WORKLOAD_RX;
		if (json_is_true(json_object_get(core, "tx")))
			workloads |= CORE_WORKLOAD_TX;
		if (json_is_true(json_object_get(core, "dist")))
			workloads |= CORE_WORKLOAD_DIST;
		if (json_is_true(json_object_get(core, "work")))
			workloads |= CORE_WORKLOAD_WORK;
		if (json_is_true(json_object_get(core, "kni"))) {
			workloads |= CORE_WORKLOAD_KNI;
			cfg->kni_enabled = 1;
		}

		cfg->lcore_configs[c].workloads = workloads;

		// RX and TX workloads operate on flow paths, retrieve them
		//   "lcore-16": { "rx": true, "flow_paths": [0, 1] },
		if ((workloads & (CORE_WORKLOAD_RX | CORE_WORKLOAD_TX)) != 0) {
			item = json_object_get(core, "flow_paths");

			if (json_array_size(item) > PER_CORE_MAX_FLOW_PATHS) {
				glb_log_error(
				    "%d flow paths configured, but a maximum of %d is supported",
				    json_array_size(item), PER_CORE_MAX_FLOW_PATHS);
				json_decref(root);
				free(cfg);
				return NULL;
			}

			uint32_t flow_path_ids[PER_CORE_MAX_FLOW_PATHS];
			unsigned num_flow_path_ids = json_int_array_to_c(
				item, &flow_path_ids[0], PER_CORE_MAX_FLOW_PATHS);

			cfg->lcore_configs[c].num_flow_paths = num_flow_path_ids;

			// validate that the specified flow_path ids are within range
			for (f = 0; f < num_flow_path_ids; f++) {
				if (flow_path_ids[f] >= cfg->num_flow_paths) {
					glb_log_error(
					    "lcore uses invalid flow_path id %d, only %d configured",
					    flow_path_ids[f], cfg->num_flow_paths);
					json_decref(root);
					free(cfg);
					return NULL;
				}

				cfg->lcore_configs[c].flow_paths[f] = cfg->flow_paths[flow_path_ids[f]];
			}
		}

		// distributor workloads need to know their max worker count
		//   "lcore-18": { "dist": true, "num_dist_workers": 9 },
		if ((workloads & CORE_WORKLOAD_DIST) != 0) {
			json_t *val = json_object_get(core, "num_dist_workers");
			if (val == NULL) {
				glb_log_error(
				    "num_dist_workers must be specified for distributors");
				json_decref(root);
				free(cfg);
				return NULL;
			}

			cfg->lcore_configs[c].num_dist_workers = 
				json_integer_value(val);

			if (cfg->lcore_configs[c].num_dist_workers < 1) {
				glb_log_error(
				    "num_dist_workers must be at least 1 for distributors");
				json_decref(root);
				free(cfg);
				return NULL;
			}
		}

		// worker workloads need to know their source distributor core
		//   "lcore-20": { "work": true, "work_source": 18 },
		if ((workloads & CORE_WORKLOAD_WORK) != 0) {
			json_t *val = json_object_get(core, "work_source");
			if (val == NULL) {
				glb_log_error(
				    "work_source must be specified for workers");
				json_decref(root);
				free(cfg);
				return NULL;
			}

			cfg->lcore_configs[c].source_dist_core = 
				json_integer_value(val);

			// roughly sanity check here, we can check in more detail in a
			// second pass when we set up the actual cores
			if (cfg->lcore_configs[c].source_dist_core > RTE_MAX_LCORE) {
				glb_log_error(
				    "work_source must be a valid core");
				json_decref(root);
				free(cfg);
				return NULL;
			}
		}
	}

	/* Hash field specification.
	 * By default, we include a single hash of source IP.
	 */
	cfg->hash_fields.src_addr = 1;
	cfg->hash_fields.dst_addr = 0;
	cfg->hash_fields.src_port = 0;
	cfg->hash_fields.dst_port = 0;
	cfg->use_alt_hash_fields = 0;

	json_t *hash_fields = json_object_get(root, "hash_fields");
	if (hash_fields != NULL) {
		if (parse_hash_fields("hash_fields", &cfg->hash_fields, hash_fields) != 0) {
			json_decref(root);
			free(cfg);
			return NULL;
		}
	}

	json_t *alt_hash_fields = json_object_get(root, "alt_hash_fields");
	if (alt_hash_fields != NULL) {
		cfg->use_alt_hash_fields = 1;

		if (parse_hash_fields("alt_hash_fields", &cfg->alt_hash_fields, alt_hash_fields) != 0) {
			json_decref(root);
			free(cfg);
			return NULL;
		}
	}

	json_decref(root);
	return cfg;
}

static int parse_hash_fields(const char *field_name, glb_director_hash_fields *out, json_t *cfg)
{
	out->src_addr = json_is_true(json_object_get(cfg, "src_addr"));
	out->dst_addr = json_is_true(json_object_get(cfg, "dst_addr"));
	out->src_port = json_is_true(json_object_get(cfg, "src_port"));
	out->dst_port = json_is_true(json_object_get(cfg, "dst_port"));

	/* succeed if we have at least one field configured */
	if (out->src_addr || out->dst_addr || out->src_port || out->dst_port) {
		return 0;
	} else {
		glb_log_error(
			    "%s must contain at least 1 field if specified", field_name);
		return -1;
	}
}
