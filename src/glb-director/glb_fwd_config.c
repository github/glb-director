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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_log.h>

#include "bind_classifier.h"
#include "config.h"
#include "glb_fwd_config.h"
#include "log.h"

struct glb_fwd_config_ctx *create_glb_fwd_config(const char *config_file)
{
	char *source_data;
	int fd;
	struct stat fs;
	int config_status = 0;

	fd = open(config_file, O_RDONLY);
	if (fstat(fd, &fs) != 0) {
		glb_log_error("glb-config loading failed: could not stat fd");
		goto fail;
	}
	glb_log_info("glb-config loading with size %lu", fs.st_size);

	source_data = mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (source_data == MAP_FAILED) {
		glb_log_error("glb-config loading failed: could not mmap file");
		goto fail;
	}

	struct glb_fwd_config_ctx *ctx =
	    malloc(sizeof(struct glb_fwd_config_ctx));
	if (ctx == NULL) {
		glb_log_error(
		    "glb-config loading failed: could not allocate context "
		    "struct");
		munmap(source_data, fs.st_size);
		goto cleanup;
		goto fail;
	}

	rte_atomic32_set(&ctx->_ref_count, 0);

	ctx->raw_config_size = fs.st_size;
	ctx->raw_config = malloc(ctx->raw_config_size);
	if (ctx->raw_config == NULL) {
		glb_log_error(
		    "glb-config loading failed: could not allocate config "
		    "copy");
		munmap(source_data, fs.st_size);
		goto cleanup;
		goto fail;
	}

	memcpy(ctx->raw_config, source_data, ctx->raw_config_size);
	munmap(source_data, fs.st_size);
	close(fd);

	glb_log_info("glb-config raw config loaded, validating...");

	config_status = check_config(ctx);
	if (config_status != 0) {
		goto cleanup;
		goto fail;
	}

#ifndef PCAP_MODE
	/* dont create bind classifiers in pcap mode, requires dpdk*/
	glb_log_info(
	    "glb-config raw config looks good, generating classifiers...");
	ctx->bind_classifier_v4 = NULL;
	ctx->bind_classifier_v6 = NULL;
	int ret =
	    create_bind_classifier(ctx->raw_config, &ctx->bind_classifier_v4,
				   &ctx->bind_classifier_v6);
	if (ret != 0) {
		glb_log_error(
		    "glb-config loading failed: could not create a bind "
		    "classifier");
		goto cleanup;
		goto fail;
	}
#endif

	goto done;

cleanup:
	free(ctx);

fail:
	close(fd);
	exit(1);

done:
	return glb_fwd_config_ctx_incref(ctx);
}

struct glb_fwd_config_ctx *
glb_fwd_config_ctx_incref(struct glb_fwd_config_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;

	rte_atomic32_inc(&ctx->_ref_count);

	return ctx;
}

void glb_fwd_config_ctx_decref(struct glb_fwd_config_ctx *ctx)
{
	if (ctx == NULL)
		return;

	if (rte_atomic32_dec_and_test(&ctx->_ref_count)) {
// dont deal with bind classifiers in pcap mode, requires dpdk
#ifndef PCAP_MODE
		// no more refs, we can free this!
		if (ctx->bind_classifier_v4 != NULL)
			rte_acl_free(ctx->bind_classifier_v4);
		if (ctx->bind_classifier_v6 != NULL)
			rte_acl_free(ctx->bind_classifier_v6);
#endif

		free(ctx->raw_config);
		free(ctx);
	}
}

void glb_fwd_config_dump(struct glb_fwd_config_ctx *ctx)
{
	uint32_t i, x, y;

	glb_log_info("version: %d", ctx->raw_config->version);

	for (i = 0; i < ctx->raw_config->num_tables; i++) {
		struct glb_fwd_config_content_table *table =
		    &ctx->raw_config->tables[i];

		for (x = 0; x < table->num_binds; x++) {
			struct glb_fwd_config_content_table_bind *bind =
			    &table->binds[x];

			if (bind->family == FAMILY_IPV4) {
				char ip[INET_ADDRSTRLEN];

				inet_ntop(AF_INET, &(bind->ipv4_addr), ip,
					  INET_ADDRSTRLEN);

				glb_log_info("bind: %s:[%d-%d] (%d)", ip,
						bind->port_start, bind->port_end,
						bind->proto);
			} else if (bind->family == FAMILY_IPV6) {
				char ip[INET6_ADDRSTRLEN];

				inet_ntop(AF_INET6, &(bind->ipv6_addr), ip,
					  INET6_ADDRSTRLEN);

				glb_log_info("bind: %s:[%d-%d] (%d)", ip,
					bind->port_start, bind->port_end,
					bind->proto);
			}

			for (y = 0; y < table->num_backends; y++) {
				struct glb_fwd_config_content_table_backend
				    *backend = &table->backends[y];

				if (backend->family == FAMILY_IPV4) {
					char ip[INET_ADDRSTRLEN];

					inet_ntop(AF_INET,
						  &(backend->ipv4_addr), ip,
						  INET_ADDRSTRLEN);

					glb_log_info(
					    "** backend: %s (state: %d / "
					    "health: %d)",
					    ip, backend->state,
					    backend->healthy);
				} else if (backend->family == FAMILY_IPV6) {
					char ip[INET6_ADDRSTRLEN];

					inet_ntop(AF_INET6,
						  &(backend->ipv6_addr), ip,
						  INET6_ADDRSTRLEN);

					glb_log_info(
					    "** backend: %s (state: %d / "
					    "health: %d)",
					    ip, backend->state,
					    backend->healthy);
				}
			}
		}
	}
}

int check_config(struct glb_fwd_config_ctx *ctx)
{
	uint32_t i, x, y;

	if (ctx->raw_config->magic_word != GLB_FMT_MAGIC_WORD) {
		glb_log_error("glb-config loading failed: invalid magic word");
		return 1;
	}

	if (ctx->raw_config->version != GLB_FMT_VERSION) {
		glb_log_error(
		    "glb-config loading failed: invalid version (expected "
		    "%d, got %d)",
		    GLB_FMT_VERSION, ctx->raw_config->version);
		return 1;
	}

	if (ctx->raw_config->table_entries != GLB_FMT_TABLE_ENTRIES) {
		glb_log_error(
		    "glb-config loading failed: invalid number of table "
		    "entries (expected %d, got %d)",
		    GLB_FMT_TABLE_ENTRIES, ctx->raw_config->table_entries);
		return 1;
	}

	if (ctx->raw_config->max_num_backends != GLB_FMT_MAX_NUM_BACKENDS) {
		glb_log_error(
		    "glb-config loading failed: invalid number of backends "
		    "(expected %d, got %d)",
		    GLB_FMT_MAX_NUM_BACKENDS,
		    ctx->raw_config->max_num_backends);
		return 1;
	}

	uint64_t expected_size = sizeof(struct glb_fwd_config_content) +
				 (sizeof(struct glb_fwd_config_content_table) *
				  ctx->raw_config->num_tables);
	if (expected_size != ctx->raw_config_size) {
		glb_log_error(
		    "glb-config loading failed: config file has wrong size "
		    "(expected %lu, got %lu)",
		    expected_size, ctx->raw_config_size);
		return 1;
	}

	for (i = 0; i < ctx->raw_config->num_tables; i++) {
		struct glb_fwd_config_content_table *table =
		    &ctx->raw_config->tables[i];

		if (table->num_binds > GLB_FMT_MAX_NUM_BINDS) {
			glb_log_error(
			    "glb-config loading failed: too many binds: %d",
			    table->num_binds);
			return 1;
		}

		if (table->num_backends > GLB_FMT_MAX_NUM_BACKENDS) {
			glb_log_error(
			    "glb-config loading failed: too many backends: "
			    "%d",
			    table->num_backends);
			return 1;
		}

		for (x = 0; x < table->num_binds; x++) {
			struct glb_fwd_config_content_table_bind *bind =
			    &table->binds[x];

			if (bind->family != FAMILY_IPV4 &&
			    bind->family != FAMILY_IPV6) {
				glb_log_error(
				    "glb-config loading failed: bind not "
				    "IPv4 or IPv6: %d",
				    bind->family);
				return 1;
			}

			int sup_proto = 0;
			sup_proto = supported_proto(bind->proto);
			if (sup_proto != 0) {
				glb_log_error(
				    "glb-config loading failed: unsupprted "
				    "protocol: %d",
				    bind->proto);
				return 1;
			}

			for (y = 0; y < table->num_backends; y++) {
				struct glb_fwd_config_content_table_backend
				    *backend = &table->backends[y];

				if (backend->family != FAMILY_IPV4 &&
				    backend->family != FAMILY_IPV6) {
					glb_log_error(
					    "glb-config loading failed: "
					    "backend not IPv4 or IPv6: "
					    "%d",
					    backend->family);
					return 1;
				}
			}
		}
	}

	return 0;
}

int supported_proto(int proto_num)
{
	switch (proto_num) {
	case SUPPORTED_PROTOS_ICMP:
		return 0;
	case SUPPORTED_PROTOS_TCP:
		return 0;
	case SUPPORTED_PROTOS_UDP:
		return 0;
	default:
		return 1;
	}
}
