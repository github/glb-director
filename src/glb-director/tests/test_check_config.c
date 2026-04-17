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

/*
 * Unit tests for check_config() validation in glb_fwd_config.c.
 * Compiled with NO_DPDK to avoid DPDK dependency.
 *
 * Tests that the forwarding table validator correctly rejects tables
 * with 0 backends, 0 binds, or 0 tables.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NO_DPDK 1
#include "glb_fwd_config.h"

/* Minimal stubs to satisfy linker */
bool debug = false;

int tests_run = 0;
int tests_failed = 0;

#define ASSERT(cond, msg)                                                     \
	do {                                                                  \
		tests_run++;                                                  \
		if (!(cond)) {                                                \
			fprintf(stderr, "FAIL: %s (line %d): %s\n", msg,     \
				__LINE__, #cond);                             \
			tests_failed++;                                       \
		} else {                                                      \
			fprintf(stdout, "PASS: %s\n", msg);                   \
		}                                                             \
	} while (0)

/*
 * Build a minimal valid forwarding table in memory.
 * Caller must free the returned ctx->raw_config and ctx.
 */
static struct glb_fwd_config_ctx *
build_config(uint32_t num_tables, uint32_t *num_backends_per_table,
	     uint32_t *num_binds_per_table)
{
	uint64_t size = sizeof(struct glb_fwd_config_content) +
			(sizeof(struct glb_fwd_config_content_table) *
			 num_tables);

	struct glb_fwd_config_content *content = calloc(1, size);
	if (content == NULL)
		return NULL;

	content->magic_word = GLB_FMT_MAGIC_WORD;
	content->version = GLB_FMT_VERSION;
	content->num_tables = num_tables;
	content->table_entries = GLB_FMT_TABLE_ENTRIES;
	content->max_num_backends = GLB_FMT_MAX_NUM_BACKENDS;
	content->max_num_binds = GLB_FMT_MAX_NUM_BINDS;

	for (uint32_t i = 0; i < num_tables; i++) {
		struct glb_fwd_config_content_table *table = &content->tables[i];
		table->num_backends = num_backends_per_table[i];
		table->num_binds = num_binds_per_table[i];

		/* Fill in minimal valid backend/bind entries */
		for (uint32_t b = 0; b < table->num_backends; b++) {
			table->backends[b].family = FAMILY_IPV4;
			table->backends[b].ipv4_addr = htonl(0x01020300 + b);
			table->backends[b].state = GLB_BACKEND_STATE_ACTIVE;
			table->backends[b].healthy = GLB_BACKEND_HEALTH_UP;
		}
		for (uint32_t b = 0; b < table->num_binds; b++) {
			table->binds[b].family = FAMILY_IPV4;
			table->binds[b].ipv4_addr = htonl(0x01010100 + b);
			table->binds[b].port_start = 80;
			table->binds[b].port_end = 80;
			table->binds[b].proto = SUPPORTED_PROTOS_TCP;
		}
	}

	struct glb_fwd_config_ctx *ctx =
	    calloc(1, sizeof(struct glb_fwd_config_ctx));
	if (ctx == NULL) {
		free(content);
		return NULL;
	}

	ctx->raw_config = content;
	ctx->raw_config_size = size;
	ctx->_ref_count = 1;

	return ctx;
}

static void free_config(struct glb_fwd_config_ctx *ctx)
{
	if (ctx != NULL) {
		free(ctx->raw_config);
		free(ctx);
	}
}

static void test_valid_config(void)
{
	uint32_t backends[] = {3};
	uint32_t binds[] = {2};
	struct glb_fwd_config_ctx *ctx = build_config(1, backends, binds);
	ASSERT(ctx != NULL, "build valid config");
	ASSERT(check_config(ctx) == 0, "valid config passes check_config");
	free_config(ctx);
}

static void test_zero_tables(void)
{
	struct glb_fwd_config_ctx *ctx = build_config(0, NULL, NULL);
	ASSERT(ctx != NULL, "build 0-tables config");
	ASSERT(check_config(ctx) != 0,
	       "config with 0 tables is rejected by check_config");
	free_config(ctx);
}

static void test_zero_backends(void)
{
	uint32_t backends[] = {0};
	uint32_t binds[] = {2};
	struct glb_fwd_config_ctx *ctx = build_config(1, backends, binds);
	ASSERT(ctx != NULL, "build 0-backends config");
	ASSERT(check_config(ctx) != 0,
	       "config with 0 backends is rejected by check_config");
	free_config(ctx);
}

static void test_zero_binds(void)
{
	uint32_t backends[] = {3};
	uint32_t binds[] = {0};
	struct glb_fwd_config_ctx *ctx = build_config(1, backends, binds);
	ASSERT(ctx != NULL, "build 0-binds config");
	ASSERT(check_config(ctx) != 0,
	       "config with 0 binds is rejected by check_config");
	free_config(ctx);
}

static void test_zero_backends_second_table(void)
{
	uint32_t backends[] = {3, 0};
	uint32_t binds[] = {2, 2};
	struct glb_fwd_config_ctx *ctx = build_config(2, backends, binds);
	ASSERT(ctx != NULL, "build config with 0 backends in second table");
	ASSERT(check_config(ctx) != 0,
	       "config with 0 backends in second table is rejected");
	free_config(ctx);
}

static void test_zero_binds_second_table(void)
{
	uint32_t backends[] = {3, 3};
	uint32_t binds[] = {2, 0};
	struct glb_fwd_config_ctx *ctx = build_config(2, backends, binds);
	ASSERT(ctx != NULL, "build config with 0 binds in second table");
	ASSERT(check_config(ctx) != 0,
	       "config with 0 binds in second table is rejected");
	free_config(ctx);
}

static void test_multiple_valid_tables(void)
{
	uint32_t backends[] = {3, 4};
	uint32_t binds[] = {2, 3};
	struct glb_fwd_config_ctx *ctx = build_config(2, backends, binds);
	ASSERT(ctx != NULL, "build multi-table valid config");
	ASSERT(check_config(ctx) == 0,
	       "valid multi-table config passes check_config");
	free_config(ctx);
}

int main(void)
{
	test_valid_config();
	test_zero_tables();
	test_zero_backends();
	test_zero_binds();
	test_zero_backends_second_table();
	test_zero_binds_second_table();
	test_multiple_valid_tables();

	printf("\n%d/%d tests passed\n", tests_run - tests_failed, tests_run);
	return tests_failed > 0 ? 1 : 0;
}
