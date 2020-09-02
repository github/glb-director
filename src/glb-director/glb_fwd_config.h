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

#define GLB_FMT_MAGIC_WORD 0x44424c47 // 'GLBD'
#define GLB_FMT_VERSION 2
#define GLB_FMT_TABLE_ENTRIES 0x10000
#define GLB_FMT_TABLE_HASHMASK 0xffff
#define GLB_FMT_MAX_NUM_BACKENDS 0x100
#define GLB_FMT_MAX_NUM_BINDS 0x100

#define GLB_FMT_SECURE_KEY_BYTES 16

#define FAMILY_IPV4 1
#define FAMILY_IPV6 2

struct glb_fwd_config_content_table_backend {
	uint32_t family;
	union {
		uint32_t ipv4_addr;
		uint8_t ipv6_addr[16];
	};
	uint16_t state;
	uint16_t healthy;
} __attribute__((__packed__));

struct glb_fwd_config_content_table_bind {
	uint32_t family;
	union {
		uint32_t ipv4_addr;
		uint8_t ipv6_addr[16];
	};
	uint16_t ip_bits;

	uint16_t port_start;
	uint16_t port_end;
	uint8_t proto;
	uint8_t reserved;
} __attribute__((__packed__));

struct glb_fwd_config_content_table_entry {
	uint32_t primary;
	uint32_t secondary;
} __attribute__((__packed__));

struct glb_fwd_config_content_table {
	uint32_t num_backends;
	struct glb_fwd_config_content_table_backend
	    backends[GLB_FMT_MAX_NUM_BACKENDS];

	uint32_t num_binds;
	struct glb_fwd_config_content_table_bind binds[GLB_FMT_MAX_NUM_BINDS];

	uint8_t secure_key[GLB_FMT_SECURE_KEY_BYTES];
	struct glb_fwd_config_content_table_entry
	    entries[GLB_FMT_TABLE_ENTRIES];
} __attribute__((__packed__));

struct glb_fwd_config_content {
	uint32_t magic_word;
	uint32_t version;
	uint32_t num_tables;
	uint32_t table_entries;
	uint32_t max_num_backends;
	uint32_t max_num_binds;

	struct glb_fwd_config_content_table tables[];
} __attribute__((__packed__));

struct glb_fwd_config_ctx {
	struct glb_fwd_config_content *raw_config;
	uint64_t raw_config_size;

#ifndef NO_DPDK
	struct rte_acl_ctx *bind_classifier_v4;
	struct rte_acl_ctx *bind_classifier_v6;

	rte_atomic32_t _ref_count;
#else
	uint32_t _ref_count;
#endif
};

struct glb_fwd_config_ctx *create_glb_fwd_config(const char *config_file);
struct glb_fwd_config_ctx *
glb_fwd_config_ctx_incref(struct glb_fwd_config_ctx *ctx);
void glb_fwd_config_ctx_decref(struct glb_fwd_config_ctx *ctx);
void glb_fwd_config_dump(struct glb_fwd_config_ctx *ctx);
int check_config(struct glb_fwd_config_ctx *ctx);
int supported_proto(int proto_num);
