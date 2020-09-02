/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019 Roblox Corporation.
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
#ifndef __GLB_CONFIG_TYPES_H__

#define __GLB_CONFIG_TYPES_H__

typedef enum {FALSE, TRUE} boolean;

typedef struct {
	uint32_t file_fmt_ver;
	uint32_t num_tables;
	uint32_t table_entries;
	uint32_t max_num_backends;
	uint32_t max_num_binds;
} bin_file_header;

typedef struct {
	uint32_t inet_family;

	union {
		char v6[16];
		struct {
			uint32_t v4;
			char reserved[12];
		};
	} ip;

	uint16_t state;
	uint16_t health;
} backend_entry;

typedef struct {
	uint32_t inet_family;

	union {
		char v6[16];
		struct {
			uint32_t v4;
			char _[12];
		};
	} ip;

	uint16_t ip_bits;

	uint16_t port_start;
	uint16_t port_end;
	uint8_t ipproto;
	uint8_t reserved;
} bind_entry;

struct table_entry_ {
	uint32_t primary_idx;
	uint32_t secondary_idx;
} __attribute__((__packed__));
typedef struct table_entry_ table_entry;


#endif /* __GLB_CONFIG_TYPES_H__ */
/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
