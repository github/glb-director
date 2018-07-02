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
#include <byteswap.h>
#include <jansson.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

#define GLB_BACKEND_HEALTH_DOWN 0
#define GLB_BACKEND_HEALTH_UP 1

#define GLB_BACKEND_STATE_FILLING 0
#define GLB_BACKEND_STATE_ACTIVE 1
#define GLB_BACKEND_STATE_DRAINING_INACTIVE 2

// http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#define GLB_FAMILY_RESERVED 0
#define GLB_FAMILY_IPV4 1
#define GLB_FAMILY_IPV6 2

#define GLB_IPPROTO_UDP 17
#define GLB_IPPROTO_TCP 6

int siphash(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k);

#pragma pack(1)

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

typedef struct {
	uint32_t primary_idx;
	uint32_t secondary_idx;
} table_entry;

typedef struct {
	uint32_t index;
	uint64_t hash;
	backend_entry *backend;
} sortable_backend;

int sortable_backend_cmp(const void *a_, const void *b_)
{
	const sortable_backend *a = (sortable_backend *)a_;
	const sortable_backend *b = (sortable_backend *)b_;
	if (a->hash < b->hash)
		return -1;
	if (a->hash > b->hash)
		return 1;
	return 0;
}

void usage()
{
	glb_log_error(
	    "Usage: glb-director-cli build-config <src-json> <dst-binary>");
}

void decodehex(char *dst, const char *src, int dst_len)
{
	int i;
	unsigned int byteval;
	for (i = 0; i < dst_len; i++) {
		sscanf(&src[i * 2], "%2x", &byteval);
		dst[i] = byteval;
	}
}

int main(int argc, char *argv[])
{
	size_t i, b;

	if (argc != 4 || strcmp(argv[1], "build-config") != 0) {
		usage();
		return 1;
	}

	const char *src_json = argv[2];
	const char *dst_binary = argv[3];

	json_error_t error;
	json_t *root = json_load_file(src_json, 0, &error);
	if (root == NULL) {
		glb_log_error("Error parsing JSON config file.");
		return 1;
	}

	json_t *tables = json_object_get(root, "tables");
	if (tables == NULL) {
		glb_log_error("JSON config file must contain a 'tables' "
			      "entry listing each forwarding table.");
		return 1;
	}

	FILE *out = fopen(dst_binary, "wb");
	if (out == NULL) {
		glb_log_error("Could not open destination file for writing.");
		return 1;
	}

	fwrite("GLBD", 4, 1, out);

	bin_file_header hdr = {
	    .file_fmt_ver = 2,
	    .num_tables = json_array_size(tables),
	    .table_entries = 0x10000,
	    .max_num_backends = 0x100,
	    .max_num_binds = 0x100,
	};
	fwrite(&hdr, sizeof(bin_file_header), 1, out);

	size_t index;
	json_t *table;

	sortable_backend sortable_backends[hdr.max_num_backends];
	int num_available_backends = 0;

	json_array_foreach(tables, index, table)
	{
		/* write out the backends */
		json_t *backends = json_object_get(table, "backends");

		if (backends == NULL) {
			glb_log_error_and_exit("No backends!");
		}

		uint32_t num_backends = json_array_size(backends);
		fwrite(&num_backends, sizeof(uint32_t), 1, out);

		backend_entry out_backends[hdr.max_num_backends];
		memset(&out_backends, 0, sizeof(out_backends));

		num_available_backends = 0;

		for (i = 0; i < hdr.max_num_backends; i++) {
			backend_entry *entry = &out_backends[i];

			if (i < num_backends) {
				json_t *backend = json_array_get(backends, i);

				const char *backend_ip = json_string_value(
				    json_object_get(backend, "ip"));

				if (backend_ip == NULL) {
					glb_log_error_and_exit(
					    "Bad backend IP!");
				}

				const char *backend_state = json_string_value(
				    json_object_get(backend, "state"));

				if (backend_state == NULL) {
					glb_log_error_and_exit(
					    "Bad backend state!");
				}

				int backend_healthy = json_boolean_value(
				    json_object_get(backend, "healthy"));

				if (backend_healthy != 0 &&
				    backend_healthy != 1) {
					glb_log_error_and_exit(
					    "Bad backend health!");
				}

				int status = -1;

				// parse our IP
				if (strchr(backend_ip, ':') == NULL) {
					entry->inet_family = GLB_FAMILY_IPV4;
					status = inet_pton(AF_INET, backend_ip,
							   &entry->ip.v4);
				} else {
					entry->inet_family = GLB_FAMILY_IPV6;
					status = inet_pton(AF_INET6, backend_ip,
							   &entry->ip.v6);
				}

				if (status <= 0) {
					glb_log_error_and_exit(
					    "Malformed backend IP");
				}

				if (!strcmp(backend_state, "active")) {
					entry->state = GLB_BACKEND_STATE_ACTIVE;
				} else if (!strcmp(backend_state, "filling")) {
					entry->state =
					    GLB_BACKEND_STATE_FILLING;
				} else if (!strcmp(backend_state, "draining")) {
					entry->state =
					    GLB_BACKEND_STATE_DRAINING_INACTIVE;
				} else if (!strcmp(backend_state, "inactive")) {
					entry->state =
					    GLB_BACKEND_STATE_DRAINING_INACTIVE;
				} else {
					glb_log_error_and_exit(
					    "Bad backend state!");
				}

				entry->health = backend_healthy
						    ? GLB_BACKEND_HEALTH_UP
						    : GLB_BACKEND_HEALTH_DOWN;

				// save a copy in the sortable-backends field,
				// unless the backend is inactive
				if (strcmp(backend_state, "inactive") != 0) {
					sortable_backends
					    [num_available_backends]
						.backend = entry;
					sortable_backends
					    [num_available_backends]
						.index = i;
					num_available_backends++;
				}
			}
		}

		fwrite(&out_backends[0], sizeof(backend_entry),
		       hdr.max_num_backends, out);

		/* write out the binds */
		json_t *binds = json_object_get(table, "binds");

		if (binds == NULL) {
			glb_log_error_and_exit("No binds!");
		}

		uint32_t num_binds = json_array_size(binds);
		fwrite(&num_binds, sizeof(uint32_t), 1, out);

		for (i = 0; i < hdr.max_num_binds; i++) {
			bind_entry entry;
			memset(&entry, 0, sizeof(bind_entry));

			if (i < num_binds) {
				json_t *bind = json_array_get(binds, i);

				char *bind_ip = (char *)json_string_value(
				    json_object_get(bind, "ip"));

				if (bind_ip == NULL) {
					glb_log_error_and_exit("Bad bind IP!");
				}

				const char *bind_proto = json_string_value(
				    json_object_get(bind, "proto"));

				if (bind_proto == NULL) {
					glb_log_error_and_exit(
					    "Bad bind protocol!");
				}

				json_t *port_json = json_object_get(bind, "port");
				int bind_port_start, bind_port_end;
				if (port_json != NULL) {
					// retrieve a single port, use as start+end of range
					int bind_port = json_integer_value(port_json);
					bind_port_start = bind_port;
					bind_port_end = bind_port;
				} else {
					// retrieve a port range (must both be specified)
					bind_port_start = json_integer_value(
						json_object_get(bind, "port_start"));
					bind_port_end = json_integer_value(
						json_object_get(bind, "port_end"));
				}

				if (bind_port_start >= 0 && bind_port_start <= 65535) {
					// convert this to a range with same from/to
					entry.port_start = bind_port_start;
				} else {
					glb_log_error_and_exit(
					    "Bad port number: %d!", bind_port_start);
				}

				if (bind_port_end >= 0 && bind_port_end <= 65535) {
					// convert this to a range with same from/to
					entry.port_end = bind_port_end;
				} else {
					glb_log_error_and_exit(
					    "Bad port number: %d!", bind_port_end);
				}

				int status = -1;
				unsigned ip_bits = 0;

				int is_ipv6 = (strchr(bind_ip, ':') != NULL);

				// by default, use all bits
				if (is_ipv6)
					ip_bits = 128;
				else
					ip_bits = 32;

				// dup the bind_ip so we can mutate it
				bind_ip = strdup(bind_ip);

				char *cidr_slash = strchr(bind_ip, '/');
				if (cidr_slash != NULL) {
					// convert the '/' to a '/0' so the bind_ip is just the IP
					*cidr_slash = '\0';

					// retrieve the rest (after the '/') as an integer bit count
					unsigned req_ip_bits = atoi(cidr_slash + 1);
					if (req_ip_bits > ip_bits) {
						glb_log_error_and_exit(
					    	"Mask bit size can't be %d, it's greater than %d",
					    	req_ip_bits, ip_bits);
					}

					ip_bits = req_ip_bits;
				}

				entry.ip_bits = ip_bits;

				// parse our IP
				if (is_ipv6) {
					entry.inet_family = GLB_FAMILY_IPV6;
					status = inet_pton(AF_INET6, bind_ip,
							   &entry.ip.v6);
				} else {
					entry.inet_family = GLB_FAMILY_IPV4;
					status = inet_pton(AF_INET, bind_ip,
							   &entry.ip.v4);
				}

				if (status <= 0) {
					glb_log_error_and_exit(
					    "Malformed backend IP");
				}

				// we dup'd this above, so clean it up
				free(bind_ip);

				if (!strcmp(bind_proto, "tcp")) {
					entry.ipproto = GLB_IPPROTO_TCP;
				} else if (!strcmp(bind_proto, "udp")) {
					entry.ipproto = GLB_IPPROTO_UDP;
				} else {
					glb_log_error_and_exit("Bad protocol!");
				}
			}

			fwrite(&entry, sizeof(bind_entry), 1, out);
		}

		/* write out the key for the source IP hashing function */
		const char *hash_key_hex =
		    json_string_value(json_object_get(table, "hash_key"));

		if (hash_key_hex == NULL) {
			glb_log_error_and_exit("Bad hash key!");
		}

		if (strlen(hash_key_hex) != 32) {
			glb_log_error_and_exit("Hash key too short!");
		}

		char hash_key[16];
		decodehex(hash_key, hash_key_hex, 16);
		fwrite(hash_key, 16, 1, out);

		/* load up the table seed */
		const char *seed_hex =
		    json_string_value(json_object_get(table, "seed"));

		if (seed_hex == NULL) {
			glb_log_error_and_exit("Bad seed!");
		}

		if (strlen(seed_hex) != 32) {
			glb_log_error_and_exit("Seed key too short!");
		}

		char seed[16];
		decodehex(seed, seed_hex, 16);
		uint32_t ui;

		/* write out the pre-computed rendezvous hash entries */
		for (ui = 0; ui < hdr.table_entries; ui++) {
			table_entry entry = {0, 0};

			uint32_t i_be = htonl(ui);
			struct {
				uint64_t row_hash;
				union {
					char v6[16];
					struct {
						uint32_t v4;
						char _[12];
					};
				} ip;
			} data; // 8 byte prefix plus ipv4 or ipv6 address
			siphash((uint8_t *)&data, (uint8_t *)&i_be,
				sizeof(uint32_t), (const uint8_t *)seed);

			for (b = 0; b < num_available_backends; b++) {
				backend_entry *backend =
				    sortable_backends[b].backend;

				// work out if we're hashing an ipv4 or ipv6
				// address
				int data_len = sizeof(data);
				if (backend->inet_family == GLB_FAMILY_IPV4) {
					// only take the hash and ipv4, not the
					// blank ipv6 padding
					data_len =
					    sizeof(uint64_t) + sizeof(uint32_t);
				}

				memcpy(&data.ip, &backend->ip, sizeof(data.ip));

				uint64_t tmp_hash;
				siphash((uint8_t *)&tmp_hash, (uint8_t *)&data,
					data_len, (const uint8_t *)seed);

				// byte swap to BE
				sortable_backends[b].hash = bswap_64(tmp_hash);
			}

			qsort(sortable_backends, num_available_backends,
			      sizeof(sortable_backend), sortable_backend_cmp);

			// if the primary is draining or unhealthy and the
			// secondary is up, swap primary/secondary
			backend_entry *primary_backend =
			    &out_backends[sortable_backends[0].index];
			backend_entry *secondary_backend =
			    &out_backends[sortable_backends[1].index];
			int primary_bad =
			    (primary_backend->state ==
				 GLB_BACKEND_STATE_DRAINING_INACTIVE ||
			     primary_backend->health != GLB_BACKEND_HEALTH_UP);

			int first_idx = 0;
			if (primary_bad &&
			    secondary_backend->state == GLB_BACKEND_HEALTH_UP) {
				first_idx = 1;
			}

			entry.primary_idx = sortable_backends[first_idx].index;
			entry.secondary_idx =
			    sortable_backends[1 - first_idx].index;

			fwrite(&entry, sizeof(table_entry), 1, out);
		}
	}

	fclose(out);

	return 0;
}
