/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019 Roblox Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *	 list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *	 contributors may be used to endorse or promote products derived from
 *	 this software without specific prior written permission.
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <netdb.h>
#include "glb-includes/glb_common_includes.h"
#include "../glb_consts.h"
#include "glb_config_types.h"
#include "glb-ftctl.h"

ftctl_config_t cli_config;

/*
 * This file contains code for a utility to dump the contents of a binary
 * forwarding table (BFT) used by GLB-director.
 * 
 * In the future, the displayed items can be displayed in more fancy ways.
 * This is just a start.
 */

/*
 * glb_ftctl_usage()
 *
 */
void glb_ftctl_usage()
{
	printf("Usage: glb-director-ftctl <options> <ft.bin>\n"				\
		   " Options: \n"												\
		   "   -d, --detail			Print everything other than table-entries\n" \
		   "   -n, --table-num <N>	Print forwarding-table entries only for " \
		   "this table (numbering starts with 0)\n"												\
		   "   -v, --verbose		Print everything\n"					\
		   "\n"															\
		   "   Default behavior:	Print only the common info\n\n"		\
		   );
}

/*
 * fread_ret_check()
 *
 * Function to check if the returned count by a call to fread() can be 
 * considered proper.
 *
 */

static int
glb_fread_ret_check(size_t ret, size_t num_expect_to_read,
					boolean check_num_expect)
{
	/* Improper read */
	if (check_num_expect) {
		if (ret < num_expect_to_read) {
			return 0;
		}
	} else {
		if (!ret) {
			return 0;
		}
	}

	/* Proper read */
	return 1;
}

/*
 * glb_ip_addr_to_str()
 * 
 * Converts an IP address (v4 or v6) to a corresponding string representation,
 * based on the inet_family provided.
 *
 * Caller's responsibility to ensure that dst can hold an appropriate length of
 * characters.
 */

static boolean
glb_ip_addr_to_str(uint32_t glb_inet_family, const void *src, char *dst)
{
	socklen_t size = 0;
	uint32_t inet_family = inet_family;
	
	if (glb_inet_family == GLB_FAMILY_IPV4) {
		inet_family = AF_INET;
		size = INET_ADDRSTRLEN;
	} else if (glb_inet_family == GLB_FAMILY_IPV6) {
		inet_family = AF_INET6;
		size = INET6_ADDRSTRLEN;
	} else {
		return FALSE;
	}
	
	inet_ntop(inet_family, src, dst, size);
	return TRUE;
}

/*
 * glb_read_per_table_fields()
 *
 * Prints ther per-table fields.
 * Assumption is that the read-offet for "in" is at the appropriate offset for
 * a table that is sought to be read.
 *
 */
static int
glb_read_per_table_fields(FILE *in, const bin_file_header *bfh,
						  uint32_t table_num)
{
	uint32_t i = 0;
	uint32_t num_backends;
	
	backend_entry *backendp;
	bind_entry *bindp;
	table_entry *tablep;

	uint32_t num_binds;
	char hash_key[16];
	char ip[INET_ADDRSTRLEN];
	size_t ret;

	/* Read the # of backends that this BFT file knows about */
	ret = fread(&num_backends, sizeof(uint32_t), 1, in);
	if (!glb_fread_ret_check(ret, 1, TRUE)) {
		return -1;
	}
	
	/* Deal with backends : read each backend & display same */
	backendp = (backend_entry *) malloc(bfh->max_num_backends * \
									   sizeof(backend_entry));
	if (!backendp) {
		return -1;
	}	
	ret = fread(backendp, sizeof(backend_entry), bfh->max_num_backends, in);
	if (!glb_fread_ret_check(ret, bfh->max_num_backends, FALSE)) {
		return -1;
	}

	if (FTCTL_CHECK_IF_ENTRIES_ALL_OR_THIS(cli_config.table_num,
										   table_num)) {
		printf("\n\n*** Table #: %d ***", table_num);
		printf("\n\nBackends:");
		for (i = 0; i < num_backends; i++) {
			if (glb_ip_addr_to_str(backendp[i].inet_family, &backendp[i].ip,
								   ip)) {
				printf("\n%u: \t%s \t: %s, \t%s, \t%s",
					   i, ip, glb_addr_family_names[backendp[i].inet_family],
					   glb_state_names[backendp[i].state],
					   glb_backend_health_status[backendp[i].health]);
			}
		}
	}


	
	/* Number of binds */
	ret = fread(&num_binds, sizeof(uint32_t), 1, in);
	if (!glb_fread_ret_check(ret, 1, TRUE)) {
		return -1;
	}

	/* Deal with binds: read & display each bind entry */
	bindp = (bind_entry *)malloc(bfh->max_num_binds * sizeof(bind_entry));
	if (!bindp) {
		return -1;
	}
	
	ret = fread(bindp, sizeof(bind_entry), bfh->max_num_binds, in);
	if (!glb_fread_ret_check(ret, bfh->max_num_binds, TRUE)) {
		free(bindp);
		return -1;
	}

	if (FTCTL_CHECK_IF_ENTRIES_ALL_OR_THIS(cli_config.table_num,
										   table_num)) {
		printf("\n\nBinds:");

		for (i = 0; i < num_binds; i++) {
			struct protoent *proto;
			
			if (glb_ip_addr_to_str(bindp[i].inet_family, &bindp[i].ip, ip)) {
				proto = getprotobynumber(bindp[i].ipproto);
				printf("\n%40s, %s, Port: %u-%u",
					   ip,
					   (proto ? proto->p_name : "Unknown"),
					   bindp[i].port_start,
					   bindp[i].port_end);
			}
		}
	}

	free(bindp);

	/* Hash key */
	ret = fread(hash_key, 16, 1, in);
	if (!glb_fread_ret_check(ret, 1, TRUE)) {
		return -1;
	}

	if (FTCTL_CHECK_IF_ENTRIES_ALL_OR_THIS(cli_config.table_num,
										   table_num)) {
		printf("\n\nHash-key: 0x");
		for (i = 0; i < 16; i++) {
			printf("%x", (unsigned char)hash_key[i]);
		}
		printf("\n");
	}
	/* Deal with the rendezvous hash-table */
	tablep = (table_entry *)malloc(sizeof(table_entry));
	if (!tablep) {
		return -1;
	}

	for (i = 0; i < bfh->table_entries; i++) {
		ret = fread(&tablep->primary_idx, sizeof(uint32_t), 1, in);
		if (!glb_fread_ret_check(ret, 1, TRUE)) {
			free(tablep);
			return -1;
		}
		ret = fread(&tablep->secondary_idx, sizeof(uint32_t), 1, in);
		if (!glb_fread_ret_check(ret, 1, TRUE)) {
			free(tablep);
			return -1;
		}
		if (cli_config.verbose &&										\
			FTCTL_CHECK_IF_ENTRIES_ALL_OR_THIS(cli_config.table_num,
											   table_num)) {
			if (i ==0) {
				printf("\n\nForwarding table:");
			}
			printf("\nEntry: 0x%x", i);
			printf(" %4d", tablep->primary_idx);
			printf(" %4d", tablep->secondary_idx);
		}
	}
	free(tablep);
	free(backendp);
	return 0;
}

/*
 * glb_print_bin_file_header()
 *
 * Print the contents of the file header
 */ 
static void
glb_print_bin_file_header(bin_file_header *bfh)
{
	printf("\nFile header");
	printf("\n\tVersion: %u", bfh->file_fmt_ver);
	printf("\n\tNumber of tables: %u", bfh->num_tables);
	printf("\n\tTable entries: %u", bfh->table_entries);
	printf("\n\tMax. # of backends: %u", bfh->max_num_backends);
	printf("\n\tMax. # of binds: %u\n", bfh->max_num_binds);
}

static struct option longopts[] = {
	{ "detail", no_argument, NULL, 'd' },
	{ "num-table", required_argument, NULL, 'n' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help",		 no_argument,		NULL, 'h' },
	{ NULL,			 0,					NULL,  0  }
};

/*
 * Parse the args & determine validity
 *
 *	 -d, --detail			 Print everything other than table-entries
 *	 -n, --num-table <N>	 Print entries only from table-number specified
 *	 -v, --verbose			 Print everything
 *	 -h, --help				 Help
 *
 *	 Default behavior:	  Print only the table-names, VIPs, backends
 */
static int
parse_args(int argc, char **argv, const char **src_binary)
{
	int c;

	cli_config.table_num = FTCTL_TABLE_ENTRIES_ALL;

	while ((c = getopt_long(argc, argv, "n:dvh?", longopts,
							NULL)) != -1) {
		switch(c) {
		case 'd':
			cli_config.detailed = TRUE;
			break;

		case 'n':
			cli_config.table_num = atoi(optarg);
			break;

		case 'v':
			cli_config.verbose = TRUE;
			break;

		case 'h':
		case '?':
		default:
			return(-1);
		}
	}
	
	if (optind == argc) {
		return(-1);
	}
	if (cli_config.detailed && cli_config.verbose) {
		printf("Mutually exclusive options configured together\n");
		return(-1);
	}
	*src_binary = argv[optind];
	return(0);
}


int
main(int argc, char **argv)
{
	char buffer[256];
	uint32_t i = 0;
	bin_file_header *bfh;
	size_t ret;
	const char *src_binary;
	
	if (parse_args(argc, argv, &src_binary)) {
		glb_ftctl_usage();
		return -1;
	}
	

	/* Open the binary forwarding table file for reading */
    FILE *in = fopen(src_binary, "rb");
    if (in == NULL) {
        printf("Could not open forwarding table file for reading: %s",
			   src_binary);
        return -1;
    }
    
    /* Read magic word */
    ret = fread(buffer, 4, 1, in);
    if (!glb_fread_ret_check(ret, 1, TRUE)) {
        return -1;
    }
    
    /* Read file header */
    bfh = malloc(sizeof(bin_file_header));
    if (!bfh) {
        return -1;
    }   
    ret = fread(bfh, sizeof(bin_file_header), 1, in);
    if (!glb_fread_ret_check(ret, 1, TRUE)) {
        return -1;
    }

    /* Print the header */
    glb_print_bin_file_header(bfh);

    printf("\nNumber of tables: %u", bfh->num_tables);

	if (cli_config.detailed || cli_config.verbose) {
		/* For each table, read the fields & display same */
		for (i = 0; i < bfh->num_tables; i++) {
			ret = glb_read_per_table_fields(in, bfh, i);
		}
	}
    
    free(bfh);
	printf("\n");
    return(ret);
}
/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
