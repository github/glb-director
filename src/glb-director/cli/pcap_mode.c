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

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_encap_pcap.h"
#include "glb_fwd_config.h"
#include "log.h"

#include <getopt.h>
#include <pcap.h>

#define ERRBUF_SIZE 1024

char config_file[256] = "";
char forwarding_table[256] = "";
char pcap_filename[256] = "";
char packet_filename[256] = "";

struct glb_processor_ctx *glb_lcore_contexts[RTE_MAX_LCORE] = {NULL};

int main(int argc, char **argv)
{
	int index, opt;

	static struct option long_options[] = {
	    {"config-file", required_argument, NULL, 'c'},
	    {"forwarding-table", required_argument, NULL, 't'},
	    {"pcap-file", required_argument, NULL, 'p'},
	    {"packet-file", required_argument, NULL, 'k'},
	    {NULL, 0, NULL, 0}};

	/* Find any command line options */

	while ((opt = getopt_long(argc, argv, ":c:t:p:", long_options, NULL)) !=
	       -1)
		switch (opt) {
		case 'c':
			strcpy(config_file, optarg);
			break;
		case 't':
			strcpy(forwarding_table, optarg);
			break;
		case 'p':
			strcpy(pcap_filename, optarg);
			break;
		case 'k':
			strcpy(packet_filename, optarg);
			break;
		case ':':
			/* missing option argument */
			glb_log_error("%s: option '-%c' requires an argument",
				      argv[0], optopt);
		case '?':
			/* invalid option */
			glb_log_error("Invalid option(s) in command");
			return 1;
		default:
			abort();
		}

	glb_log_info("Using config: %s, Using forwarding table: %s, Using pcap "
		     "file: %s, Using packet file: %s",
		     config_file, forwarding_table, pcap_filename,
		     packet_filename);

	for (index = optind; index < argc; index++)
		glb_log_error("Non-option argument %s", argv[index]);

	glb_log_info("Loading GLB configuration ...");
	g_director_config =
	    glb_director_config_load_file(config_file, forwarding_table);

	glb_log_info("Processing GLB config...");
	struct glb_fwd_config_ctx *config_ctx =
	    create_glb_fwd_config(g_director_config->forwarding_table_path);

	glb_log_info("GLB config context: %p", config_ctx);

	if (strlen(pcap_filename) > 0) {

		pcap_t *pcap;
		static char errbuf[ERRBUF_SIZE + 1];

		configuration conf[1] = {
		    {0, config_ctx} // use table 0
		};

		pcap = pcap_open_offline(pcap_filename, errbuf);

		if (pcap == NULL) {
			glb_log_error_and_exit("error: bad pcap file: %s",
					       pcap_filename);
		}

		pcap_loop(pcap, 0, (pcap_handler)glb_pcap_handler,
			  (u_char *)conf);

	} else if (strlen(packet_filename) > 0) {

		FILE *fp;
		unsigned char buffer[10240];
		int ret = 0;

		fp = fopen(packet_filename, "rb");

		ret = fread(buffer, 1, sizeof(buffer), fp);

		if (ret <= 0) {
			glb_log_error_and_exit("failed to read packet file");
		}

		pcap_packet pkt;
		pkt.data = buffer;
		pkt.len = ret;
		ret = glb_encapsulate_packet_pcap(config_ctx, &pkt, 0);

		if (ret != 0) {
			glb_log_error_and_exit("packet encap failed!");
		}

		fclose(fp);
	}

	exit(0);
}
