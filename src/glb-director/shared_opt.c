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

#include "shared_opt.h"
#include <getopt.h>

/* parses --config-file, --forwarding-table, and --debug cli options */

void get_options(char *config_file, char *forwarding_table, int argc,
		 char *const *argv)
{

	int opt_index, opt;
	debug = false;

	static struct option long_options[] = {
	    {"config-file", required_argument, NULL, 'c'},
	    {"forwarding-table", required_argument, NULL, 't'},
	    {"debug", no_argument, NULL, 'v'},
	    {NULL, 0, NULL, 0}};

	while ((opt = getopt_long(argc, argv, ":c:t:v", long_options, NULL)) !=
	       -1)
		switch (opt) {
		case 'c':
			strcpy(config_file, optarg);
			break;
		case 't':
			strcpy(forwarding_table, optarg);
			break;
		case 'v':
			debug = true;
			break;
		case ':':
			/* missing option argument */
			glb_log_error("%s: option '-%c' requires an argument",
				      argv[0], optopt);
			GLB_FALL_THROUGH;
		case '?':
			/* invalid option */
			glb_log_error("Invalid option(s) in command");
			GLB_FALL_THROUGH;
		default:
			abort();
		}

	glb_log_info("Using config: %s, Using forwarding table: %s,",
		     config_file, forwarding_table);

	for (opt_index = optind; opt_index < argc; opt_index++)
		glb_log_error("Non-option argument %s", argv[opt_index]);
};
