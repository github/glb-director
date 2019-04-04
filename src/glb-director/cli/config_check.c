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

#include "bind_classifier.h"
#include "config.h"
#include "glb_control_loop.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_fwd_config.h"
#include "glb_processor_loop.h"
#include "shared_opt.h"

#include <rte_common.h>

char config_file[256];
char forwarding_table[256];

struct glb_processor_ctx *glb_lcore_contexts[RTE_MAX_LCORE] = {NULL};
struct rte_mempool *glb_processor_msg_pool = NULL;

int main(int argc, char **argv)
{
	int ret = 0;

	/* Initialise EAL*/
	glb_log_info("Initialising EAL");
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		glb_log_error_and_exit("Could not initialise EAL (%d)", ret);
	}

	argc -= ret;
	argv += ret;

	/* Find any command line options */
	get_options(config_file, forwarding_table, argc, argv);

	glb_log_info("Loading GLB configuration");
	g_director_config =
	    glb_director_config_load_file(config_file, forwarding_table);

	glb_log_info("Processing GLB config");
	struct glb_fwd_config_ctx *config_ctx = load_glb_fwd_config();

	if (config_ctx->bind_classifier_v4 == NULL &&
	    config_ctx->bind_classifier_v6 == NULL) {
		glb_log_error_and_exit("Expecting at least one initial bind "
				       "classifier creation to succeed.");
	}

	glb_log_info("GLB config context: %p", config_ctx);

	glb_fwd_config_dump(config_ctx);

	glb_log_info("Config ok!");
	exit(0);
}
