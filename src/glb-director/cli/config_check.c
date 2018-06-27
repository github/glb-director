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
