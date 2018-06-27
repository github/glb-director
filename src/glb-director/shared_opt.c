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
		case '?':
			/* invalid option */
			glb_log_error("Invalid option(s) in command");
		default:
			abort();
		}

	glb_log_info("Using config: %s, Using forwarding table: %s,",
		     config_file, forwarding_table);

	for (opt_index = optind; opt_index < argc; opt_index++)
		glb_log_error("Non-option argument %s", argv[opt_index]);
};
