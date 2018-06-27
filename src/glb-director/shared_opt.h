#ifndef SHARED_OPT
#define SHARED_OPT

#include "log.h"
#include <getopt.h>

extern bool debug;

/* parses --config-file, --forwarding-table, and --debug cli options */

void get_options(char *config_file, char *forwarding_table, int argc,
		 char *const *argv);

#endif
