#ifndef _GLB_ENCAP_LIMITS_H
#define _GLB_ENCAP_LIMITS_H

#include <stdint.h>

#define	BPF_MAX_BINDS	4096

uint32_t bpf_max_binds()
{
	return BPF_MAX_BINDS;
}
#endif
