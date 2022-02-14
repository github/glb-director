#ifndef _GLB_ENCAP_LIMITS_H
#define _GLB_ENCAP_LIMITS_H

#include <stdint.h>

/*
 * The GLB forwarding table allows for bind ranges which has a port-range-start and port-range-end.
 * Since looping through those in XDP isn't possible (since looping structures aren't yet allowed in BPF), these ranges are expanded to individual port binds within the helper cgo.
 * The limit below defines the maximum supported number of binds in the map after the bind ranges have been expanded.
 */
#define BPF_MAX_BINDS 4096

// Macro access function for cgo
uint32_t bpf_max_binds()
{
	return BPF_MAX_BINDS;
}
#endif
