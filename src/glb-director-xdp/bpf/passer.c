#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

SEC("prog")
int xdp_passer(struct xdp_md *ctx) {
    return XDP_PASS;
}
