/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2019, Cloudflare. All rights reserved.
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

#ifndef XDPCAP_HOOK_H
#define XDPCAP_HOOK_H

#include <linux/bpf.h>

/**
 * Create a bpf map suitable for use as an xdpcap hook point.
 *
 * For example:
 *   struct bpf_map_def xdpcap_hook = XDPCAP_HOOK();
 */
#define XDPCAP_HOOK() { \
	.type = BPF_MAP_TYPE_PROG_ARRAY, \
	.key_size = sizeof(int), \
	.value_size = sizeof(int), \
	.max_entries = 5, \
}

/**
 * Return action, exposing the action and input packet to xdpcap hook.
 *
 *   return xdpcap_exit(ctx, &hook, XDP_PASS)
 *
 * is equivalent to:
 *
 *   return XDP_PASS;
 */
__attribute__((__always_inline__))
static inline enum xdp_action xdpcap_exit(struct xdp_md *ctx, void *hook_map, enum xdp_action action) {
	// tail_call
	// Some headers define tail_call (Cilium), others bpf_tail_call (kernel self tests). Use the helper ID directly
	((int (*)(struct xdp_md *, void *, int))12)(ctx, hook_map, action);
	return action;
}

#endif /* XDPCAP_HOOK_H */
