/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2020 GitHub.
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

#include <stdio.h>
#include <unistd.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <systemd/sd-daemon.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <tailcall_elf_path> <bpffs_path> <interface>\n", argv[0]);
        return 1;
    }

    const char *tailcall_elf_path = argv[1];
    const char *bpffs_path = argv[2];
    const char *iface_name = argv[3];

    /* get more resources */
    struct rlimit rl = {};
	if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        fprintf(stderr, "getrlimit RLIMIT_MEMLOCK failed\n");
		return 1;
    }

	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = rl.rlim_max;
	
	if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
        fprintf(stderr, "setrlimit RLIMIT_MEMLOCK failed\n");
		return 1;
    }

    /* make sure we have a valid interface */
    int iface_index = if_nametoindex(iface_name);
    if (iface_index == 0) {
        fprintf(stderr, "Could not find interface '%s'\n", iface_name);
        return 1;
    }

    /* load the tailcall bpf */
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
        .file = tailcall_elf_path,
    };
    struct bpf_object *shim_obj;
    int prog_fd;

    if (bpf_prog_load_xattr(&prog_load_attr, &shim_obj, &prog_fd)){
        fprintf(stderr, "Could not load '%s'\n", prog_load_attr.file);
        return 1;
    }

    /* pin the map to the */
    struct bpf_map *root_array = bpf_object__find_map_by_name(shim_obj, "root_array");

    unlink(bpffs_path);
    if (bpf_map__pin(root_array, bpffs_path) != 0) {
        fprintf(stderr, "Could not pin root array map to '%s'\n", bpffs_path);
        return 1;
    }
    
    /* bind it to the interface with XDP */
    if (bpf_set_link_xdp_fd(iface_index, prog_fd, 0) < 0) {
        fprintf(stderr, "Could not attach XDP program to interface '%s'\n", iface_name);
        return 1;
    }

    sd_notify(0, "READY=1");

    while (1) sleep(1);
}
