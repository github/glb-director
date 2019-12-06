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

#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "config.h"
#include "glb_director_config.h"
#include "glb_encap.h"
#include "glb_encap_pcap.h"
#include "glb_fwd_config.h"
#include "shared_opt.h"
#include "util.h"
#include "strlcpy.h"

#define DEFAULT_IFACE "lo"
#define MAX_BUFFER 10240
#define DEFAULT_SRC_IP_PREFIX "127.1"

char config_file[256] = "";
char forwarding_table[256] = "";
struct ifreq iface_opts;
int socket_fd = 0;
struct glb_fwd_config_ctx *config_ctx;

struct glb_fwd_config_ctx *load_glb_fwd_config(void)
{
	return create_glb_fwd_config(g_director_config->forwarding_table_path);
}

void signal_handler(int signum)
{
	/* handle reload request */
	if (signum == SIGUSR1) {
		glb_log_info("SIGUSER1 received, requesting state reload");

		struct glb_fwd_config_ctx *old_config_ctx = config_ctx;

		glb_log_info("Processing GLB config");
		config_ctx = load_glb_fwd_config();

		glb_fwd_config_ctx_decref(old_config_ctx);

		glb_log_info("GLB config context: %p", config_ctx);
		glb_fwd_config_dump(config_ctx);
	}

	if (signum == SIGINT || signum == SIGTERM) {
		memset(&iface_opts, 0, sizeof(iface_opts));
		strlcpy(iface_opts.ifr_name, DEFAULT_IFACE, IFNAMSIZ);

		if (ioctl(socket_fd, SIOCGIFFLAGS, &iface_opts) == -1) {
			close(socket_fd);
			glb_log_error_and_exit("failed to SIOCGIFFLAGS");
		}

		iface_opts.ifr_flags |= IFF_UP | IFF_RUNNING;

		iface_opts.ifr_flags &= ~IFF_PROMISC;
		if (ioctl(socket_fd, SIOCSIFFLAGS, &iface_opts) == -1) {
			glb_log_error_and_exit(
			    "cant restore interface settings");
		}

		exit(0);
	}
}

int main(int argc, char **argv)
{
	int socket_opts = 0;
	unsigned char pkt_buf[MAX_BUFFER];
	char src_ip[INET_ADDRSTRLEN];
	ssize_t bytes_read;

	/* Associate signal_hanlder function with USR signals */
	signal(SIGUSR1, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Find any command line options */
	get_options(config_file, forwarding_table, argc, argv);

	glb_log_info("Loading GLB configuration");

	g_director_config =
	    glb_director_config_load_file(config_file, forwarding_table);

	glb_log_info("Processing GLB config");
	config_ctx = load_glb_fwd_config();

	glb_log_info("GLB config context: %p", config_ctx);
	glb_fwd_config_dump(config_ctx);

	if ((socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_IPv4))) ==
	    -1) {
		glb_log_error_and_exit("failed to open socket");
	}

	memset(&iface_opts, 0, sizeof(iface_opts));
	strlcpy(iface_opts.ifr_name, DEFAULT_IFACE, IFNAMSIZ);

	if (ioctl(socket_fd, SIOCGIFFLAGS, &iface_opts) == -1) {
		close(socket_fd);
		glb_log_error_and_exit("failed to SIOCGIFFLAGS");
	}

	iface_opts.ifr_flags |= IFF_UP | IFF_RUNNING;

	// set promiscuous mode
	iface_opts.ifr_flags |= IFF_PROMISC;

	if (ioctl(socket_fd, SIOCSIFFLAGS, &iface_opts) == -1) {
		close(socket_fd);
		glb_log_error("failed to switch to promiscuous mode");
		goto done;
	}

	// set reuseaddr
	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &socket_opts,
		       sizeof(socket_opts)) == -1) {
		close(socket_fd);
		glb_log_error("failed to switch to promiscuous mode");
		goto done;
	}

	// bind to device
	if (setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, DEFAULT_IFACE,
		       IFNAMSIZ - 1) == -1) {
		close(socket_fd);
		glb_log_error("failed to bind to device");
		goto done;
	}

	glb_log_info("waiting for packets from %s*", DEFAULT_SRC_IP_PREFIX);
	fflush(stdout);

repeat:
	bytes_read = recvfrom(socket_fd, pkt_buf, MAX_BUFFER, 0, NULL, NULL);
	if (bytes_read <= 0) {
		glb_log_error_and_exit("failed to read bytes from socket");
	}

	struct ether_hdr *eth_hdr = (struct ether_hdr *)pkt_buf;
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	inet_ntop(AF_INET, &(ipv4_hdr->src_addr), src_ip, INET_ADDRSTRLEN);

	if (strncmp(src_ip, DEFAULT_SRC_IP_PREFIX,
		    strlen(DEFAULT_SRC_IP_PREFIX)) == 0) {
		pcap_packet pkt;
		pkt.data = pkt_buf;
		pkt.len = bytes_read;
		if (glb_encapsulate_packet_pcap(config_ctx, &pkt, 0) != 0) {
			glb_log_error_and_exit("packet encap failed!");
		}
	}
	fflush(stdout);
	goto repeat;

done:
	iface_opts.ifr_flags &= ~IFF_PROMISC;
	if (ioctl(socket_fd, SIOCSIFFLAGS, &iface_opts) == -1) {
		glb_log_error_and_exit("cant restore interface settings");
	}

	exit(0);
}
