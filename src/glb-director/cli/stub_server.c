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
	unsigned char pkt[MAX_BUFFER];
	char src_ip[INET_ADDRSTRLEN];

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
	recvfrom(socket_fd, pkt, MAX_BUFFER, 0, NULL, NULL);

	struct ether_hdr *eth_hdr = (struct ether_hdr *)pkt;
	struct ipv4_hdr *ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

	inet_ntop(AF_INET, &(ipv4_hdr->src_addr), src_ip, INET_ADDRSTRLEN);

	if (strncmp(src_ip, DEFAULT_SRC_IP_PREFIX,
		    strlen(DEFAULT_SRC_IP_PREFIX)) == 0) {
		if (glb_encapsulate_packet_pcap(config_ctx, pkt, 0) != 0) {
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
