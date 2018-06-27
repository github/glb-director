#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <rte_acl.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_kni.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_ring.h>
#include <rte_string_fns.h>
#include <rte_version.h>

#if RTE_VERSION >= RTE_VERSION_NUM(17, 11, 0, 1)
#include <rte_bus_pci.h>
#endif

#include "config.h"
#include "glb_kni.h"
#include "log.h"
#include "util.h"

#if RTE_VERSION > RTE_VERSION_NUM(17,11,0,0)
typedef uint16_t port_id_t;
#else
typedef uint8_t port_id_t;
#endif

static struct rte_kni *kni_alloc(port_id_t port_id, struct rte_mempool *pktmbuf_pool);
static void handle_kni_to_nic(unsigned port_id, struct rte_kni *kni,
			      uint8_t tx_queue);

struct glb_kni_ {
	uint8_t physical_port_id;
	uint16_t rx_tx_queue_id;

	struct rte_kni *kni;
	struct rte_ring *kni_tx_ring;

	unsigned owner_lcore_id;
};

glb_kni *glb_kni_new(uint8_t physical_port_id, uint16_t rx_tx_queue_id,
		     unsigned owner_lcore_id, struct rte_mempool *pktmbuf_pool)
{
	glb_kni *gk = calloc(1, sizeof(glb_kni));
	if (gk == NULL) {
		return NULL;
	}

	gk->kni = kni_alloc(physical_port_id, pktmbuf_pool);
	if (gk->kni == NULL) {
		free(gk);
		glb_log_error_and_exit(
		    "Could not create KNI interface.");
		return NULL;
	}

	gk->physical_port_id = physical_port_id;
	gk->rx_tx_queue_id = rx_tx_queue_id;

	gk->owner_lcore_id = owner_lcore_id;

	/* setup a ring to allow multiple producer threads to pass packets on to
	 * the port's kni. this is explicitly multi-producer and single-consumer
	 */
	char tmp[64];
	sprintf(tmp, "glb_kni_tx_%i", physical_port_id);
	gk->kni_tx_ring =
	    rte_ring_create(tmp, 0x100, SOCKET_ID_ANY, RING_F_SC_DEQ);
	if (gk->kni_tx_ring == NULL) {
		free(gk);
		glb_log_error_and_exit(
		    "Could not create packet TX ring for lcore %d.",
		    physical_port_id);
		return NULL;
	}

	/* Set the KNI device MAC to the MAC of the primary port */
	struct ether_addr addr;
	char mac_str[128];
	int ret;
	char mac_ip_tmp[256];
	const char *kni_name;

	kni_name = rte_kni_get_name(gk->kni);
	glb_log_info("Using KNI interface %s", kni_name);

	rte_eth_macaddr_get(physical_port_id, &addr);
	ether_format_addr(mac_str, sizeof(mac_str), &addr);

	sprintf(mac_ip_tmp, "/bin/ip link show vglb_kni%d", physical_port_id);
	glb_log_info("-> %s", mac_ip_tmp);
	ret = WEXITSTATUS(system(mac_ip_tmp));
	if (ret != 0) {
		free(gk);
		glb_log_error_and_exit(
		    "KNI interface %d doesn't exist (exit code: %d).",
		    physical_port_id, ret);
		return NULL;
	}

	glb_log_info("Setting KNI MAC Address to: %s", mac_str);
	sprintf(mac_ip_tmp, "/bin/ip link set dev vglb_kni%d address %s",
		physical_port_id, mac_str);
	glb_log_info("-> %s", mac_ip_tmp);
	ret = WEXITSTATUS(system(mac_ip_tmp));
	if (ret != 0) {
		free(gk);
		glb_log_error_and_exit(
		    "Could not set the MAC of the KNI interface %d (exit "
		    "code: %d).",
		    physical_port_id, ret);
		return NULL;
	}

	sprintf(mac_ip_tmp, "/bin/ip link show vglb_kni%d", physical_port_id);
	glb_log_info("-> %s", mac_ip_tmp);
	ret = WEXITSTATUS(system(mac_ip_tmp));
	if (ret != 0) {
		free(gk);
		glb_log_error_and_exit(
		    "KNI interface %d doesn't exist (exit code: %d).",
		    physical_port_id, ret);
		return NULL;
	}

	return gk;
}

void glb_kni_release(glb_kni *gk)
{
	assert(gk != NULL);

	rte_kni_release(gk->kni);
	rte_ring_free(gk->kni_tx_ring);
}

unsigned glb_kni_safe_tx_burst(glb_kni *gk, struct rte_mbuf **kni_tx_burst,
			       unsigned tx_burst_size)
{
	assert(gk != NULL);

	if (gk->owner_lcore_id == rte_lcore_id()) {
		// send directly to the KNI, since this core owns the KNI
		glb_log_debug(
		    "lcore-%u: -> %d packets bursting immediately to KNI",
		    rte_lcore_id(), tx_burst_size);
		return rte_kni_tx_burst(gk->kni, kni_tx_burst, tx_burst_size);
	} else {
		// queue up for the owning thread to send
		return rte_ring_enqueue_burst(
		    gk->kni_tx_ring, (void **)kni_tx_burst, tx_burst_size
#if RTE_VERSION > RTE_VERSION_NUM(17,05,0,0)
		    	, NULL
#endif
		    );
	}
}

void glb_kni_lcore_flush(glb_kni *gk)
{
	assert(gk != NULL);

	/* If we're running on the lcore that is responsible for tx on this KNI
	 * port, burst packets out to the real KNI port.
	 */
	if (gk->owner_lcore_id == rte_lcore_id()) {
		struct rte_mbuf *kni_tx_burst[PKT_BURST_SZ];
		unsigned kni_tx_num = rte_ring_dequeue_burst(
		    gk->kni_tx_ring, (void **)kni_tx_burst, PKT_BURST_SZ
#if RTE_VERSION > RTE_VERSION_NUM(17,05,0,0)
		    	, NULL
#endif
		    );

		// send any queued packets to KNI
		if (kni_tx_num > 0) {
			unsigned sent =
			    rte_kni_tx_burst(gk->kni, kni_tx_burst, kni_tx_num);
			burst_free_missed_mbufs(kni_tx_burst, kni_tx_num, sent);

			glb_log_debug(
			    "lcore-%u: -> %d packets bursting to KNI (%d "
			    "actually sent, remainder dropped)",
			    rte_lcore_id(), kni_tx_num, sent);
		}

		// TODO: this is currently disabled and run on the main core. to be reworked shortly.
		// handle any requests like link state changes
		// rte_kni_handle_request(gk->kni);

		// receive from KNI and send to NIC queue
		handle_kni_to_nic(gk->physical_port_id, gk->kni,
				  gk->rx_tx_queue_id);
	}
}

void glb_kni_handle_request(glb_kni *gk) {
	rte_kni_handle_request(gk->kni);
}

#define KNI_ENET_HEADER_SIZE 14

/* Callback for request of changing MTU */
static int kni_change_mtu(port_id_t port_id, unsigned new_mtu)
{
	if (port_id >= rte_eth_dev_count()) {
		glb_log_error("Invalid port id %d", port_id);
		return -EINVAL;
	}

	glb_log_info("Change MTU of port %d to %u", port_id, new_mtu);

	return 0;
}

/* Callback for request of configuring network interface up/down */
static int kni_config_network_interface(port_id_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		glb_log_error("Invalid port id %d", port_id);
		return -EINVAL;
	}

	glb_log_info("Configure network interface of %d %s", port_id,
		     if_up ? "up" : "down");

#if 0
	if (if_up != 0) { /* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else /* Configure network interface down */
		rte_eth_dev_stop(port_id);
#endif
	if (ret < 0)
		glb_log_error("Failed to start port %d", port_id);

	return ret;
}

static struct rte_kni *kni_alloc(port_id_t port_id, struct rte_mempool *pktmbuf_pool)
{
	struct rte_kni *kni;
	struct rte_kni_conf conf;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vglb_kni%u", port_id);
	conf.group_id = (uint16_t)port_id;
	conf.mbuf_size = MAX_PACKET_SZ;

	struct rte_kni_ops ops;
	struct rte_eth_dev_info dev_info;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(port_id, &dev_info);
	if (dev_info.pci_dev) {
		conf.addr = dev_info.pci_dev->addr;
		conf.id = dev_info.pci_dev->id;
	}

	memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
	ops.change_mtu = kni_change_mtu;
	ops.config_network_if = kni_config_network_interface;

	kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);

	if (kni == NULL)
		glb_log_error_and_exit("Fail to create kni for port: %d",
				       port_id);

	return kni;
}

static void handle_kni_to_nic(unsigned port_id, struct rte_kni *kni,
			      uint8_t tx_queue)
{
	unsigned nb_rx, nb_tx;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	nb_rx = rte_kni_rx_burst(kni, pkts_burst, PKT_BURST_SZ);
	if (unlikely(nb_rx > PKT_BURST_SZ)) {
		glb_log_error("Error receiving from KNI");
		return;
	}

	if (likely(nb_rx == 0)) {
		return;
	}

	nb_tx =
	    rte_eth_tx_burst(port_id, tx_queue, pkts_burst, (uint16_t)nb_rx);
	burst_free_missed_mbufs(pkts_burst, nb_rx, nb_tx);

	glb_log_debug(
			    "lcore-%u: -> %d packets (%d queued) burst from KNI to port %d queue %d",
			    rte_lcore_id(), nb_rx, nb_tx, port_id, tx_queue);
}
