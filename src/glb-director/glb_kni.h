#ifndef GLB_KNI_H
#define GLB_KNI_H

#include <rte_mbuf.h>

typedef struct glb_kni_ glb_kni;

/* Creates a GLB context for a KNI interface mapping to the given physical port.
 * The specified lcore is the one core that will be allowed to burst packets
 * directly to the KNI interface, while all other lcores will sent via an
 * intermediary queue.
 */
glb_kni *glb_kni_new(uint8_t physical_port_id, uint16_t rx_tx_queue_id,
		     unsigned owner_lcore_id, struct rte_mempool *pktmbuf_pool);

/* Safely send a burst of packets to the KNI port.
 * If the currently lcore owns this KNI port, the packets are bursted directly.
 * Otherwise, the packets are queued up for that lcore to send on the next call
 * to "glb_kni_lcore_queue_flush".
 */
unsigned glb_kni_safe_tx_burst(glb_kni *gk, struct rte_mbuf **kni_tx_burst,
			       unsigned tx_burst_size);

/* When called on the owning lcore:
 *   - causes any queued packets to be sent to the KNI port.
 *   - causes packets received from KNI to be sent to the NIC.
 */
void glb_kni_lcore_flush(glb_kni *gk);

/* Handle housekeeping for the KNI interface.
 */
void glb_kni_handle_request(glb_kni *gk);

/* Clean up KNI and allocated data.
 */
void glb_kni_release(glb_kni *gk);

#endif // GLB_KNI_H
