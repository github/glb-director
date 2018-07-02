/*
 * BSD 3-Clause License
 * 
 * Copyright (c) 2018 GitHub.
 * Copyright (c) 2016 Intel Corporation. (original DPDK example code)
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
