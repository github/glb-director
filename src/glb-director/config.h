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

#include <stdint.h>

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#ifndef NO_DPDK
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_version.h>
#if __has_include(<rte_mbuf_dyn.h>) && RTE_VERSION >= RTE_VERSION_NUM(23, 3, 0, 0)
#include <rte_mbuf_dyn.h>
#define GLB_HAVE_MBUF_USERDATA_DYNFIELD 1
#else
#define GLB_HAVE_MBUF_USERDATA_DYNFIELD 0
#endif
#endif

/* Max size of a single packet */
#define MAX_PACKET_SZ 9220

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created, from docs:
 *   The optimum size (in terms of memory usage) for a mempool 
 *   is when n is a power of two minus one: n = (2^q - 1). 
 */
#define NB_MBUF ((8192 * 8) - 1)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ 32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ PKT_BURST_SZ

/* Number of RX ring descriptors */
#define NB_RXD 128

/* Number of TX ring descriptors */
#define NB_TXD 512

#define MAX_KNI_PORTS 4

/* default ethernet dev, used for collecting nic info */
#define DEFAULT_ETH_DEV 0

/*
 * Compatibility aliases for DPDK API naming differences between older and
 * newer releases.
 */
#ifndef NO_DPDK
#ifdef RTE_ETHER_TYPE_IPV4
#define GLB_ETHER_HDR_DST_ADDR dst_addr
#define GLB_ETHER_HDR_SRC_ADDR src_addr

#ifndef ether_addr
#define ether_addr rte_ether_addr
#endif

#ifndef ether_hdr
#define ether_hdr rte_ether_hdr
#endif

#ifndef ipv4_hdr
#define ipv4_hdr rte_ipv4_hdr
#endif

#ifndef ipv6_hdr
#define ipv6_hdr rte_ipv6_hdr
#endif

#if !defined(ETHER_TYPE_IPv4) && defined(RTE_ETHER_TYPE_IPV4)
#define ETHER_TYPE_IPv4 RTE_ETHER_TYPE_IPV4
#endif

#if !defined(ETHER_TYPE_IPv6) && defined(RTE_ETHER_TYPE_IPV6)
#define ETHER_TYPE_IPv6 RTE_ETHER_TYPE_IPV6
#endif

#ifndef ether_addr_octet
#define ether_addr_octet addr_bytes
#endif

#ifndef tcp_hdr
#define tcp_hdr rte_tcp_hdr
#endif

#ifndef udp_hdr
#define udp_hdr rte_udp_hdr
#endif

#ifndef ether_format_addr
#define ether_format_addr rte_ether_format_addr
#endif

/* mbuf TX flags renamed in DPDK 21.11 */
#ifndef PKT_TX_IPV4
#define PKT_TX_IPV4 RTE_MBUF_F_TX_IPV4
#endif

#ifndef PKT_TX_IP_CKSUM
#define PKT_TX_IP_CKSUM RTE_MBUF_F_TX_IP_CKSUM
#endif

#ifndef PKT_TX_UDP_CKSUM
#define PKT_TX_UDP_CKSUM RTE_MBUF_F_TX_UDP_CKSUM
#endif

/* Ethernet device config constants renamed in DPDK 21.11 */
#ifndef ETH_MQ_RX_RSS
#define ETH_MQ_RX_RSS RTE_ETH_MQ_RX_RSS
#endif

#ifndef ETH_MQ_TX_NONE
#define ETH_MQ_TX_NONE RTE_ETH_MQ_TX_NONE
#endif

#ifndef ETH_RSS_UDP
#define ETH_RSS_UDP RTE_ETH_RSS_UDP
#endif

#ifndef ETH_RSS_TCP
#define ETH_RSS_TCP RTE_ETH_RSS_TCP
#endif
#else
#define GLB_ETHER_HDR_DST_ADDR d_addr
#define GLB_ETHER_HDR_SRC_ADDR s_addr

#ifndef rte_ether_addr
#define rte_ether_addr ether_addr
#endif

#ifndef rte_ether_hdr
#define rte_ether_hdr ether_hdr
#endif

#ifndef rte_ipv4_hdr
#define rte_ipv4_hdr ipv4_hdr
#endif

#ifndef rte_ipv6_hdr
#define rte_ipv6_hdr ipv6_hdr
#endif

#if !defined(RTE_ETHER_TYPE_IPV4) && defined(ETHER_TYPE_IPv4)
#define RTE_ETHER_TYPE_IPV4 ETHER_TYPE_IPv4
#endif

#if !defined(RTE_ETHER_TYPE_IPV6) && defined(ETHER_TYPE_IPv6)
#define RTE_ETHER_TYPE_IPV6 ETHER_TYPE_IPv6
#endif

#ifndef rte_tcp_hdr
#define rte_tcp_hdr tcp_hdr
#endif

#ifndef rte_udp_hdr
#define rte_udp_hdr udp_hdr
#endif

#ifndef rte_ether_format_addr
#define rte_ether_format_addr ether_format_addr
#endif
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(18, 11, 0, 0)
#define GLB_ETH_DEV_COUNT() rte_eth_dev_count_avail()
#else
#define GLB_ETH_DEV_COUNT() rte_eth_dev_count()
#endif

#ifndef RTE_LCORE_FOREACH_SLAVE
#define RTE_LCORE_FOREACH_SLAVE RTE_LCORE_FOREACH_WORKER
#endif

#ifdef RTE_LCORE_FOREACH_WORKER
#ifndef rte_get_master_lcore
#define rte_get_master_lcore rte_get_main_lcore
#endif
#endif

/* KNI was removed in DPDK 23.11. GLB_HAVE_KNI gates all KNI-dependent code. */
#if __has_include(<rte_kni.h>)
#define GLB_HAVE_KNI 1
#else
#define GLB_HAVE_KNI 0
#endif

#if GLB_HAVE_MBUF_USERDATA_DYNFIELD
extern int glb_mbuf_userdata_offset;

static inline void glb_mbuf_set_userdata(struct rte_mbuf *mbuf, uint64_t value)
{
	*RTE_MBUF_DYNFIELD(mbuf, glb_mbuf_userdata_offset, uint64_t *) = value;
}

static inline uint64_t glb_mbuf_get_userdata(const struct rte_mbuf *mbuf)
{
	return *RTE_MBUF_DYNFIELD(mbuf, glb_mbuf_userdata_offset, const uint64_t *);
}
#else
static inline void glb_mbuf_set_userdata(struct rte_mbuf *mbuf, uint64_t value)
{
	mbuf->udata64 = value;
}

static inline uint64_t glb_mbuf_get_userdata(const struct rte_mbuf *mbuf)
{
	return mbuf->udata64;
}
#endif
#endif /* NO_DPDK */
