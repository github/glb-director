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

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>

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
#ifdef RTE_ETHER_TYPE_IPV4
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
#else
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
#endif

#ifndef RTE_LCORE_FOREACH_SLAVE
#define RTE_LCORE_FOREACH_SLAVE RTE_LCORE_FOREACH_WORKER
#endif

#ifdef RTE_LCORE_FOREACH_WORKER
#ifndef rte_get_master_lcore
#define rte_get_master_lcore rte_get_main_lcore
#endif
#endif
