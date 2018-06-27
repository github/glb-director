/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

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
