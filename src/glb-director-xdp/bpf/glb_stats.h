#ifndef _GLB_STATS_H_
#define _GLB_STATS_H_

/* NOTE: these fields follow Go naming conventions, because they are an interface with
 * cgo which needs the fields to be capitalised to be exported and binary-unmarshal-able.
 */

typedef struct glb_global_stats {
    /* The number of packets entering the XDP pipeline */
    uint64_t Processed;
    /* The number of packets that couldn't be parsed, meaning it wasn't the protocols we know how to parse.
     * This isn't always an error, since we listen for any packets on the host.
     */
    uint64_t UnknownFormat;
    /* The number of packets that we could successfully parse, but then didn't match a bind.
     * This is also expected in production.
     */
    uint64_t NoMatchingBind;
    /* The number of processed packets that matched a bind and should be included in the table stats */
    uint64_t Matched;
    
    /* The number of packets that made it all the way through to encapsulation and transmit. */
    uint64_t Encapsulated;
    
    /* The below errors are unexpected, and we generally expect none of them to occur.
     * They might be useful to debug why the system isn't behaving as expected
     */

    /* Internal Error: Reference of a table that we then couldn't look up */
    uint64_t ErrorTable;
    /* Internal Error: Reference of a table with no hashing secret */
    uint64_t ErrorSecret;
    /* Internal Error: The hash field configuration couldn't be retrieved */
    uint64_t ErrorHashConfig;
    /* Internal Error: We looked up a table, but the table didn't have a row where we expected */
    uint64_t ErrorMissingRow;
    /* Internal Error: We tried to create space to encapsulate the packet (at the front), but this failed */
    uint64_t ErrorCreatingSpace;
    /* Internal Error: The outbound gateway MAC address could not be read from configuration */
    uint64_t ErrorMissingGatewayMAC;
    /* Internal Error: The local machine's source IP address could not be read from configuration */
    uint64_t ErrorMissingSourceAddress;
} glb_global_stats;

#endif
