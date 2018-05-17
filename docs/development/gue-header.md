## GUE Header usage in GLB

<!--
https://github.com/luismartingarcia/protocol

./protocol "Source port:16,Destination port:16,Length:16,Checksum:16,0:2,C:1,Hlen:5,Proto/ctype:8,Flags:16,Private data type (0):16,Next hop idx:8,Hop count:8,Hop 0:32,...:32,Hop N:32"
-->

GLB Director uses [Generic UDP Encapsulation](https://tools.ietf.org/html/draft-ietf-intarea-gue-04) to encapsulate received IP packets and send them over the wire to proxy servers. GUE provides an extensible header with an unspecified private data area, and GLB Director uses this area to encode the additional servers which may be given a second chance at utilising the given packet in the case that the current server believes it is invalid (not for a given local connection)

```
 0                   1                   2                   3  
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\
|          Source port          |        Destination port       | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ UDP
|             Length            |            Checksum           | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
| 0 |C|   Hlen  |  Proto/ctype  |             Flags             | GUE
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Private data type (0)     |  Next hop idx |   Hop count   |\
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
|                             Hop 0                             | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ GLB
|                              ...                              | private
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ data
|                             Hop N                             | |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
```

#### GUE fields

The GUE version, C-bit and Flags fields are all set to `0`. The length of the private data is calculated from the standard GUE header length as defined in the [GUE draft RFC](https://tools.ietf.org/html/draft-ietf-intarea-gue-04).

The `Proto/ctype` field either encodes the value `4` for IPv4 or `41` for IPv6 based on the original packet received by the GLB Director, no other protocol types are used. These are the standard [IANA Assigned Internet Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml) for IPv4 and IPv6 encapsulation.

The built in Linux Foo-over-UDP module supports GUE, and is compatible with this header format by ignoring the private data entirely. The GLB-REDIRECT iptables module understands how to parse and forward on this header - in the case where a packet is deemed usable by the local server it is allowed through to the Linux network stack for further processing by the gue tunnel.

#### Private data fields

The `Private data type` is `0`, this is essentially a reserved field that leaves room for additional fields in future versions of the GLB header format.

The `Next hop idx` gives the index to the next hop to try if the local machine is unable to process the packet due to it being invalid for all established connections (and not a SYN packet). GLB Director sets this field to `0`.

The `Hop count` specifies the number of IPv4 addresses that follow.

### Packet Processing

Each server receiving a GLB GUE packet must take the following steps:

1. If the packet is a SYN packet or relates to an existing, established or in progress connection, handle it locally by decapsulating the packet.
1. If the packet is otherwise invalid locally, forward the packet to the next alternate server:
    1. If `Next hop idx >= Hop count`, we have no further alternate servers to try, drop the packet (or handle it locally).
    1. Take the outer IP packet Destination IP address and store it in Source IP address field.
    1. Take the hop specified by `Next hop idx` and store it in the Destination IP address field.
    1. Increment the `Next hop idx` field.
    1. Re-route the packet through the kernel IP stack to forward the packet to the destination.
