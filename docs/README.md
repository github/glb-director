# Documentation

## Setup

 * [Example Vagrant Setup](./setup/example-setup-vagrant.md) - if you want to get all components up and running in a test environment and look around at how different GLB components work together.
 * [Known Compatible DPDK configurations](./setup/known-compatible-dpdk.md) - if you want to see examples of how GitHub configures DPDK in its datacenters, or how to use it on a public cloud provider that supports DPDK and BGP.

Some notable known limitations / design decisions of the current implementation:
 * The datacenter internal MTU is expected to be large enough to encapsulate any user packet inside a GUE header. We use jumbo frames (9000+ MTU) within the datacenter with a transit/internet MTU of 1500. GLB Director will not fragment packets if they are too large.
 * If GLB is used within a datacenter, proxy servers should know the correct maximum MSS they can use. We tell `haproxy` to clamp MSS to a small enough value that it can always be encapsulated.
 * Because of the above 2 points, GLB Director doesn't send ICMP fragmentation required messages when it cannot forward packets.
   * GLB Director will, however, forward ICMP fragmentation required packets from outside to the correct proxy server.

## GLB Architecture

 * [GLB Hashing](./development/glb-hashing.md) - explains how the GLB forwarding table is generated and the way rendezvous hashing is used to maintain consistent server mapping for client IPs.
 * [Second Chance Design](./development/second-chance-design.md) - explains how GLB avoids storing or sharing connection state on the director tier, and compares to some other similar technologies.
 * [GUE Header](./development/gue-header.md) - lays out the fields of the GLB private data of the GUE (Generic UDP Encapsulation) header that GLB uses to encapsulate and tunnel packets.
