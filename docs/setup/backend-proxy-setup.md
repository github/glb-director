# Backend Proxy Tier Setup

GLB Director operates on a 2-tier L4+L7 setup. Most of the work is done on the "director" tier, however the "proxy" tier that terminates TCP connections must also run the `glb-redirect` iptables module to allow [second chance flow](../development/second-chance-design.md) to function.

![L4/L7 load balancer design](../images/glb-component-overview.png)

## Configuring GUE

GLB Director forwards packets using [GUE](../development/gue-header.md). Linux kernel 4.x supports this out of the box, and we've tested it with the Debian Stretch 4.9 series kernel. The proxy server must be configured to receive these GUE packets and decapsulate them. The following will configure them to do so, and can typically be enabled by configuration management:
```
# `fou` includes support for GUE as well as the basic FOU it's based on
modprobe fou
# designate port 19523 as having GUE-encoded data.
ip fou add port 19523 gue
```

For load balancer IPs that use IPv4, ensure that `tunl0` is up and contains those IPs (GUE packets with IPv4 will be decapsulated here automatically):
```
ip link set up dev tunl0
ip addr add <ipv4-address>/32 dev tunl0
```

For load balancer IPs that use IPv6, ensure that `sit0` is up and contains those IPs (GUE packets with IPv6 will be decapsulated here automatically):
```
modprobe sit
ip link set up dev sit0
ip addr add <ipv6-address>/128 dev sit0
```

## Installing and configuring the iptables module

To install the `glb-redirect` iptables module, the `glb-redirect-iptables-dkms` package will compile the module for the running kernel (and any new kernels installed). This will provide a new iptables target called `GLBREDIRECT` which implements the GLB [second chance flow](../development/second-chance-design.md).

```
# ensure we don't track these with conntrack (if in use), since they are not stateful
sudo iptables -t raw -A INPUT -p udp -m udp --dport 19523 -j CT --notrack
# process all packets through GLBREDIRECT to support second chance
sudo iptables -A INPUT -p udp -m udp --dport 19523 -j GLBREDIRECT
```
