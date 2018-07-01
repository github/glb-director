# Examples of known-compatible DPDK setups

## Bare metal servers on Packet.net cloud, SR-IOV flow bifurcation on Intel X710 (i40e driver)

`glb-director` has been minimally tested on [Packet.net](https://www.packet.net/) with a similar implementation to GitHub's physical datacenters.

Launching a `x1.small.x86` instance type (the default in edge locations) running Debian Stretch, at the time of writing had an Intel X710, and a few components need to be adjusted and upgraded in order to get DPDK set up in a compatible way.

In the default instance state, setting `sriov_numvfs` fails because of PCI bus address assignment. Having the kernel assign bus addresses will work around this. Add `pci=assign-busses` to the end of the linux command line in `/etc/default/grub`, then run the following to persist the changes:
```
apt update
apt install grub2
update-grub
reboot
```

The default i40e drivers provided with the default Debian Stretch kernel are not compatible with flow bifurcation. To enable them, upgrade the drivers to a more recent version:
```
wget https://jaist.dl.sourceforge.net/project/e1000/i40e%20stable/2.4.10/i40e-2.4.10.tar.gz
tar -zxvf i40e-2.4.10.tar.gz
cd i40e-2.4.10/src
make
make install
reboot
```

### Announcing the IP

To announce an IP on multiple glb-director machines on Packet's infrastructure, you'll need to have [BGP enabled on your project](https://help.packet.net/technical/networking/bgp). Once this is in place, request one or more Public IPv4/IPv6 addresses in the location you intend to announce from.

On each director server, using the Packet UI, enable BGP for the server and then install `bird` using the example provided by Packet in the enablement UI.

Since GLB will be receiving the packets, but not locally handling them, the following changes will need to be made to the BIRD configuration:

 * Under `filter packet_bgp`, add a whitelist for the IPs you allocated above, e.g. `if net = 1.2.3.4/32 then accept;`
 * Create a new section, using the same allocated IP (in this example, `1.2.3.4`) and the local machine's IP as the `via` (in this example, `10.48.2.1`):
```
protocol static {
  route 1.2.3.4/32 via 10.48.2.1;
}
```
 * Under `protocol kernel`, change the `import all` line to `import none`. This will prevent the route from being added on the local machine itself, and announce it via BGP only.

You can validate the route is being exported with the usual:
```
birdc show protocols all bgp1
```

### Enabling flow bifurcation to get the public IP routed to the VF

To enable flow bifurcation on Packet's X710 NIC (either just the primary, or both if you want bonding):
```
ethtool --features eno1 ntuple on
echo 1 > /sys/class/net/eno1/device/sriov_numvfs
ip link set eno1 vf 0 spoofchk off
ip link set eno1 vf 0 trust on
```

The flow filters on the X710 allow directing entire destination IP addresses to the VF using the following (note this is slightly different to what is described in the [DPDK docs](https://doc.dpdk.org/guides/howto/flow_bifurcation.html#using-flow-bifurcation-on-i40e-in-linux), since that was for a different driver version):
```
ethtool -N eno1 flow-type ip4 dst-ip 1.2.3.4 user-def 0x8000000000000000 action 0x100000000 loc 0
```

### Bind the VF to DPDK

DPDK can be installed and hugepages configured for it:
```
curl -s https://packagecloud.io/install/repositories/github/unofficial-dpdk-stable/script.deb.sh | sudo bash
apt install linux-headers-$(uname -r)
apt install dpdk dpdk-igb-uio-dkms dpdk-rte-kni-dkms
modprobe igb_uio
modprobe rte_kni

mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
```

Finally, the VF can be bound to the DPDK driver:
```
dpdk-devbind --status # note the PCI address of the VF
dpdk-devbind -b igb_uio 0000:03:02.0 # substitute the PCI address of the VF from above
```

At this point, glb-director should be able to start up and access the VF as configured for DPDK, and Packet-provided IP space should be announced and arrive on that VF. glb-director can then be configured with binds on those IPs.

## Bare metal servers in GitHub datacenters, SR-IOV flow bifurcation on Intel X540-AT2 (ixgbe driver)

The most tested installation of GLB powers the edge load balancing in GitHub's physical datacenters. At the time of writing, we run all our GLB nodes on Intel X540-AT2 NICs on Debian Jessie with a backports 4.9 kernel (from Debian Stretch).

We have datacenters using both active-backup bonding and LACP/802.3ad active-active bonding. We use [flow bifurcation](https://doc.dpdk.org/guides/howto/flow_bifurcation.html) to match packets destined to load balancer IPs and direct them to a SR-IOV virtual function on each of the underlying bond devices that is completely under DPDK's control. `glb-director` receives each VF as a DPDK `port` and does flow forwarding on both of them.

The instructions above for installation on Packet.net are very similar to what we use in our production datacenters (except that it's all automated using configuration management). However, for NICs using `ixgbe` rather than `i40e`, the method of passing packets to the VF is slightly different, and matches [DPDK's documentation for flow bifurcation](https://doc.dpdk.org/guides/howto/flow_bifurcation.html#using-flow-bifurcation-on-ixgbe-in-linux).

Notably, we use Jumbo Frames within the datacenter and this simplifies our setup since we always have headroom to encapsulate packets from our transit providers (MTU of 1500). 
