# GoBGP integration

When using Github Load Balancer (GLB), you need to inform the upstream network
devices about which bind or VIPs that your services are listening on. In the provided
example Vagrant topology the BIRD BGP daemon is used for announcing routes for the available
bind/VIPs configured on GLB. This is an excellent solution for integrating with upstream routers
and announcing available VIPs. The drawback is that this is a static announcement that provides
no validation of the actual VIP is healthy.

Within the glb-healthcheck service it provides all the available health checking to understand the
state for all the backends associated with a VIP. The glb-healthcheck service can to talk to a local
instance of [GoBGP](https://github.com/osrg/gobgp) and use that as the method for announcing the VIPs
to the upstream routers via BGP. This allows the state of the binds to determine if a route should be
announced or not. This prevents the GLB node from potentially black holing or dropping traffic to VIPs
that are not ready to serve traffic.

## Enabling GoBGP integration

To enable the integration with GoBGP you must configure the glb-healthcheck service to use the local GoBGP
daemon. The required configurtion must be set in the `healthcheck.conf` file, more details for the configuration
options can be found [here](./setup/forwarding-table-config.md).

## Running GoBGP

You must install the GoBGP daemon locally so glb-healthcheck is able to communicate with it. You can download the
[latest release](https://github.com/osrg/gobgp/releases) bundle. It includes gobgpd (daemon) and gobgp (tool to interact with the
daemon) in its release file. Place the binaries on your system and set it up as a systemd service.

### Systemd service definition

To enable GoBGP as a systemd service this service definition can be placed in `/lib/systemd/system/gobgp.service`. Once 
added you will need to run `systemctl daemon-reload` to pickup the new service. The service definition below requires there
to be a local `gobgpd` user for the service to run as. This prevents it from needing to run as `root`.

```
[Unit]
Description=GoBGP Daemon
After=network.target network-online.target
Wants=network.target

[Service]
Type=simple
Restart=always
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/local/sbin/gobgpd --api-hosts=127.0.0.1:50051 -f /etc/gobgp/config.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=TERM
User=gobgpd
WorkingDirectory=/etc/gobgp
TimeoutStopSec=3

[Install]
WantedBy=multi-user.target
```

### Listening on low port without running as root

To enable the service to listen on TCP port 179 without running as root we can enable the capacity directly on the binary.

```
# setcap cap_net_bind_service=+ep /usr/local/sbin/gobgpd
# chown gobgpd:gobgpd /usr/local/sbin/gobgpd
```

### Base GoBGP Configuration

Below is a simple base configuration that will announce any routes that are added to GoBGP to its upstream
neighbor. There are many [configuration options](https://github.com/osrg/gobgp/blob/master/docs/sources/configuration.md)
available for GoBGP. Currently within glb-healthcheck GoBGP is only used for IPv4 or IPv6 route announcements. In the future
other features of GoBGP could be used such as flowspec integration.

```
[global.config]
    as = 65000
    router-id = "1.1.1.1"

# configure each remote neighbor
[[neighbors]]
    [neighbors.config]
        neighbor-address = "172.31.2.168"
        peer-as = 65001
    [neighbors.apply-policy.config] # only export routes, do not recieve them
        export-policy-list = ["export-all-ipv4", "export-all-ipv6"]
        default-export-policy = "accept-route"
    [[neighbors.afi-safis]] # enable upstream IPv4
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv4-unicast"
    [[neighbors.afi-safis]] # enable upstream IPv6
        [neighbors.afi-safis.config]
        afi-safi-name = "ipv6-unicast"
        
# Prefix list to match any IPv4 address
[[defined-sets.prefix-sets]]
    prefix-set-name = "any-ipv4"
    [[defined-sets.prefix-sets.prefix-list]]
        ip-prefix = "0.0.0.0/0"

# Prefix list to match any IPv6 address
[[defined-sets.prefix-sets]]
    prefix-set-name = "any-ipv6"
    [[defined-sets.prefix-sets.prefix-list]]
        ip-prefix = "::/0"

# Export policy to export any IPv4 addresses
[[policy-definitions]]
    name = "export-all-ipv4"
    [[policy-definitions.statements]]
        name = "export-ipv4-all-match"
        [policy-definitions.statements.conditions.match-prefix-set]
        prefix-set = "any-ipv4"
        [policy-definitions.statements.actions]
        route-disposition = "accept-route"

# Export policy to export any IPv6 addresses
[[policy-definitions]]
    name = "export-all-ipv6"
    [[policy-definitions.statements]]
        name = "export-ipv6-all-match"
        [policy-definitions.statements.conditions.match-prefix-set]
        prefix-set = "any-ipv6"
        [policy-definitions.statements.actions]
        route-disposition = "accept-route"
```

## How it works

After every run of the glb-healthcheck the GoBGP integration will take the results and determine which binds to announce. It
will only announce routes for binds with healthy backends. The route will be refreshed for every successful health check cycle.
Once all of the backends for a specific bind have failed health checks, the route will be withdrawn automatically. 

If a bind is removed from one of the forwarding tables it will automatically be removed at the end of the next run. The state
of the routes is stored within glb-healthcheck. In the event that you want to gracefully retire a VIP you can drain each backend. Once 
the backends are all set to `inactive` state then the routes will be automatically withdrawn. This prevents accidently dropping traffic
by sending traffic to a bind in which all backends are set to `inactive`.

## Cleaning up routes

If any announced routes get out of sync you can manually remove them from the GoBGP daemon. You can restart GoBGP and this will
remove any routes loaded. This will be disruptive as it will force your instance of GoBGP to reset all of its neighbor connections.
Alternatively you can delete routes using the control plane CLI tool `gobgp`.

```
# gobgp global rib del <prefix> [-a <address family>]
$ gobgp global rib del 1.1.1.1/32
$ gobgp global rib del 2001:dead:beef::1/128 -a ipv6
```