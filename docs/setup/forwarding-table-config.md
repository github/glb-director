# Forwarding table & Healthchecking

The `glb-director` component provides packet forwarding based on lookups in a binary forwarding table, filled in using [GLB Hashing](../development/glb-hashing.md).

The forwarding table(s) start as a small JSON definition of each load balancer and its binds (IP+port combinations) and backends (proxy servers) as well as state information about those backends.

JSON forwarding tables are converted to the binary format the `glb-director` can read using:
```
glb-director-cli build-config /etc/glb/forwarding_table.json /etc/glb/forwarding_table.bin
```

Typically this is combined with the `glb-healthcheck` component which provides healthchecks and automatically updates the health state of a forwarding table.

## Typical file update flow

### No healthchecker

 1. `/etc/glb/forwarding_table.json` updated by a process (ChatOps, configuration management, etc).
 2. `glb-director-cli build-config /etc/glb/forwarding_table.json /etc/glb/forwarding_table.bin` is run to convert this to a binary forwarding table.
 3. `systemctl reload glb-director` signals the director to load the new forwarding table.

### With `glb-healthcheck` companion

 1. `/etc/glb/forwarding_table.src.json` updated by a process (ChatOps, configuration management, etc).
 2. `systemctl reload glb-healthcheck` signals the healthchecker to load the new source forwarding table.
 3. The healthchecker, either because of the update or a health change, writes `/etc/glb/forwarding_table.checked.json` with updated health states for every backend.
 4. Because it updated the above file, the healthchecker executes its `reload_command`, by default building a binary `/etc/glb/forwarding_table.checked.bin` and then reloading the glb-director as per the manual process.

## Forwarding table configuration options

The forwarding table JSON format looks like the following:
```
{
  "tables": [
    {
      "name": "example1",
      "hash_key": "12345678901234561234567890123456",
      "seed": "34567890123456783456789012345678",
      "binds": [
        { "ip": "10.10.10.10", "proto": "tcp", "port": 80 },
        { "ip": "fdb4:98ce:52d4::42", "proto": "tcp", "port": 80 }
      ],
      "backends": [
        { "ip": "192.168.50.10", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.11", "state": "active", "healthchecks": {"http": 80, "gue": 19523} }
      ]
    }
  ]
}
```

One or more tables can be defined, and each acts independently (this allows multiple "load balancers" to run side by side on the same GLB Director infrastructure). For each table, the following options control how GLB functions:

### `name`

_required by healthchecker, optional without healthchecker_

This specifies the name for the service, and is used by the healthchecker to collate healthcheck events/changes for a particular table in log output. Typically this will be something relating to the load balancer, like `api`, or `git`.

### `hash_key`

_required_

This is a secret key that is used to hash the source IP of inbound packets, making collisions (multiple IPs going to the same backend) more difficult to find.

This should be set to a 32 hex digit (16 decoded byte) string generated randomly. The `hash_key` should be the same across all director nodes for the same table to ensure consistent hashing, and can also be shared across all tables. For more details of how this is used, see [GLB Hashing](../development/glb-hashing.md).

### `seed`

_required_

This is a secret seed that is used to create the rendezvous hash entries.

This should be set to a 32 hex digit (16 decoded byte) string generated randomly. The `seed` should be the same across all director nodes for the same table to ensure consistent hashing. This should be unique for each table to ensure that entries are different in each table even if the original backend list is the same. For more details of how this is used, see [GLB Hashing](../development/glb-hashing.md).

### `binds`

_required_

Array with items of the form `{ "ip": "10.10.10.10", "proto": "tcp", "port": 80 }`.

A list of IP, protocol and port combinations for GLB Director to forward on. It is assumed that packets will land on the NIC already via some other means (usually BGP announcements).

Binds for different ports on the same IP can span multiple tables, providing all tables using that IP are on the same GLB Director installation.

`ip` can either be a single IPv4 or IPv6 address, or an entire subnet in CIDR notation.

The port can either be specified with a single `port`, or a range can be specified with `"port_start": X, "port_end": Y`, in which case all ports in that range (inclusive) will be matched.

`proto` must be either `tcp` or `udp` but only `tcp` has been thoroughly tested (and `udp` defeats most of the purpose of GLB, since there is no connection state)

### `backends`

_required_

Array with items of the form:
 * With healthchecks: `{ "ip": "192.168.50.10", "state": "active", "healthchecks": {"http": 80, "gue": 19523} }`.
 * Without healthchecks: `{ "ip": "192.168.50.10", "state": "active", "healthy": true }`.

This specifies the proxy servers (backends) that will handle packets on this table. 

`ip` must be an IPv4 address of the backend server that will accept GUE encapsulated packets for the specified binds and is running the `glb-redirect` iptables module.

`state` must be one of the following (see [GLB Hashing](../development/glb-hashing.md) for a discription of these states and transitions):
  * `active` - the backend is functioning normally
  * `draining` - existing connections should continue, but new connections should not arrive on this backend
  * `filling` - functionally the same as `active`, but indicates that it may not be safe to change the state of this server
  * `inactive` - the backend is completely ignored

`healthy` specifies whether the server is functioning normally. When unhealthy, the server will be deprioritised as if it was draining. This field does not need to be provided if `glb-healthcheck` is used, it will fill it in when generating the output table. If you are using alternative healthchecking, you should fill in this field.

`healthchecks` - used only when the `glb-healthcheck` component is configured, defines how to check the health state of this backend. Typically this should always contain `"gue": 19523` to test that GUE decapsulation is supported on this backend. `"http": <port>` is also available to do application level healthchecking, for example to test that a service like `haproxy` is running.

If `glb-healthcheck` is used, a backend will be considered down if either the `gue` or `http` healthcheck fails.

## Healthcheck configuration options

`/etc/glb/healthcheck.conf` defines the few values that need to be configured to use the healthchecker. For most use cases, the default will work:
```
{
  "forwarding_table": {
    "src": "/etc/glb/forwarding_table.src.json",
    "dst": "/etc/glb/forwarding_table.checked.json"
  },
  "reload_command": "glb-director-cli build-config /etc/glb/forwarding_table.checked.json /etc/glb/forwarding_table.checked.bin && systemctl reload glb-director",
  "gobgp_config": {
    "address": "127.0.0.1:50051",
    "nexthop": "192.168.50.6",
    "nexthop_ipv6": "fdb4:98ce:52d4::1",
    "communities": [ "65000:1234", "65000:5678" ], 
  },
}
```
### `forwarding_table` 

_required_

specifies which forwarding tables are used for glb-healtcheck

`src` the source forwarding table that is created by the user
`dst` the destination forwarding table that is generated by glb-healthcheck

### `reload_command` 

_required_

This instructs the healthchecker to load `/etc/glb/forwarding_table.src.json`, perform any checks defined inside it, and keep a `/etc/glb/forwarding_table.checked.json` up to date with valid/live health state. Any time it changes the `dst` file, it also runs the reload command (which in this case compiles the table and reloads the director to pick up those changes).

### `gobgp_config`

_optional_

This instructs the health checker to integrate with a [GoBGP](https://github.com/osrg/gobgp) daemon. It communicates over
gRPC to announce the status of the GLB binds or VIPs. When a bind/VIP is healthy the path will be announced with the configured
next hop address. The setting `nexthop` is used for IPv4 bind/VIPs and `nexthop_ipv6` is used for IPv6 bind/VIPs. If the protocol
specific next hop is not configured, then it will not be able to announce the route. If the `address` is not configured (default) this feature will not be enabled.

`address` _required_ The gRPC address for the GoBGP daemon. This typically is `172.0.0.1:50051` assuming you have the BGP daemon installed locally.

`nexthop` _required_ The IPv4 next hop address to use for route announcements. This is required if you have IPv4 bind/VIPs.

`nexthop_ipv6` _optional_ The IPv6 next hop address to use for route announcements. This is only required if you are using IPv6 binds/VIPs.

`communities` _optional_ A list of BGP communities you wish to use for tagging routes