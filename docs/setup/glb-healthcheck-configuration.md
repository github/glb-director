# glb-healthcheck configuration

The `glb-healthcheck` component is the application that sends probes to determine liveliness of the 
L7 back-ends for which `glb-director` is acting as an L4 load-balancer.


`glb-healthcheck` does the health-checking for those L7 back-ends which are listed in the configuration for `glb-director`.
 It processes two json files: 
* A source JSON file: to learn the identities of the L7 back-ends whose health is to be checked. This file also lists the protocol to use and the specific protocol-parameters to use when crafting the health-check probes. By default this file is present at `/etc/glb/forwarding_table.src.json`.
* A destination JSON file: to which `glb-healthcheck` writes the contents of the source JSON file along with health-status for each of the L7 back-ends listed in the `source JSON file`. The `glb-director CLI` converts this JSON file into a `.bin` file which serves as the configuration file to be read by `glb-director`. 
By default this file is present at `/etc/glb/forwarding_table.checked.json`.
  
The configuration for `glb-healthcheck` component is present by default at:
* `/etc/glb/healthcheck.conf`: This file lists the locations of the 2 json files processed by `glb-healthcheck`.
* `/etc/glb/forwarding_table.src.json`: This file provides the configuration for `glb-director` if health-checking of the L7 back-ends is not to be performed. It also provides configuration for `glb-healthcheck` for the actual sending of the probes.

## `/etc/glb/healthcheck.conf`

`/etc/glb/healthcheck.conf` defines the few values that need to be configured to use the healthchecker. For most use cases, the default will work:
```
{
  "forwarding_table": {
    "src": "/etc/glb/forwarding_table.src.json",
    "dst": "/etc/glb/forwarding_table.checked.json"
  },
  "reload_command": "glb-director-cli build-config /etc/glb/forwarding_table.checked.json /etc/glb/forwarding_table.checked.bin && systemctl reload glb-director"
}
```

### forwarding_table
####`src` and `dst`

These fields specify the file paths for the source and destination JSON files to be processed by `glb-healthcheck`. By default, `src` is `/etc/glb/forwarding_table.src.json`; and `dst` is `/etc/glb/forwarding_table.checked.json`.

This instructs the healthchecker to load `/etc/glb/forwarding_table.src.json`, perform any checks defined inside it, and keep a `/etc/glb/forwarding_table.checked.json` up to date with valid/live health state. Any time it changes the `dst` file, it also runs the reload command (which in this case compiles the table and reloads the director to pick up those changes).

#### reload_command
Specifies the commands to run upon creation, by `glb-healthcheck`, of a new/updated destination JSON.
 
## `/etc/glb/forwarding_table.src.json`

Health-checking configuration related to the actual sending of the probes and the receiving of the responses is listed in this file:
```
{
 "healthcheck_defaults":
  {
     "interval_ms": 4000,
     "timeout_ms": 2000,
     "trigger": 4
  }
  "tables":
  {
     "backends": [{ "ip": "<a.b.c.d>", "state": "<state-name>", "healthchecks": {"<protocol>": <port-number>, "<tunnel-type>": <gue-port-number>, "http_uri": "<URL if protocol is "http">" } }]
  }
}
```
### interval_ms
_optional_

This field specifies the duration of time, in milli seconds, between successive health-check probes sent to a given a L7 back-end.
It applies to all back-ends for which health-checking is enabled.

By default, 2 seconds.

### timeout_ms
_optional_

This field specifies the duration of time, in milli seconds, that is allowed for a response of health-check probe to received.
At the conclusion of this duration, in the absence of a response the health-check is considered to have failed due to a timeout.
It applies to all back-ends for which health-checking is enabled.

By default, 1 second.

### trigger
_optional_

This field specifies the count of consecutive failing health-checks of a given healthy back-end that causes that back-end to be marked unhealthy.
Similarly, for an unhealthy back-end this specifies the count of consecutive succeeding health-checks that cause that back-end to be marked healthy.
It applies to all back-ends for which health-checking is enabled.

By default, 3.

### backends
_mandatory_

This field specifies the list of back-ends to which glb-director will load-balance the traffic. The list of back-ends for which to do the health-checking, is determined by the presence of "healthchecks" for the resepctive backends. 

If health-checking is not desired for a specific back-end, the parameters under "healthchecks" for that back-end can be omitted.
If present, then along with the settings under "healthcheck_defaults" it determines the characteristics of health-checking for the back-ends listed.

For each back-end listed, health-check probes of the specified protocol are sent to its IP and port as listed.

Currently supported protocols are:
```
    http
    tcp
``` 
Additionally, for the tunnel between a glb-director and a back-end, health-checking of the tunnel is supported for tunnels of the following types:
```
    gue
    fou
```
State maybe one of the following:
```
    filling
    active
    draining
    inactive
```
