# glb-healthcheck configuration

The `glb-healthcheck` component is the application that sends probes to determine liveliness of the 
L7 back-ends for which `glb-director` is acting as an L4 load-balancer.


`glb-healthcheck` does the health-checking for those L7 back-ends which are listed in the configuration for `glb-director`.
 It processes two json files: 
* A source JSON file: to learn the identities of the L7 back-ends whose health is to be checked. This file also lists the protocol to use and the specific protocol-parameters to use when crafting the health-check probes. By default this file is present at `/etc/glb/forwarding_table.src.json`.
* A destination JSON file: to which `glb-healthcheck` writes the contents of this file along with health-status for each of the L7 back-ends listed in the `source JSON file`. The `glb-director CLI` converts this json file into a `.bin` file which serves as the configuration file to be read by `glb-director`. 
By default this file is present at `/etc/glb/forwarding_table.checked.json`.
  
The configuration for `glb-healthcheck` component is present by default at:
* `/etc/glb/healthcheck.conf`: This file lists the locations of the 2 json files processed by `glb-healthcheck`.
* `/etc/glb/forwarding_table.src.json`: This file provides the configuration for `glb-director` if health-checking of the L7 back-ends is not to be performed. It also provides configuration for `glb-healthcheck` for the actual sending of the probes.

## `/etc/glb/healthcheck.conf`

### forwarding_table
Under `src` and `dst`: configuration for the file-path for the source and destination JSON files to be processed by `glb-healthcheck`.
By default, `src` is `/etc/glb/forwarding_table.src.json`; and `dst` is `/etc/glb/forwarding_table.checked.json` .

### reload_command
Specifies the commands to run upon creation, by `glb-healthcheck`, of a new/updated destination JSON.
 
## `/etc/glb/forwarding_table.src.json`
Health-checking related fields that apply to all back-ends listed in this file:

### timeout_ms
_optional_

This field specifies the duration of time, in milli seconds, that is allowed for a response of health-check probe to received.
At the conclusion of this duration, in the absence of a response the health-check is considered to have failed due to a timeout.

By default, 1 second.

### interval_ms
_optional_

This field specifies the duration of time, in milli seconds, between successive health-check probes sent to a given a L7 back-end.
By default, 2 seconds.

### trigger
_optional_

This field specifies the count of consecutive failing health-checks of a given healthy back-end that causes that back-end to be marked unhealthy.
Similarly, for an unhealthy back-end this specifies the count of consecutive succeeding health-checks that cause that back-end to be marked healthy.
By default, 3.
