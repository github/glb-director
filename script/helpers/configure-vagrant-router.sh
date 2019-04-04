#!/bin/bash -e

cat >/etc/bird/bird.conf <<EOF
filter glbdemo {
  # the example IPv4 VIP announced by GLB
  if net = 10.10.10.10/32 then accept;
}

router id 192.168.50.2;

protocol direct {
  interface "lo"; # Restrict network interfaces BIRD works with
}

protocol kernel {
  persist; # Don't remove routes on bird shutdown
  scan time 20; # Scan kernel routing table every 20 seconds
  import all; # Default is import all
  export all; # Default is export none
  merge paths on;
}

# This pseudo-protocol watches all interface up/down events.
protocol device {
  scan time 10; # Scan interfaces every 10 seconds
}

protocol bgp users {
  local as 64003;

  import none;
  export filter glbdemo;

  neighbor 192.168.40.2 as 64002;
}

protocol bgp director1 {
  local as 65002;

  import filter glbdemo;
  export none;

  neighbor 192.168.50.6 as 65006;
}

protocol bgp director2 {
  local as 65002;

  import filter glbdemo;
  export none;

  neighbor 192.168.50.7 as 65007;
}
EOF

systemctl restart bird
