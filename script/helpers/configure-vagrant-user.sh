#!/bin/bash -e

cat >/etc/bird/bird.conf <<EOF
filter glbdemo {
  # the example IPv4 VIP announced by GLB
  if net = 10.10.10.10/32 then accept;
}

router id 192.168.40.2;

protocol direct {
  interface "lo"; # Restrict network interfaces BIRD works with
}

protocol kernel {
  persist; # Don't remove routes on bird shutdown
  scan time 20; # Scan kernel routing table every 20 seconds
  import all; # Default is import all
  export all; # Default is export none
}

# This pseudo-protocol watches all interface up/down events.
protocol device {
  scan time 10; # Scan interfaces every 10 seconds
}

protocol bgp {
  local as 64002;

  import filter glbdemo;
  export none;

  # user side neighbor
  neighbor 192.168.40.3 as 64003;
}
EOF

systemctl restart bird
