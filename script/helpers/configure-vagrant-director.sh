#!/bin/bash 

set -x

tech_type="$1"

local_ipv4_ip="$2"
last_octet="${local_ipv4_ip#*.*.*.}"

/sbin/ifconfig
## BIRD

cat >/etc/bird/bird.conf <<EOF
filter glbdemo {
  # the example IPv4 VIP announced by GLB
  if net = 10.10.10.10/32 then accept;
}

router id ${local_ipv4_ip};

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
  local as 6500${last_octet};

  import none;
  export filter glbdemo;

  neighbor 192.168.50.2 as 65002;
}

protocol static {
  route 10.10.10.10/32 via ${local_ipv4_ip};
}
EOF

systemctl restart bird

## glb-healthcheck

cat >/etc/glb/forwarding_table.src.json <<EOF
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
EOF

systemctl enable glb-healthcheck
systemctl reload glb-healthcheck

## glb-director

if [[ "$tech_type" == "dpdk" ]]; then
  cat >/etc/default/glb-director <<EOF
GLB_DIRECTOR_EAL_ARGS="--master-lcore 0 -l 0,1,2"
GLB_DIRECTOR_CONFIG_FILE="/etc/glb/director.conf"
GLB_DIRECTOR_FORWARDING_TABLE="/etc/glb/forwarding_table.checked.bin"
EOF

  cat >/etc/glb/director.conf <<EOF
{
  "outbound_gateway_mac": "00:11:22:33:44:55",
  "outbound_src_ip": "${local_ipv4_ip}",
  "forward_icmp_ping_responses": true,
  "num_worker_queues": 1,
  "rx_drop_en": false,
  "flow_paths": [
    { "rx_port": 0, "rx_queue": 0, "tx_port": 0, "tx_queue": 0 }
  ],
  "lcores": {
    "lcore-1": {
      "rx": true,
      "tx": true,
      "flow_paths": [0],

      "dist": true,
      "num_dist_workers": 1,

      "kni": true
    },
    "lcore-2": {
      "work": true,
      "work_source": 1
    }
  }
}
EOF

  systemctl enable glb-director
  systemctl restart glb-director

  while ! /sbin/ifconfig vglb_kni0 >/dev/null; do
    sleep 1
    echo 'Waiting for vglb_kni0 to come up...'
  done

  /sbin/ifconfig vglb_kni0 up "$local_ipv4_ip"
fi

if [[ "$tech_type" == "xdp" ]]; then
 set -x
  cat >/etc/default/glb-director-xdp <<EOF
GLB_DIRECTOR_XDP_ROOT_PATHS="--xdp-root-path=/sys/fs/bpf/xdp_root_array@ens6"
GLB_DIRECTOR_XDP_CONFIG_FILE="/etc/glb/director.conf"
GLB_DIRECTOR_XDP_FORWARDING_TABLE="/etc/glb/forwarding_table.checked.bin"
GLB_DIRECTOR_XDP_BPF_PROGRAM="/usr/share/glb-director-xdp/glb_encap.o"
GLB_DIRECTOR_XDP_EXTRA_ARGS=""
EOF

  cat >/etc/glb/director.conf <<EOF
{
  "outbound_gateway_mac": "00:11:22:33:44:55",
  "outbound_src_ip": "${local_ipv4_ip}",
  "forward_icmp_ping_responses": true
}
EOF

  mkdir -p /etc/systemd/system/glb-director-xdp.service.d/
  cat >/etc/systemd/system/glb-director-xdp.service.d/depend_on_shim.conf <<EOF
[Unit]
Requires=xdp-root-shim@ens6
After=xdp-root-shim@ens6
EOF

  /sbin/ifconfig ens6 up "$local_ipv4_ip"

  systemctl daemon-reload
  systemctl enable 'xdp-root-shim@ens6'
  systemctl enable glb-director-xdp
  systemctl restart 'xdp-root-shim@ens6'
  systemctl restart glb-director-xdp

fi
