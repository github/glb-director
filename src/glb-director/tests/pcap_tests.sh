#!/bin/bash

set -e

. "$BASEDIR/tests/lib/testlib.sh"

begin_test "run with pcap and example tables"
(
  $BASEDIR/cli/glb-director-cli build-config \
    $BASEDIR/tests/data/table.json \
    $BASEDIR/tests/data/test-tables.bin
  
  sudo timeout 2.0 $BASEDIR/build/glb-director \
    --vdev="net_pcap0,rx_pcap=$BASEDIR/tests/data/1k_pkts.pcap,tx_pcap=$BASEDIR/build/tx.pcap" -- \
    --config-file $BASEDIR/tests/data/config.json \
    --forwarding-table $BASEDIR/tests/data/test-tables.bin \
    || true # timeout will make this look like an error, but it's expected
)
end_test

begin_test "tx: should be 1000 packets"
(
  sudo tcpdump -r $BASEDIR/build/tx.pcap | wc -l | grep 1000
)
end_test

begin_test "tx: verify to/from"
(
  sudo tcpdump -nr $BASEDIR/build/tx.pcap | grep -q 'IP 65.65.65.65.61139 > 3.4.5.6.19523: UDP, length 52'
)
end_test
