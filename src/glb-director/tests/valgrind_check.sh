#!/bin/bash

set -e

. "$BASEDIR/tests/lib/testlib.sh"

valgrind --leak-check=full $BASEDIR/cli/glb-director-pcap \
  --config-file $BASEDIR/tests/data/config.json \
  --forwarding-table $BASEDIR/tests/data/test-tables.bin \
  --packet-file $BASEDIR/tests/data/dummy1.bin &> $BASEDIR/build/cmd.out || true

begin_test "make sure there are no leaks in packet file mode"
(
  grep -q "ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)" $BASEDIR/build/cmd.out
)
end_test
