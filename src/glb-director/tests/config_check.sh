#!/bin/bash

set -eo pipefail

. "$BASEDIR/tests/lib/testlib.sh"

begin_test "config checker exits cleanly"
(
  $BASEDIR/cli/glb-director-cli build-config \
    $BASEDIR/tests/data/table.json \
    $BASEDIR/tests/data/test-tables.bin

  sudo $BASEDIR/cli/glb-config-check --no-huge -- \
    --config-file $BASEDIR/tests/data/config.json \
    --forwarding-table $BASEDIR/tests/data/test-tables.bin 2>&1 \
    | tee $BASEDIR/build/check.out
)
end_test

begin_test "config checker returns ok"
(
  grep 'Config ok' $BASEDIR/build/check.out
)
end_test

begin_test "bind get classified"
(
  grep 'Creating ICMP fragmentation needed bind classifier: 1.1.1.1' $BASEDIR/build/check.out
)
end_test

begin_test "bind gets outputted"
(
  grep 'bind: 1.1.1.1:\[80-80\] (6)' $BASEDIR/build/check.out
)
end_test

begin_test "backend gets outputted"
(
  grep '** backend: 1.2.3.4' $BASEDIR/build/check.out
)
end_test

begin_test "no errors"
(
  grep -iv 'failed' $BASEDIR/build/check.out
)
end_test
