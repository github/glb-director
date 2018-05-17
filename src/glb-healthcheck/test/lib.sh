#!/bin/sh
# Usage: . lib.sh
# Simple shell command language test library.
# Adapted for babeld.
#
# Tests must follow the basic form:
#
#   begin_test "the thing"
#   (
#        set -e
#        echo "hello"
#        false
#   )
#   end_test
#
# When a test fails its stdout and stderr are shown.
#
# Note that tests must `set -e' within the subshell block or failed assertions
# will not cause the test to fail and the result may be misreported.
#
# Copyright (c) 2011-13 by Ryan Tomayko <http://tomayko.com>
# License: MIT

set -e

TEST_DIR=$(dirname "$0")
BASE_DIR=$(cd $(dirname "$0")/../../ && pwd)

TEMPDIR=$(mktemp -d /tmp/glbhc-XXXXXX)
HOME=$TEMPDIR; export HOME
TRASHDIR="${TEMPDIR}"
LOGDIR="$REALPATH/../log"
HC_LOGFILE="$LOGDIR/glb-healthcheck-$offset.log"

BUILD_DIR=${TEMPDIR}/build

# keep track of num tests and failures
tests=0
failures=0

#mkdir -p $TRASHDIR
mkdir -p $LOGDIR

# Mark the beginning of a test. A subshell should immediately follow this
# statement.
begin_test () {
    test_status=$?
    [ -n "$test_description" ] && end_test $test_status
    unset test_status

    tests=$(( tests + 1 ))
    test_description="$1"

    exec 3>&1 4>&2
    out="$TRASHDIR/out"
    err="$TRASHDIR/err"
    exec 1>"$out" 2>"$err"

    if [ -z "$KEEPTRASH" ]; then
      echo "Cleaning old logs: $HC_LOGFILE"
      rm -f $HC_LOGFILE
    fi

    echo "begin_test: $test_description"
    echo "---- begin_test: $test_description ----" >> $HC_LOGFILE

    # allow the subshell to exit non-zero without exiting this process
    set -x +e
    before_time=$(date '+%s')
}

report_failure () {
  msg=$1
  desc=$2
  failures=$(( failures + 1 ))
  printf "test: %-60s $msg\n" "$desc ..."
  (
      echo "-- stdout --"
      sed 's/^/    /' <"$TRASHDIR/out"
      echo "-- stderr --"
      grep -a -v -e '^\+ end_test' -e '^+ set +x' <"$TRASHDIR/err" |
          sed 's/^/    /'
      if [ -e "$HC_LOGFILE" ]; then
        echo "-- glb-healthcheck log --"
        sed 's/^/    /' <"$HC_LOGFILE"
      fi
  ) 1>&2
}

# Mark the end of a test.
end_test () {
    test_status="${1:-$?}"
    ex_fail="${2:-0}"
    after_time=$(date '+%s')
    set +x -e
    exec 1>&3 2>&4
    elapsed_time=$((after_time - before_time))

    echo "---- end_test: $test_description ----" >> $HC_LOGFILE

    if [ "$test_status" -eq 0 ]; then
      if [ "$ex_fail" -eq 0 ]; then
        printf "test: %-60s OK (${elapsed_time}s)\n" "$test_description ..."
      else
        report_failure "OK (unexpected)" "$test_description ..."
      fi
    else
      if [ "$ex_fail" -eq 0 ]; then
        report_failure "FAILED (${elapsed_time}s)" "$test_description ..."
      else
        printf "test: %-60s FAILED (expected)\n" "$test_description ..."
      fi
    fi
    unset test_description
}

# Mark the end of a test that is expected to fail.
end_test_exfail () {
  end_test $? 1
}

atexit () {
    [ -z "$KEEPTRASH" ] && rm -rf "$TEMPDIR"
    if [ $failures -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}
trap "atexit" EXIT

cleanup() {
    set +e

    echo "Cleaning up by killing from pid files."

    [ -e "${TEMPDIR}/glb-healthcheck.pid" ] && kill $(cat ${TEMPDIR}/glb-healthcheck.pid)

    rm -rf ${TEMPDIR}/*.pid

    if [ -f "$TEMPDIR/core" ]; then
      echo "found a coredump, failing"
      exit 1
    fi

    # put back the original config
    cp $TEMPDIR/forwarding_table.json.bak $TEMPDIR/forwarding_table.json
}

setup() {
  trap cleanup EXIT
  trap cleanup INT
  trap cleanup TERM

  set -e

  # copy a backup of the initial version to reset later
  cp $TEMPDIR/forwarding_table.json $TEMPDIR/forwarding_table.json.bak

  echo 'Running healthcheck service...'
  ./glb-healthcheck --config=${TEMPDIR}/config.json &
  hc_pid=$!

  echo "$hc_pid" > "${TEMPDIR}/glb-healthcheck.pid"

  wait_for_port "glb-healthcheck" 19520
}

signal_reload() {
  kill -HUP $(cat ${TEMPDIR}/glb-healthcheck.pid)
}

# wait for varnish to start accepting connections
wait_for_port () {
(
  SERVICE="$1"
  SERVICE_PORT="$2"

  set +e

  tries=0

  echo "Waiting for $SERVICE to start accepting connections"
  if [ $(uname) = "Linux" ]; then
    printf "GET / HTTP/1.0\n\n"| nc -q 0 localhost $SERVICE_PORT 2>&1 >/dev/null
  else
    printf "GET / HTTP/1.0\n\n" | nc localhost $SERVICE_PORT 2>&1 >/dev/null
  fi
  while [ $? -ne 0 ]; do
    tries=$(( $tries + 1 ))
    if [ $tries -gt 50 ]; then
      echo "FAILED: $SERVICE not accepting connections after $tries attempts"
      exit 1
    fi
    echo "Waiting for $SERVICE to start accepting connections"
    sleep 0.1
    if [ $(uname) = "Linux" ]; then
      printf "GET / HTTP/1.0\n\n" | nc -q 0 localhost $SERVICE_PORT 2>&1 >/dev/null
    else
      printf "GET / HTTP/1.0\n\n" | nc localhost $SERVICE_PORT 2>&1 >/dev/null
    fi
  done
  echo "OK -- $SERVICE seems to be accepting connections"
  exit 0
)
}
