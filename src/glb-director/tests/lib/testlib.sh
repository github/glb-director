#!/bin/sh
# Usage: . testlib.sh
# Simple shell command language test library.
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

# Put bin path on PATH
PATH="$(cd $(dirname "$0")/.. && pwd)/bin:$PATH"

# create a temporary work space
TMPDIR="$(cd $(dirname "$0")/.. && pwd)"/tmp
TRASHDIR="$TMPDIR/$(basename "$0")-$$"

# keep track of num tests and failures
tests=0
failures=0

# this runs at process exit
atexit () {
    rm -rf "$TRASHDIR"
    if [ $failures -gt 0 ]
    then exit 1
    else exit 0
    fi
}

# create the trash dir
trap "atexit" EXIT
mkdir -p "$TRASHDIR"
cd "$TRASHDIR"

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

    # allow the subshell to exit non-zero without exiting this process
    set -x +e
}

# Mark the end of a test.
end_test () {
    test_status="${1:-$?}"
    set +x -e
    exec 1>&3 2>&4

    if [ -f "$TRASHDIR/.skipped" ]; then
        reason=$(cat "$TRASHDIR/.skip_reason" 2>/dev/null)
        rm -f "$TRASHDIR/.skipped" "$TRASHDIR/.skip_reason"
        printf "test: %-60s SKIPPED (%s)\n" "$test_description ..." "$reason"
        unset test_description
        return 0
    fi

    if [ "$test_status" -eq 0 ]; then
        printf "test: %-60s OK\n" "$test_description ..."
    else
        failures=$(( failures + 1 ))
        printf "test: %-60s FAILED\n" "$test_description ..."
        (
            echo "-- stdout --"
            sed 's/^/    /' <"$TRASHDIR/out"
            echo "-- stderr --"
            grep -v -e '^\+ end_test' -e '^+ set +x' <"$TRASHDIR/err" |
                sed 's/^/    /'
        ) 1>&2
    fi
    unset test_description
}

end_test_exfail () {
  end_test $? 1
}

# Mark the current test as skipped from inside the subshell. The marker file
# is read by end_test to report SKIPPED rather than OK/FAILED. Mirrors the
# SkipTest pattern used by the director Python suite so tests that require
# infrastructure unavailable in the container (e.g. DPDK hugepages on
# Docker Desktop / macOS) don't fail when run via script/test-local.
skip_test () {
    reason="${1:-no reason given}"
    echo "SKIP: $reason"
    : > "$TRASHDIR/.skipped"
    echo "$reason" > "$TRASHDIR/.skip_reason"
    exit 0
}

# Returns 0 if DPDK can use hugepages on this host. DPDK requires free
# hugepages of one of the supported sizes; without them EAL initialization
# fails with "Cannot get hugepage information." Docker Desktop on macOS
# (linuxkit kernel) does not expose hugepages by default.
hugepages_available () {
    for f in /sys/kernel/mm/hugepages/hugepages-*/free_hugepages; do
        [ -r "$f" ] || continue
        n=$(cat "$f" 2>/dev/null || echo 0)
        if [ "${n:-0}" -gt 0 ]; then
            return 0
        fi
    done
    return 1
}
