#!/bin/bash
#
# BSD 3-Clause License
# 
# Copyright (c) 2018 GitHub.
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

REALPATH=$(cd $(dirname "$0") && pwd)
. "${REALPATH}/lib.sh"

cat >$TEMPDIR/config.json <<EOF
{
  "forwarding_table": {
    "src": "${TEMPDIR}/forwarding_table.json",
    "dst": "${TEMPDIR}/forwarding_table.hc.json"
  },
  "reload_command": "echo 'Stubbed out for testing purposes' >> reload.txt"
}
EOF

cat >$TEMPDIR/forwarding_table.json <<EOF
{
  "tables": [
    {
      "name": "example1",
      "hash_key": "12345678901234561234567890123456",
      "seed": "34567890123456783456789012345678",
      "binds": [
        { "ip": "1.1.1.1", "proto": "tcp", "port": 80 },
        { "ip": "1.1.1.1", "proto": "tcp", "port": 443 }
      ],
      "backends": [
        { "ip": "192.168.50.10", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.11", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.99", "state": "active", "healthchecks": {"http": 80, "gue": 19523} }
      ]
    },
    {
      "name": "example2",
      "hash_key": "12345678901234561234567890123456",
      "seed": "12345678901234561234567890123456",
      "binds": [
        { "ip": "1.1.1.2", "proto": "tcp", "port": 80 },
        { "ip": "1.1.1.0/24", "proto": "tcp", "port_start": 8080, "port_end": 8085 },
        { "ip": "fdb4:98ce:52d4::42", "proto": "tcp", "port": 80 }
      ],
      "backends": [
        { "ip": "192.168.50.10", "state": "active", "healthchecks": {"http": 5555, "gue": 19523} },
        { "ip": "192.168.50.11", "state": "active", "healthchecks": {"http": 80, "gue": 19000} },
        { "ip": "192.168.50.99", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.5", "state": "active", "healthchecks": {"http": 8765} }
      ]
    }
  ]
}
EOF

begin_test "service starts up, exposes debug vars"
(
  setup # implicitly waits for port to be bound

  curl -v http://127.0.0.1:19520/debug/vars
)
end_test

begin_test "outputs the healthcheck file with valid health"
(
  setup

  sleep 3

  [[ "$(jq -r '.tables[0].backends[0].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]
  [[ "$(jq -r '.tables[0].backends[1].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]
  [[ "$(jq -r '.tables[0].backends[2].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]

  [[ "$(jq -r '.tables[1].backends[0].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]
  [[ "$(jq -r '.tables[1].backends[1].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]
  [[ "$(jq -r '.tables[1].backends[2].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]
  [[ "$(jq -r '.tables[1].backends[3].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]
)
end_test

begin_test "reload should take effect"
(
  setup

  sleep 3

  cat >$TEMPDIR/forwarding_table.json <<EOF
{
  "tables": [
    {
      "hash_key": "12345678901234561234567890123456",
      "seed": "34567890123456783456789012345678",
      "binds": [
        { "ip": "1.1.1.1", "proto": "tcp", "port": 80 },
        { "ip": "1.1.1.1", "proto": "tcp", "port": 443 }
      ],
      "backends": [
        { "ip": "192.168.50.10", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.11", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.99", "state": "active", "healthchecks": {"http": 80, "gue": 19523} }
      ]
    },
    {
      "hash_key": "12345678901234561234567890123456",
      "seed": "12345678901234561234567890123456",
      "binds": [
        { "ip": "1.1.1.2", "proto": "tcp", "port": 80 },
        { "ip": "1.1.1.0/24", "proto": "tcp", "port_start": 8080, "port_end": 8085 },
        { "ip": "fdb4:98ce:52d4::42", "proto": "tcp", "port": 80 }
      ],
      "backends": [
        { "ip": "192.168.50.10", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.11", "state": "active", "healthchecks": {"http": 80, "gue": 19523} },
        { "ip": "192.168.50.99", "state": "active", "healthchecks": {"http": 80, "gue": 19523} }
      ]
    }
  ]
}
EOF

  signal_reload

  sleep 3

  [[ "$(jq -r '.tables[0].backends[0].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]
  [[ "$(jq -r '.tables[0].backends[1].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]
  [[ "$(jq -r '.tables[0].backends[2].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]

  [[ "$(jq -r '.tables[1].backends[0].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]
  [[ "$(jq -r '.tables[1].backends[1].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]
  [[ "$(jq -r '.tables[1].backends[2].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]
)
end_test

begin_test "responds to health check changes"
(
  setup

  sleep 3

  # local backend is now marked unhealthy, port 8765 not responding
  [[ "$(jq -r '.tables[1].backends[3].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]

  # start up a HTTP server
  python -m SimpleHTTPServer 8765 &
  http_pid=$!
  echo "$http_pid" > "${TEMPDIR}/http.pid"

  # wait >1 HC round, shouldn't change because need 3 OKs to change healthy
  sleep 5
  [[ "$(jq -r '.tables[1].backends[3].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]

  # wait for total >3 HC rounds and also over 10s hold period, should then trigger healthy
  sleep 8
  [[ "$(jq -r '.tables[1].backends[3].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]

  kill $http_pid

  # wait >1 HC round, shouldn't change because need 3 FAILs to change unhealthy
  sleep 5
  [[ "$(jq -r '.tables[1].backends[3].healthy' $TEMPDIR/forwarding_table.hc.json)" == "true" ]]

  # wait for total >3 HC rounds and also over 10s hold period, should then trigger unhealthy
  sleep 8
  [[ "$(jq -r '.tables[1].backends[3].healthy' $TEMPDIR/forwarding_table.hc.json)" == "false" ]]
)
end_test
