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

set -e

. "$BASEDIR/tests/lib/testlib.sh"

begin_test "starting up and waiting for the server"
(
  sudo $BASEDIR/cli/glb-director-cli build-config $BASEDIR/tests/data/table.json $BASEDIR/tests/data/test-tables.bin

  sudo valgrind --leak-check=full \
    $BASEDIR/cli/glb-director-stub-server \
    --config-file $BASEDIR/tests/data/config.json \
    --forwarding-table $BASEDIR/tests/data/test-tables.bin \
    &> $BASEDIR/build/stub_server.log &

  echo "waiting for remote server..."
  while ! grep -q '==' $BASEDIR/build/stub_server.log; do
    echo "waiting..."
    sleep 1
  done

  # extract out the pid. the one we would see here from $! is valgrind, not the subprocess.
  echo "$(head -n 1 $BASEDIR/build/stub_server.log | awk '{print $1}' | sed s/=//g)" >$BASEDIR/build/stub-server.pid
)
end_test

begin_test "performing configuration requests/reloads"
(
  echo "request group 1"
  curl -o /dev/null -s --local-port 50001 --interface 127.1.0.1 -iv 127.0.0.1:8888 &> /dev/null || true
  curl -o /dev/null -s --local-port 50251 --interface 127.199.255.255 -iv 127.0.0.1:8888 &> /dev/null  || true

  echo "reloading director ..."
  sudo $BASEDIR/cli/glb-director-cli build-config $BASEDIR/tests/data/table1.json $BASEDIR/tests/data/test-tables.bin
  sudo kill -SIGUSR1 $(cat $BASEDIR/build/stub-server.pid)

  echo "request group 2"
  curl -o /dev/null -s --local-port 50002 --interface 127.1.0.1 -iv 127.0.0.1:8888 &> /dev/null  || true
  curl -o /dev/null -s --local-port 50252 --interface 127.199.255.255 -iv 127.0.0.1:8888 &> /dev/null  || true

  echo "reloading director ..."
  sudo $BASEDIR/cli/glb-director-cli build-config $BASEDIR/tests/data/table.json $BASEDIR/tests/data/test-tables.bin
  sudo kill -SIGUSR1 $(cat $BASEDIR/build/stub-server.pid)

  echo "request group 3"
  curl -o /dev/null -s --local-port 50003 --interface 127.1.0.1 -iv 127.0.0.1:8888 &> /dev/null  || true
  curl -o /dev/null -s --local-port 50253 --interface 127.199.255.255 -iv 127.0.0.1:8888 &> /dev/null  || true

  echo "reloading director ..."
  sudo $BASEDIR/cli/glb-director-cli build-config $BASEDIR/tests/data/table2.json $BASEDIR/tests/data/test-tables.bin
  sudo kill -SIGUSR1 $(cat $BASEDIR/build/stub-server.pid)

  echo "request group 4"
  curl -o /dev/null -s --local-port 50004 --interface 127.1.0.1 -iv 127.0.0.1:8888 &> /dev/null  || true
  curl -o /dev/null -s --local-port 50254 --interface 127.199.255.255 -iv 127.0.0.1:8888 &> /dev/null  || true

  echo "reloading director ..."
  sudo $BASEDIR/cli/glb-director-cli build-config $BASEDIR/tests/data/table.json $BASEDIR/tests/data/test-tables.bin
  sudo kill -SIGUSR1 $(cat $BASEDIR/build/stub-server.pid)

  echo "request group 5"
  curl -o /dev/null -s --local-port 50005 --interface 127.1.0.1 -iv 127.0.0.1:8888 &> /dev/null  || true
  curl -o /dev/null -s --local-port 50255 --interface 127.199.255.255 -iv 127.0.0.1:8888 &> /dev/null  || true

  echo "reloading director ..."
  sudo $BASEDIR/cli/glb-director-cli build-config $BASEDIR/tests/data/table3.json $BASEDIR/tests/data/test-tables.bin
  sudo kill -SIGUSR1 $(cat $BASEDIR/build/stub-server.pid)

  echo "request group 6"
  curl -o /dev/null -s --local-port 50006 --interface 127.1.0.1 -iv 127.0.0.1:8888 &> /dev/null  || true
  curl -o /dev/null -s --local-port 50256 --interface 127.199.255.255 -iv 127.0.0.1:8888 &> /dev/null  || true

  sleep 1 # wait for the request to go through before killing stuff
  sudo kill $(cat $BASEDIR/build/stub-server.pid)
  sleep 1 # wait for kill
)
end_test

# clean up, to be sure
sudo kill $(cat $BASEDIR/build/stub-server.pid) || true
rm $BASEDIR/build/stub-server.pid

begin_test "ensure we received three packets"
(
  grep -c '\[packet\]' $BASEDIR/build/stub_server.log | grep 12
)
end_test

begin_test "[127.1.0.1] hashes to 920d666b67911c9a"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep '127.1.0.1' | grep -c '920d666b67911c9a' | grep 6
)
end_test

begin_test "[127.199.255.255] hashes to 605677c71b0f36f6"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep '127.199.255.255' | grep -c '605677c71b0f36f6' | grep 6
)
end_test

begin_test "[127.1.0.1] ensure first packet went to 1.2.3.4 (state: normal)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50001 | grep 'via_ip: 1.2.3.4 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.1.0.1] ensure second packet went to 2.3.4.5 (state: 1.2.3.4 removed)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50002 | grep 'via_ip: 2.3.4.5 alt_ip: 3.4.5.6'
)
end_test

begin_test "[127.1.0.1] ensure third packet went to 1.2.3.4 (state: normal)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50003 | grep 'via_ip: 1.2.3.4 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.1.0.1] ensure fourth packet went to 1.2.3.4 (state: 3.4.5.6 draining)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50004 | grep 'via_ip: 1.2.3.4 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.1.0.1] ensure fifth packet went to 1.2.3.4 (state: normal)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50005 | grep 'via_ip: 1.2.3.4 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.1.0.1] ensure sixth packet went to 1.2.3.4 (state: 2.3.4.5 unhealthy)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50006 | grep 'via_ip: 1.2.3.4 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.199.255.255] ensure first packet went to 2.3.4.5 (state: normal)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50251 | grep 'via_ip: 3.4.5.6 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.199.255.255] ensure second packet went to 2.3.4.5 (state: 1.2.3.4 removed)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50252 | grep 'via_ip: 3.4.5.6 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.199.255.255] ensure third packet went to 2.3.4.5 (state: normal)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50253 | grep 'via_ip: 3.4.5.6 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.199.255.255] ensure fourth packet went to 1.2.3.4 (state: 3.4.5.6 draining)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50254 | grep 'via_ip: 2.3.4.5 alt_ip: 3.4.5.6'
)
end_test

begin_test "[127.199.255.255] ensure fifth packet went to 2.3.4.5 (state: normal)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50255 | grep 'via_ip: 3.4.5.6 alt_ip: 2.3.4.5'
)
end_test

begin_test "[127.199.255.255] ensure sixth packet went to 1.2.3.4 (state: 2.3.4.5 unhealthy)"
(
  grep '\[packet\]' $BASEDIR/build/stub_server.log | grep 50256 | grep 'via_ip: 2.3.4.5 alt_ip: 3.4.5.6'
)
end_test

begin_test "make sure there are no leaks in stub server mode"
(
  grep -q "ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)" $BASEDIR/build/stub_server.log
)
end_test
