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
