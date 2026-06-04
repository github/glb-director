# Copyright (c) 2018 GitHub.
#
# This file is part of the `glb-redirect` test suite.
#
# This file is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This file is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this project.  If not, see <https://www.gnu.org/licenses/>.

from scapy.all import sniff, send, L3RawSocket, L3RawSocket6
import socket
from unittest import SkipTest

def _tcp_probe(host, port, timeout=0.2):
	"""Return True iff a TCP connect to host:port succeeds within `timeout`."""
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		rc = s.connect_ex((host, port))
		s.close()
		return rc == 0
	except OSError:
		return False


def _proxy_backends_available():
	"""Return True iff the Vagrant proxy backends (proxy1/proxy2) used by
	these tests are reachable. They live in the Vagrant `glb_datacenter_network`
	and aren't present when running under script/test-local in Docker.

	Both SSH (22) and the test-snoop helper (9999) must answer: the
	multi-host scenarios in test_glb_redirect_v*_on_v*.py use
	RemoteSnoop -> tcp/9999 on each proxy, and probing only SSH would let
	those tests run (and then hang on the SYNC handshake) on lab hosts
	where test-snoop.service hasn't been started."""
	for host in ('192.168.50.10', '192.168.50.11'):
		# port 22 is used as a liveness probe in the actual tests
		if not _tcp_probe(host, 22):
			return False
		# port 9999 is script/helpers/test-snoop.py, required by RemoteSnoop
		if not _tcp_probe(host, 9999):
			return False
	return True


def skip_if_no_vagrant_network():
	"""Raise SkipTest if the Vagrant proxy network isn't available. The
	glb-redirect tests fundamentally require the proxy1/proxy2/director-test
	VMs (with the glb-redirect iptables module loaded), so they can't run in
	the Docker test image."""
	if not _proxy_backends_available():
		raise SkipTest(
			"Vagrant proxy backends (192.168.50.10/11) not reachable on "
			"both ssh/22 and test-snoop/9999; glb-redirect tests require "
			"the Vagrant test network with the glb-redirect iptables "
			"module installed on proxy1/proxy2 and test-snoop.service "
			"running.")


class GLBTestHelpers(object):
	@classmethod
	def setup_class(cls):
		skip_if_no_vagrant_network()

	def _sendrecv6(self, pkt, **kwargs):
		s = L3RawSocket6()
		send(pkt)
		ret = sniff(opened_socket=s, timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		print("Received packet:", repr(ret[0]))
		return ret[0]

	def _sendrecvmany4(self, pkt, **kwargs):
		s = L3RawSocket()
		s.send(pkt)
		ret = s.sniff(timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		for pkt in ret:
			print("Received packet:", repr(pkt))
		return ret

	def _sendrecv4(self, pkt, **kwargs):
		return self._sendrecvmany4(pkt, count=1, **kwargs)[0]

	@staticmethod
	def _match_tuple(saddr, daddr, sport, dport):
		return lambda p: p.src == saddr and p.dst == daddr and p.payload.sport == sport and p.payload.dport == dport
