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

class GLBTestHelpers(object):
	def _sendrecv6(self, pkt, **kwargs):
		s = L3RawSocket6()
		send(pkt)
		ret = sniff(opened_socket=s, timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		print "Received packet:", repr(ret[0])
		return ret[0]

	def _sendrecvmany4(self, pkt, **kwargs):
		s = L3RawSocket()
		s.send(pkt)
		ret = s.sniff(timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		for pkt in ret:
			print "Received packet:", repr(pkt)
		return ret

	def _sendrecv4(self, pkt, **kwargs):
		return self._sendrecvmany4(pkt, count=1, **kwargs)[0]

	@staticmethod
	def _match_tuple(saddr, daddr, sport, dport):
		return lambda p: p.src == saddr and p.dst == daddr and p.payload.sport == sport and p.payload.dport == dport
