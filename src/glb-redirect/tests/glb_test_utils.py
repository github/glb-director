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

from scapy.all import sniff, send, conf, L3RawSocket6

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

	def _sendrecv4(self, pkt, **kwargs):
		s = conf.L3socket(**kwargs)
		s.send(pkt)
		ret = sniff(opened_socket=s, timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		print "Received packet:", repr(ret[0])
		return ret[0]
