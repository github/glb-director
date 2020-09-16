# Copyright (c) 2018 GitHub.
#
# This file is part of the `glb-director` test suite.
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

from glb_test_utils import GLBDirectorTestBase, GLBGUE
from scapy.all import Ether, IP, IPv6, Packet, UDP, TCP, ICMP
from nose.tools import assert_equals
from nose.plugins.attrib import attr
import socket, struct, time

@attr(director_type='xdp')
class TestGLBDirectorMetrics(GLBDirectorTestBase):
	def test_01_route_classified_increments_metrics(self):
		self.clear_metrics()

		test_packet = Ether(dst='56:0e:37:46:a2:21', src='b6:59:5f:11:c1:2a')/IP(src="10.11.12.13", dst="1.1.1.1")/TCP(sport=45678, dport=80)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '3.4.5.6')

		time.sleep(10) # wait for 1 metrics cycle

		self.expect_metrics({
			('glb.director.packets.results', ('glb_engine:xdp', 'result:Matched')): (lambda value: value > 0),
			('glb.director.packets.results', ('glb_engine:xdp', 'result:UnknownFormat')): (lambda value: value == 0),
			('glb.director.packets.processed', ('glb_engine:xdp',)): (lambda value: value > 0),
			('glb.director.packets.encapsulated', ('glb_engine:xdp',)): (lambda value: value > 0),
		})
