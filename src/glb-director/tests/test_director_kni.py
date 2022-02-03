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
from scapy.all import Ether, IP, IPv6, Packet, UDP, TCP
from nose.tools import assert_equals
from nose.plugins.attrib import attr

@attr(director_type='dpdk')
class TestGLBKNI(GLBDirectorTestBase):
	def test_01_nic_rx_to_kni(self):
		if self.kni_tx is None: return # if no KNI is available, don't test

		self.sendp(Ether()/IP(dst="1.2.3.4"), iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.kni_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '1.2.3.4')
		assert_equals(packet.payload.dst, '1.2.3.4')

	def test_02_kni_to_nic_tx(self):
		if self.kni_tx is None: return # if no KNI is available, don't test

		self.sendp(Ether()/IP(dst="1.2.3.5"), iface=self.IFACE_NAME_KNI)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '1.2.3.5')
		assert_equals(packet.payload.dst, '1.2.3.5')
