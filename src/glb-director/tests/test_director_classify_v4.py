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
import socket, struct, time

class TestGLBClassifyV4(GLBDirectorTestBase):
	def test_01_route_classified_v4(self):
		test_packet = Ether()/IP(src="10.11.12.13", dst="1.1.1.1")/TCP(sport=45678, dport=80)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '3.4.5.6')

		assert isinstance(packet, Ether)
		assert_equals(packet.dst, self.py_side_mac)

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '3.4.5.6')

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['2.3.4.5'])

		inner_ip = glb_gue.payload
		assert isinstance(inner_ip, IP) # Expecting the inner IP packet
		assert_equals(inner_ip.dst, '1.1.1.1')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, TCP) # Expecting the inner TCP packet
		assert_equals(inner_tcp.dport, 80)

	def test_02_icmp_fragmentation_required(self):
		test_packet = Ether()/IP(src="10.11.99.99", dst="1.1.1.1")/ICMP(type=3, code=4)/IP(src="1.1.1.1", dst="10.11.12.13")/TCP(sport=80, dport=45678)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '3.4.5.6')

		assert isinstance(packet, Ether)
		assert_equals(packet.dst, self.py_side_mac)

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '3.4.5.6')

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['2.3.4.5'])

		inner_ip = glb_gue.payload
		assert isinstance(inner_ip, IP) # Expecting the inner IP packet
		assert_equals(inner_ip.dst, '1.1.1.1')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, ICMP) # Expecting the inner ICMP packet
		assert_equals(inner_tcp.type, 3)
		assert_equals(inner_tcp.code, 4)

	def test_03_icmp_echo_request(self):
		test_packet = Ether()/IP(src="10.11.12.13", dst="1.1.1.1")/ICMP(type=8, code=0)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '3.4.5.6')

		assert isinstance(packet, Ether)
		assert_equals(packet.dst, self.py_side_mac)

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '3.4.5.6')

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['2.3.4.5'])

		inner_ip = glb_gue.payload
		assert isinstance(inner_ip, IP) # Expecting the inner IP packet
		assert_equals(inner_ip.src, '10.11.12.13')
		assert_equals(inner_ip.dst, '1.1.1.1')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, ICMP) # Expecting the inner ICMP packet
		assert_equals(inner_tcp.type, 8)
		assert_equals(inner_tcp.code, 0)

	def test_04_reload_and_unhealthy_primary(self):
		config = self.get_running_forwarding_config()
		# this will cause the packet to be destined to the secondary, with alternate of the primary.
		config['tables'][0]['backends'][2]['healthy'] = False
		self.update_running_forwarding_tables(config)
		time.sleep(1)

		test_packet = Ether()/IP(src="10.11.12.13", dst="1.1.1.1")/TCP(sport=45678, dport=80)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and str(packet.payload.dst) in ('2.3.4.5', '3.4.5.6'))

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '2.3.4.5') # what was previously the secondary

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['3.4.5.6'])

		inner_ip = glb_gue.payload
		assert isinstance(inner_ip, IP) # Expecting the inner IP packet
		assert_equals(inner_ip.dst, '1.1.1.1')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, TCP) # Expecting the inner TCP packet
		assert_equals(inner_tcp.dport, 80)
