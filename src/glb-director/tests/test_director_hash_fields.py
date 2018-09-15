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

class GLBHashFieldsBase(GLBDirectorTestBase):
	alt_route_fields = None

	@classmethod
	def get_initial_director_config(cls):
		base_cfg = GLBDirectorTestBase.get_initial_director_config()
		base_cfg.update(cls.config_ext)
		return base_cfg

	def test_01_route_classified_v4(self):
		for ip_kwargs, tcp_kwargs, expected_route in self.expected_routes:
			test_packet = Ether()/IP(**ip_kwargs)/TCP(**tcp_kwargs)
			self.sendp(test_packet, iface=self.IFACE_NAME_PY)

			route_path = self.route_for_packet(test_packet, fields=self.route_fields)
			if self.alt_route_fields is not None:
				route_path.extend(self.route_for_packet(test_packet, fields=self.alt_route_fields))
			assert_equals(route_path, expected_route)

			packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == route_path[0])

			assert isinstance(packet, Ether)
			assert_equals(packet.dst, self.py_side_mac)

			fou_ip = packet.payload
			assert isinstance(fou_ip, IP) # Expecting an IP packet
			assert_equals(fou_ip.src, '65.65.65.65')
			assert_equals(fou_ip.dst, route_path[0])

			fou_udp = fou_ip.payload
			assert isinstance(fou_udp, UDP) # Expecting a FOU packet
			assert_equals(fou_udp.sport, self.sport_for_packet(test_packet, fields=self.route_fields))
			assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

			glb_gue = fou_udp.payload
			assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
			assert_equals(glb_gue.private_data[0].hop_count, len(route_path) - 1)
			assert_equals(glb_gue.private_data[0].next_hop, 0)
			assert_equals(glb_gue.private_data[0].hops, route_path[1:])

class TestGLBHashFieldsSourceAddr(GLBHashFieldsBase):
	config_ext = {
		'hash_fields': { 'src_addr': True },
	}
	route_fields = ('src_addr',)
	expected_routes = [
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45678, 'dport': 80}, ['3.4.5.6', '2.3.4.5']),
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45679, 'dport': 80}, ['3.4.5.6', '2.3.4.5']),
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45680, 'dport': 80}, ['3.4.5.6', '2.3.4.5']),
	]

class TestGLBHashFieldsSourceAddrAndPort(GLBHashFieldsBase):
	config_ext = {
		'hash_fields': { 'src_addr': True, 'src_port': True },
	}
	route_fields = ('src_addr', 'src_port')
	expected_routes = [
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45678, 'dport': 80}, ['1.2.3.4', '2.3.4.5']),
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45679, 'dport': 80}, ['1.2.3.4', '3.4.5.6']),
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45680, 'dport': 80}, ['2.3.4.5', '3.4.5.6']),
	]

class TestGLBHashFieldsMigration(GLBHashFieldsBase):
	config_ext = {
		'hash_fields': { 'src_addr': True, 'src_port': True },
		'alt_hash_fields': { 'src_addr': True },
	}
	route_fields = ('src_addr', 'src_port')
	alt_route_fields = ('src_addr',)
	expected_routes = [
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45678, 'dport': 80}, ['1.2.3.4', '2.3.4.5', '3.4.5.6', '2.3.4.5']),
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45679, 'dport': 80}, ['1.2.3.4', '3.4.5.6', '3.4.5.6', '2.3.4.5']),
		({'src': '10.11.12.13', 'dst': '1.1.1.1'}, {'sport': 45680, 'dport': 80}, ['2.3.4.5', '3.4.5.6', '3.4.5.6', '2.3.4.5']),
	]
