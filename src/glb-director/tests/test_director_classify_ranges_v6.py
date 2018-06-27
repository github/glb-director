from glb_test_utils import GLBDirectorTestBase, GLBGUE
from scapy.all import Ether, IP, IPv6, Packet, UDP, TCP, ICMP
from nose.tools import assert_equals
import socket, struct, time

class TestGLBClassifyRangesV6(GLBDirectorTestBase):
	@classmethod
	def get_initial_forwarding_config(cls):
		return {
			"tables": [
				{
					"hash_key": "12345678901234561234567890123456",
					"seed": "12345678901234561234567890123456",
					"binds": [
						{ "ip": "fdb4:98ce:52d4::4240/122", "proto": "tcp", "port": 80 },
						{ "ip": "fdb4:98ce:52d4::42", "proto": "tcp", "port_start": 100, "port_end": 200 }
					],
					"backends": [
						{ "ip": "4.5.6.7", "state": "active", "healthy": True }
					]
				}
			]
		}

	def test_01_ip_range_match_v6(self):
		for i in [0, 1, 10, 50, 62, 63]: # fdb4:98ce:52d4::4240/122
			dst_ip = "fdb4:98ce:52d4::42%02x" % (64 + i)

			test_packet = Ether()/IPv6(src="fd91:79d3:d621::1234", dst=dst_ip)/TCP(sport=45678, dport=80)
			self.sendp(test_packet, iface=self.IFACE_NAME_PY)
			packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '4.5.6.7')

			assert isinstance(packet, Ether)
			assert_equals(packet.dst, self.py_side_mac)

			fou_ip = packet.payload
			assert isinstance(fou_ip, IP) # Expecting an IP packet
			assert_equals(fou_ip.src, '65.65.65.65')
			assert_equals(fou_ip.dst, '4.5.6.7')

			fou_udp = fou_ip.payload
			assert isinstance(fou_udp, UDP) # Expecting a FOU packet
			assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
			assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

			glb_gue = fou_udp.payload
			assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)

			inner_ip = glb_gue.payload
			assert isinstance(inner_ip, IPv6) # Expecting the inner IP packet
			assert_equals(inner_ip.dst, dst_ip)

			inner_tcp = inner_ip.payload
			assert isinstance(inner_tcp, TCP) # Expecting the inner TCP packet
			assert_equals(inner_tcp.dport, 80)

	def test_02_ip_range_no_match_v6(self):
		for i in [62, 63, 128, 129]: # fdb4:98ce:52d4::4240/122
			dst_ip = "fdb4:98ce:52d4::42%02x" % i

			test_packet = Ether()/IPv6(src="fd91:79d3:d621::1234", dst=dst_ip)/TCP(sport=45678, dport=80)
			self.sendp(test_packet, iface=self.IFACE_NAME_PY)
			# test these land on KNI as they don't match due to the `/25` specified not containing the rest of the `/24`.
			packet = self.wait_for_packet(self.kni_tx, lambda packet: isinstance(packet.payload, IPv6) and packet.payload.dst == dst_ip)
			assert_equals(packet.payload.dst, dst_ip)

	def test_03_port_range_match_v6(self):
		for dst_port in [100, 101, 150, 180, 198, 199, 200]: # 100-200 inclusive should work
			test_packet = Ether()/IPv6(src="fd91:79d3:d621::1234", dst="fdb4:98ce:52d4::42")/TCP(sport=45678, dport=dst_port)
			self.sendp(test_packet, iface=self.IFACE_NAME_PY)
			packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '4.5.6.7')

			assert isinstance(packet, Ether)
			assert_equals(packet.dst, self.py_side_mac)

			fou_ip = packet.payload
			assert isinstance(fou_ip, IP) # Expecting an IP packet
			assert_equals(fou_ip.src, '65.65.65.65')
			assert_equals(fou_ip.dst, '4.5.6.7')

			fou_udp = fou_ip.payload
			assert isinstance(fou_udp, UDP) # Expecting a FOU packet
			assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
			assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

			glb_gue = fou_udp.payload
			assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
			
			inner_ip = glb_gue.payload
			assert isinstance(inner_ip, IPv6) # Expecting the inner IP packet
			assert_equals(inner_ip.dst, "fdb4:98ce:52d4::42")

			inner_tcp = inner_ip.payload
			assert isinstance(inner_tcp, TCP) # Expecting the inner TCP packet
			assert_equals(inner_tcp.dport, dst_port)

	def test_04_port_range_no_match_v6(self):
		for dst_port in [98, 99, 201, 202]: # just next to the range
			test_packet = Ether()/IPv6(src="fd91:79d3:d621::1234", dst="fdb4:98ce:52d4::42")/TCP(sport=45678, dport=dst_port)
			self.sendp(test_packet, iface=self.IFACE_NAME_PY)
			packet = self.wait_for_packet(self.kni_tx, lambda packet: isinstance(packet.payload, IPv6) and packet.payload.dst == "fdb4:98ce:52d4::42")
			assert_equals(packet.payload.dst, "fdb4:98ce:52d4::42")
