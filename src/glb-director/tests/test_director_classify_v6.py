from glb_test_utils import GLBDirectorTestBase, GLBGUE
from scapy.all import Ether, IP, IPv6, Packet, UDP, TCP, ICMPv6PacketTooBig, ICMPv6EchoRequest
from nose.tools import assert_equals
import socket, struct

class TestGLBClassifyV6(GLBDirectorTestBase):
	def test_01_route_classified_v6(self):
		test_packet = Ether()/IPv6(src='fd91:79d3:d621::1234', dst='fdb4:98ce:52d4::42')/TCP(sport=45678, dport=80)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '5.6.7.8')

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '5.6.7.8')

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['6.7.8.9'])

		inner_ip = glb_gue.payload
		print repr(inner_ip)
		assert isinstance(inner_ip, IPv6) # Expecting the inner IPv6 packet
		assert_equals(inner_ip.src, 'fd91:79d3:d621::1234')
		assert_equals(inner_ip.dst, 'fdb4:98ce:52d4::42')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, TCP) # Expecting the inner TCP packet
		assert_equals(inner_tcp.dport, 80)

	def test_02_icmp_fragmentation_required(self):
		test_packet = Ether()/IPv6(src='fd91:79d3:d621::6666', dst='fdb4:98ce:52d4::42')/ICMPv6PacketTooBig()/IPv6(src="fdb4:98ce:52d4::42", dst="fd91:79d3:d621::1234")/TCP(sport=80, dport=45678)
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '5.6.7.8')

		assert isinstance(packet, Ether)
		assert_equals(packet.dst, self.py_side_mac)

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '5.6.7.8')

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.sport, self.sport_for_packet(test_packet))
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['6.7.8.9'])

		inner_ip = glb_gue.payload
		assert isinstance(inner_ip, IPv6) # Expecting the inner IP packet
		assert_equals(inner_ip.src, 'fd91:79d3:d621::6666')
		assert_equals(inner_ip.dst, 'fdb4:98ce:52d4::42')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, ICMPv6PacketTooBig) # Expecting the inner ICMP packet
	
	def test_03_icmp_echo_request(self):
		test_packet = Ether()/IPv6(src='fd91:79d3:d621::1234', dst='fdb4:98ce:52d4::42')/ICMPv6EchoRequest()
		self.sendp(test_packet, iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '5.6.7.8')

		assert isinstance(packet, Ether)
		assert_equals(packet.dst, self.py_side_mac)

		fou_ip = packet.payload
		assert isinstance(fou_ip, IP) # Expecting an IP packet
		assert_equals(fou_ip.src, '65.65.65.65')
		assert_equals(fou_ip.dst, '5.6.7.8')

		fou_udp = fou_ip.payload
		assert isinstance(fou_udp, UDP) # Expecting a FOU packet
		assert_equals(fou_udp.dport, self.DIRECTOR_GUE_PORT)

		glb_gue = fou_udp.payload
		assert isinstance(glb_gue, GLBGUE) # Expecting a GUE packet (scapy will always map this)
		assert_equals(glb_gue.private_data[0].hop_count, 1)
		assert_equals(glb_gue.private_data[0].next_hop, 0)
		assert_equals(glb_gue.private_data[0].hops, ['6.7.8.9'])

		inner_ip = glb_gue.payload
		assert isinstance(inner_ip, IPv6) # Expecting the inner IP packet
		assert_equals(inner_ip.src, 'fd91:79d3:d621::1234')
		assert_equals(inner_ip.dst, 'fdb4:98ce:52d4::42')

		inner_tcp = inner_ip.payload
		assert isinstance(inner_tcp, ICMPv6EchoRequest) # Expecting the inner ICMP packet
