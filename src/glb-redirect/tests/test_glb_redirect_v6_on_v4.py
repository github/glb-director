from nose.tools import assert_equals
from scapy.all import IP, IPv6, UDP, TCP, ICMPv6EchoRequest, ICMPv6EchoReply, sniff, send, conf, L3RawSocket6
from glb_scapy import GLBGUEChainedRouting, GLBGUE
from glb_test_utils import GLBTestHelpers
import random

class TestGLBRedirectModuleV6OnV4(GLBTestHelpers):
	PROXY_HOST = '192.168.50.10'
	ALT_HOST = '192.168.50.11'
	SELF_HOST = '192.168.50.5'

	SELF_HOST_V6 = 'fd33:75c6:d3f2:7e9f::5'
	VIP = 'fd2c:394c:33a3:26bf::1'

	V4_TO_V6 = {
		'192.168.50.10': 'fd33:75c6:d3f2:7e9f::10',
		'192.168.50.11': 'fd33:75c6:d3f2:7e9f::11',
	}

	def test_00_icmp_accepted(self):
		for dst in [self.PROXY_HOST, self.ALT_HOST]:
			pkt = \
				IP(dst=dst) / \
				UDP(sport=12345, dport=19523) / \
				GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST])) / \
				IPv6(src=self.SELF_HOST_V6, dst=self.V4_TO_V6[dst]) / \
				ICMPv6EchoRequest()
			print repr(pkt)
			# expect a ICMP echo response back from self.PROXY_HOST (decapsulated)
			resp_ip = self._sendrecv6(pkt, lfilter=lambda p: isinstance(p, IPv6) and isinstance(p.payload, ICMPv6EchoReply))

			assert isinstance(resp_ip, IPv6)
			assert_equals(resp_ip.src, self.V4_TO_V6[dst])
			assert_equals(resp_ip.dst, self.SELF_HOST_V6)

			resp_icmp = resp_ip.payload
			assert isinstance(resp_icmp, ICMPv6EchoReply)
		

	def test_01_syn_accepted(self):
		pkt = \
			IP(dst=self.PROXY_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST])) / \
			IPv6(src=self.SELF_HOST_V6, dst=self.V4_TO_V6[self.PROXY_HOST]) / \
			TCP(sport=123, dport=22, flags='S')

		# expect a SYN-ACK back from self.PROXY_HOST (decapsulated)
		resp_ip = self._sendrecv6(pkt, filter='host {} and port 22'.format(self.V4_TO_V6[self.PROXY_HOST]))
		assert isinstance(resp_ip, IPv6)
		assert_equals(resp_ip.src, self.V4_TO_V6[self.PROXY_HOST])
		assert_equals(resp_ip.dst, self.SELF_HOST_V6)

		resp_tcp = resp_ip.payload
		assert isinstance(resp_tcp, TCP)
		assert_equals(resp_tcp.sport, 22)
		assert_equals(resp_tcp.dport, 123)
		assert_equals(resp_tcp.flags, 'SA')
	
	def test_02_unknown_redirected_through_chain(self):
		pkt = \
			IP(dst=self.PROXY_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST, self.SELF_HOST])) / \
			IPv6(src=self.SELF_HOST_V6, dst=self.VIP) / \
			TCP(sport=9999, dport=22, flags='A')

		# expect the packet to arrive back to us as a FOU packet since nobody knew about the connection
		# should arrive from the last host in the chain that wasn't us.
		resp_ip = self._sendrecv4(pkt, filter='src host {} and udp and port 19523'.format(self.ALT_HOST))
		assert isinstance(resp_ip, IP)
		assert_equals(resp_ip.src, self.ALT_HOST) # outer FOU will come from penultimate hop
		assert_equals(resp_ip.dst, self.SELF_HOST)

		resp_fou = resp_ip.payload
		assert isinstance(resp_fou, UDP)
		assert_equals(resp_fou.sport, 12345)
		assert_equals(resp_fou.dport, 19523)

		resp_gue = resp_fou.payload
		assert isinstance(resp_gue, GLBGUE)

		resp_inner_ip = resp_gue.payload
		assert isinstance(resp_inner_ip, IPv6)
		assert_equals(resp_inner_ip.src, self.SELF_HOST_V6)
		assert_equals(resp_inner_ip.dst, self.VIP)

		resp_inner_tcp = resp_inner_ip.payload
		assert isinstance(resp_inner_tcp, TCP)
		assert_equals(resp_inner_tcp.sport, 9999)
		assert_equals(resp_inner_tcp.dport, 22)
	
	def test_03_accepted_on_secondary_chain_host(self):
		eph_port = random.randint(30000, 60000)

		# force RST for this tuple
		rst = \
			IP(dst=self.ALT_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
			IPv6(src=self.SELF_HOST_V6, dst=self.VIP) / \
			TCP(sport=eph_port, dport=22, flags='R', seq=1234)
		send(rst)

		# create connection to the VIP on the alt host, which will accept the SYN
		syn = \
			IP(dst=self.ALT_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
			IPv6(src=self.SELF_HOST_V6, dst=self.VIP) / \
			TCP(sport=eph_port, dport=22, flags='S', seq=1234)

		# retrieve the SYN-ACK
		resp_ip = self._sendrecv6(syn, filter='ip6 host {} and port 22'.format(self.VIP))
		assert isinstance(resp_ip, IPv6)
		assert_equals(resp_ip.src, self.VIP)
		assert_equals(resp_ip.dst, self.SELF_HOST_V6)

		resp_tcp = resp_ip.payload
		assert isinstance(resp_tcp, TCP)
		assert_equals(resp_tcp.sport, 22)
		assert_equals(resp_tcp.dport, eph_port)
		assert_equals(resp_tcp.flags, 'SA')
		assert_equals(resp_tcp.ack, syn.seq + 1)

		syn_ack = resp_ip

		# now send an ACK to the primary proxy host, it should get accepted on the second hop
		ack = \
			IP(dst=self.PROXY_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST, self.SELF_HOST])) / \
			IPv6(src=self.SELF_HOST_V6, dst=self.VIP) / \
			TCP(sport=eph_port, dport=22, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)

		# ensure we get a PSH from the host, since SSH should send us the banner
		resp_ip = self._sendrecv6(ack, filter='ip6 host {} and port 22'.format(self.VIP))
		assert isinstance(resp_ip, IPv6)
		assert_equals(resp_ip.src, self.VIP)
		assert_equals(resp_ip.dst, self.SELF_HOST_V6)

		resp_tcp = resp_ip.payload
		assert isinstance(resp_tcp, TCP)
		assert_equals(resp_tcp.sport, 22)
		assert_equals(resp_tcp.dport, eph_port)
		assert_equals(resp_tcp.flags, 'PA')
