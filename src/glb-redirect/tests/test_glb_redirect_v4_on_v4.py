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

from nose.tools import assert_equals
from scapy.all import IP, UDP, TCP, ICMP, sniff, send, conf
from glb_scapy import GLBGUEChainedRouting, GLBGUE
from glb_test_utils import GLBTestHelpers
import random

class TestGLBRedirectModuleV4OnV4(GLBTestHelpers):
	PROXY_HOST = '192.168.50.10'
	ALT_HOST = '192.168.50.11'
	SELF_HOST = '192.168.50.5'
	VIP = '10.10.10.10'

	def test_00_icmp_accepted(self):
		for dst in [self.PROXY_HOST, self.ALT_HOST]:
			pkt = \
				IP(dst=dst) / \
				UDP(sport=12345, dport=19523) / \
				GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST])) / \
				IP(src=self.SELF_HOST, dst=dst) / \
				ICMP(type=8, code=0) # echo request

			# expect a ICMP echo response back from self.PROXY_HOST (decapsulated)
			resp_ip = self._sendrecv4(pkt, filter='host {} and icmp'.format(dst))
			print repr(resp_ip)
			assert isinstance(resp_ip, IP)
			assert_equals(resp_ip.src, dst)
			assert_equals(resp_ip.dst, self.SELF_HOST)

			resp_icmp = resp_ip.payload
			assert isinstance(resp_icmp, ICMP)
			assert_equals(resp_icmp.type, 0) # echo reply
			assert_equals(resp_icmp.code, 0)
		

	def test_01_syn_accepted(self):
		pkt = \
			IP(dst=self.PROXY_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST])) / \
			IP(src=self.SELF_HOST, dst=self.PROXY_HOST) / \
			TCP(sport=123, dport=22, flags='S')

		# expect a SYN-ACK back from self.PROXY_HOST (decapsulated)
		resp_ip = self._sendrecv4(pkt, filter='host {} and port 22'.format(self.PROXY_HOST))
		assert isinstance(resp_ip, IP)
		assert_equals(resp_ip.src, self.PROXY_HOST)
		assert_equals(resp_ip.dst, self.SELF_HOST)

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
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=9999, dport=22, flags='A')

		# expect the packet to arrive back to us as a FOU packet since nobody knew about the connection
		# should arrive from the last host in the chain that wasn't us.
		resp_ip = self._sendrecv4(pkt, filter='host {} and udp and port 19523'.format(self.ALT_HOST))
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
		assert isinstance(resp_inner_ip, IP)
		assert_equals(resp_inner_ip.src, self.SELF_HOST)
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
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=eph_port, dport=22, flags='R', seq=1234)
		send(rst)

		# create connection to the VIP on the alt host, which will accept the SYN
		syn = \
			IP(dst=self.ALT_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=eph_port, dport=22, flags='S', seq=1234)

		# retrieve the SYN-ACK
		resp_ip = self._sendrecv4(syn, filter='host {} and port 22'.format(self.VIP))
		assert isinstance(resp_ip, IP)
		assert_equals(resp_ip.src, self.VIP)
		assert_equals(resp_ip.dst, self.SELF_HOST)

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
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=eph_port, dport=22, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)

		# ensure we get a PSH from the host, since SSH should send us the banner
		resp_ip = self._sendrecv4(ack, filter='host {} and port 22'.format(self.VIP))
		assert isinstance(resp_ip, IP)
		assert_equals(resp_ip.src, self.VIP)
		assert_equals(resp_ip.dst, self.SELF_HOST)

		resp_tcp = resp_ip.payload
		assert isinstance(resp_tcp, TCP)
		assert_equals(resp_tcp.sport, 22)
		assert_equals(resp_tcp.dport, eph_port)
		assert_equals(resp_tcp.flags, 'PA')
