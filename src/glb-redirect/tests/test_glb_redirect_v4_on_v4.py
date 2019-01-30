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

from nose.tools import assert_equals, assert_true
from scapy.all import IP, UDP, TCP, ICMP, sniff, send, conf
from glb_scapy import GLBGUEChainedRouting, GLBGUE
from glb_test_utils import GLBTestHelpers
import random


import socket, time, struct
class RemoteSnoop(object):
	def __init__(self, remote_host, remote_port=9999):
		self.remote_host = remote_host
		# connect now so we start receiving our packets
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((remote_host, remote_port))
		# receive some bytes, so we know we're in sync and listening on the remote end
		assert self.s.recv(4) == 'SYNC'

	def recv(self, recv_filter, timeout=10):
		self.s.settimeout(timeout)
		start = time.time()
		while time.time() < start + timeout:
			# TODO: we don't actually timeout here, need to break out of here as well
			pkt_len_raw = self.s.recv(4)
			pkt_len, = struct.unpack('!I', pkt_len_raw)
			pkt_raw = self.s.recv(pkt_len)
			pkt = IP(pkt_raw)
			print("got packet from {}: {}".format(self.remote_host, repr(pkt)))
			if recv_filter(pkt):
				print(" -> match!")
				return pkt
			else:
				print(" -> not a match.")
		return None


class TestGLBRedirectModuleV4OnV4(GLBTestHelpers):
	PROXY_HOST = '192.168.50.10'
	ALT_HOST = '192.168.50.11'
	SELF_HOST = '192.168.50.5'
	VIP = '10.10.10.10'
	ROUTER = '192.168.50.2'

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

	def test_04_icmp_packet_too_big(self):
		# Establish full connection, since ICMP is handled differently for
		# sockets which haven't completed the full 3-way handshake (aka TCP_NEW_SYN_RECV).
		(eph_port, seq, ack) = self._establish_conn(dport=80)

		# send a Packet Too Big message via PROXY from ROUTER, which
		# should end up on the alt host
		pkt = \
			IP(dst=self.PROXY_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[self.ALT_HOST, self.PROXY_HOST])) / \
			IP(src=self.ROUTER, dst=self.VIP) / \
			ICMP(type=3, code=4, nexthopmtu=800) / \
			IP(src=self.VIP, dst=self.SELF_HOST) / \
			TCP(sport=80, dport=eph_port, seq=ack, ack=seq)

		alt_host_stream = RemoteSnoop(self.ALT_HOST)
		send(pkt)
		rem_ip = alt_host_stream.recv(lambda pkt: pkt.src == self.ROUTER)

		print("got: {}".format(repr(rem_ip)))

		# ensure the remote host (ALT_HOST) received the inner packet through the first (failed) hop
		assert isinstance(rem_ip, IP)
		assert_equals(rem_ip.src, self.ROUTER)
		assert_equals(rem_ip.dst, self.VIP)
		rem_icmp = rem_ip.payload
		assert isinstance(rem_icmp, ICMP)
		assert_equals(rem_icmp.type, 3)
		assert_equals(rem_icmp.code, 4)
		assert_equals(rem_icmp.nexthopmtu, 800)
		rem_ipip = rem_icmp.payload
		assert isinstance(rem_ipip, IP)
		assert_equals(rem_ipip.src, self.VIP)
		assert_equals(rem_ipip.dst, self.SELF_HOST)
		assert_equals(rem_ipip.sport, 80)
		assert_equals(rem_ipip.dport, eph_port)

		# http_req = "GET /test.bin HTTP/1.0\r\n\r\n"

		# req = \
		# 	IP(dst=self.ALT_HOST) / \
		# 	UDP(sport=12345, dport=19523) / \
		# 	GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
		# 	IP(src=self.SELF_HOST, dst=self.VIP) / \
		# 	TCP(sport=eph_port, dport=80, flags='PA', seq=seq, ack=ack) / \
		# 	http_req

		# seq += len(http_req)

		# print("sending request")
		# resp = self._sendrecvmany4(req, count=3, lfilter=self._match_tuple(self.VIP, self.SELF_HOST, 80, eph_port))

		# self._reset_conn(eph_port, 80, seq)

		# assert_equals(resp[0].payload.flags, 'A')
		# # TODO: Strange flags=RA packet
		# assert_equals(resp[2].payload.flags, 'FPA')
		# assert_true(len(resp[2].payload) > 800)


	def _establish_conn(self, dport):
		seq_no = random.randint(0, 2**32-1)
		eph_port = random.randint(30000, 60000)

		# create connection to the VIP on the alt host, which will accept the SYN
		syn = \
			IP(dst=self.ALT_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=eph_port, dport=dport, flags='S', seq=seq_no)

		# retrieve the SYN-ACK
		syn_ack = self._sendrecv4(syn, lfilter=self._match_tuple(self.VIP, self.SELF_HOST, dport, eph_port))

		seq_no = syn_ack.ack
		ack_no = syn_ack.seq+1

		ack = \
			IP(dst=self.ALT_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=eph_port, dport=dport, flags='A', seq=seq_no, ack=ack_no)
		send(ack)

		return (eph_port, seq_no, ack_no)

	def _reset_conn(self, sport, dport, seq):
		rst = \
			IP(dst=self.ALT_HOST) / \
			UDP(sport=12345, dport=19523) / \
			GLBGUE(private_data=GLBGUEChainedRouting(hops=[])) / \
			IP(src=self.SELF_HOST, dst=self.VIP) / \
			TCP(sport=sport, dport=dport, flags='R', seq=seq)
		send(rst)
