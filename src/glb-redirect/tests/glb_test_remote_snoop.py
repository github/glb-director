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

from scapy.data import ETH_P_IP, ETH_P_IPV6
from scapy.all import Ether
import socket, time, struct

class RemoteSnoop(object):
	def __init__(self, remote_host, remote_port=9999, remote_type=ETH_P_IP, remote_iface='tunl0', debug=False):
		self.debug = debug
		self.remote_host = remote_host
		# connect now so we start receiving our packets
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((remote_host, remote_port))

		# send the ethertype and interface we expect
		# (2 byte ethertype, 4 byte iface len, <iface data>)
		raw_iface = remote_iface.encode('ascii')
		self.s.sendall(struct.pack('!HI', remote_type, len(raw_iface)))
		self.s.sendall(raw_iface)

		# receive some bytes, so we know we're in sync and listening on the remote end
		assert self.s.recv(4) == 'SYNC'

	def recv(self, recv_filter, timeout=10):
		self.s.settimeout(timeout)
		start = time.time()
		while time.time() < start + timeout:
			pkt_len_raw = self.s.recv(4)
			pkt_len, = struct.unpack('!I', pkt_len_raw)
			pkt_raw = self.s.recv(pkt_len)

			# we don't actually want Ether header, it's just a stub so we know the protocol.
			# this means we can be lazy and Scapy do all the encoding/decoding work.
			pkt_ether = Ether(pkt_raw)
			pkt = pkt_ether.payload

			if self.debug: print("got packet from {}: {}".format(self.remote_host, repr(pkt)))
			if recv_filter(pkt):
				if self.debug: print(" -> match!")
				return pkt
			else:
				if self.debug: print(" -> not a match.")
		return None
