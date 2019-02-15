#!/usr/bin/python

import SocketServer
from scapy.all import *
import struct, sys
from scapy.all import L3RawSocket

PORT = 9999

class SnoopHandler(SocketServer.BaseRequestHandler):
	def forward_packet(self, packet):
		print('Forwarding packet: {}'.format(repr(packet)))
		sys.stdout.flush()
		# encapsulate the packet in an empty ethernet frame so the other side can decode more easily
		encap_packet = Ether(src='00:11:22:33:44:55', dst='00:11:22:33:44:55')/packet
		raw_data = str(encap_packet)
		try:
			self.request.sendall(struct.pack('!I', len(raw_data)))
			self.request.sendall(raw_data)
		except IOError:
			print('IOError, continuing')
			sys.stdout.flush()
			return False # probably broken pipe
		return True

	def handle(self):
		print('handling new client')
		sys.stdout.flush()

		# read the interface name from the remote side (prefixed by size)
		iface_len_raw = self.request.recv(6)
		ethertype, iface_len, = struct.unpack('!HI', iface_len_raw)
		iface = self.request.recv(iface_len).decode('ascii')
		print('listening on interface {} with ethertype 0x{:x}'.format(iface, ethertype))
		sys.stdout.flush()

		s = L3RawSocket(iface=iface, type=ethertype)
		self.request.sendall('SYNC') # let the other side know we're ready (listening)
		while True:
			pkt = s.recv()
			if isinstance(pkt, IP) and isinstance(pkt.payload, TCP):
				if pkt.dport == PORT or pkt.sport == PORT: continue # don't talk about ourselves
			if not self.forward_packet(pkt):
				break

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == "__main__":
	HOST, PORT = "0.0.0.0", PORT
	server = ThreadedTCPServer((HOST, PORT), SnoopHandler)
	server.serve_forever()
