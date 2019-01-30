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
		raw_data = str(packet)
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
		s = L3RawSocket(iface='tunl0')
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
