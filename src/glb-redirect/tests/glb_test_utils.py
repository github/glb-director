from scapy.all import sniff, send, conf, L3RawSocket6

class GLBTestHelpers(object):
	def _sendrecv6(self, pkt, **kwargs):
		s = L3RawSocket6()
		send(pkt)
		ret = sniff(opened_socket=s, timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		print "Received packet:", repr(ret[0])
		return ret[0]

	def _sendrecv4(self, pkt, **kwargs):
		s = conf.L3socket(**kwargs)
		s.send(pkt)
		ret = sniff(opened_socket=s, timeout=1, **kwargs)
		s.close()
		if len(ret) == 0:
			assert False, "Expected to receive a response packet, but none received."
		print "Received packet:", repr(ret[0])
		return ret[0]
