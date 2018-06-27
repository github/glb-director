import struct, siphash, socket

class GLBRendezvousTable(object):
	def __init__(self, seed_bytes):
		self.seed_bytes = seed_bytes

	def calculate_forwarding_table_row_seed(self, index):
		index_bytes = struct.pack('>I', index)
		return siphash.SipHash_2_4(self.seed_bytes, index_bytes).digest()

	def forwarding_table_entry(self, index, hosts):
		row_seed = self.calculate_forwarding_table_row_seed(index)

		sorter = lambda ip: int(siphash.SipHash_2_4(self.seed_bytes, row_seed + socket.inet_aton(ip)).hexdigest(), 16)

		copy = hosts[:]
		copy.sort(key=sorter)
		return copy