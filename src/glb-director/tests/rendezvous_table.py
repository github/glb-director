# Copyright (c) 2018 GitHub.
#
# This file is part of the `glb-director` test suite.
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
