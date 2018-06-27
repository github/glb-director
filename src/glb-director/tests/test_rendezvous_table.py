from rendezvous_table import GLBRendezvousTable
from nose.tools import assert_equals

class TestGLBRendezvousTable():
	def test_row_seeds(self):
		"""GLBRendezvousTable correctly calculates valid row seeds"""

		forwarding_table_seed = '49a3d861d661ae5ab06ed9326871a2f5'.decode('hex')
		table = GLBRendezvousTable(forwarding_table_seed)
		assert_equals(table.calculate_forwarding_table_row_seed(0x0000).encode('hex'), '491c53a72df4c837')
		assert_equals(table.calculate_forwarding_table_row_seed(0xffff).encode('hex'), 'f223c0cc65161620')

	def test_order_hosts_0000(self):
		"""
		GLBRendezvousTable correctly orders hosts (index=0x0000)
			row seed: 491c53a72df4c837
			1.1.1.1 e47127dd8fe077de
			1.1.1.2 8b1ddec5575c8634
			1.1.1.3 705425e3e522989b
			1.1.1.4 6f022ce1ea607e16
		"""

		forwarding_table_seed = '49a3d861d661ae5ab06ed9326871a2f5'.decode('hex')
		table = GLBRendezvousTable(forwarding_table_seed)

		hosts = ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4']
		a,b,c,d = hosts
		assert_equals(table.forwarding_table_entry(0x0000, hosts), [d,c,b,a])

	def test_order_hosts_ffff(self):
		"""
		GLBRendezvousTable correctly orders hosts (index=0xffff)
			row seed: f223c0cc65161620
			1.1.1.1 0233ef12d7a983d9
			1.1.1.2 6414aa65f0a10601
			1.1.1.3 af48ea8c83867829
			1.1.1.4 a1f610df9fbb2025
		"""

		forwarding_table_seed = '49a3d861d661ae5ab06ed9326871a2f5'.decode('hex')
		table = GLBRendezvousTable(forwarding_table_seed)

		hosts = ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4']
		a,b,c,d = hosts
		assert_equals(table.forwarding_table_entry(0xffff, hosts), [a,b,d,c])

	def test_order_hosts_bb44(self):
		"""
		GLBRendezvousTable correctly orders hosts (index=0xbb44)
			row seed: e290f8f430eb33d3
			1.1.1.1 3595c936c995ae63
			1.1.1.2 db40d5031678c90a
			1.1.1.3 eb798632d691530c
			1.1.1.4 0676eaf9cb7d2f85
		"""

		forwarding_table_seed = '49a3d861d661ae5ab06ed9326871a2f5'.decode('hex')
		table = GLBRendezvousTable(forwarding_table_seed)

		hosts = ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4']
		a,b,c,d = hosts
		assert_equals(table.forwarding_table_entry(0xbb44, hosts), [d,a,b,c])