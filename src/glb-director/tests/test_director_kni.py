from glb_test_utils import GLBDirectorTestBase, GLBGUE
from scapy.all import Ether, IP, IPv6, Packet, UDP, TCP
from nose.tools import assert_equals

class TestGLBKNI(GLBDirectorTestBase):
	def test_01_nic_rx_to_kni(self):
		self.sendp(Ether()/IP(dst="1.2.3.4"), iface=self.IFACE_NAME_PY)
		packet = self.wait_for_packet(self.kni_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '1.2.3.4')
		assert_equals(packet.payload.dst, '1.2.3.4')

	def test_02_kni_to_nic_tx(self):
		self.sendp(Ether()/IP(dst="1.2.3.5"), iface=self.IFACE_NAME_KNI)
		packet = self.wait_for_packet(self.eth_tx, lambda packet: isinstance(packet.payload, IP) and packet.payload.dst == '1.2.3.5')
		assert_equals(packet.payload.dst, '1.2.3.5')
