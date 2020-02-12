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

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import sniff, sendp, Ether, IP, IPv6, L2ListenSocket, MTU, Packet, UDP, TCP, bind_layers, ICMP, ICMPv6PacketTooBig
from pyroute2 import IPRoute, NetlinkError
from nose.tools import assert_equals
import subprocess, time
import signal
from contextlib import contextmanager
import socket, struct
import json
import siphash
import os, sys
import signal
import tempfile
from netaddr import IPNetwork
from glb_scapy import GLBGUEChainedRouting, GLBGUE
from rendezvous_table import GLBRendezvousTable

class TimeoutException(BaseException): pass

def timeout_handler(signum, frame):
	raise TimeoutException()

@contextmanager
def timeout(seconds):
	old_handler = signal.signal(signal.SIGALRM, timeout_handler)
	signal.alarm(seconds)
	try:
		yield
	finally:
		signal.alarm(0)
		signal.signal(signal.SIGALRM, old_handler)

class DirectorControlBase(object):
	# only implemented if the backend supports KNI (so is DPDK), others ignore this bit
	def kni(self):
		return None
	
	def setup_pyside(self, iface):
		pass

class DPDKDirectorControl(DirectorControlBase):
	IFACE_NAME_KNI = 'vglb_kni0'

	def __init__(self):
		assert os.path.exists('/dev/kni'), "KNI kernel module not loaded"

		self.director = None
	
	def setup(self, iface):
		# launch the glb director, mocking an eth device with the dpdk end of our veth
		self.director = subprocess.Popen(
			[
				'./build/glb-director',
				'--vdev=eth_pcap0,iface=' + iface,
				'--',
				'--debug',
				'--config-file', './tests/director-config.json',
				'--forwarding-table', './tests/test-tables.bin'
			],
			stdout=open('director-output.txt', 'wba'),
			stderr=subprocess.STDOUT,
		)

		print 'launched as pid', self.director.pid

		# wait for the kni interface to come up, indicating the app is ready
		try:
			with timeout(10):
				while len(ip.link_lookup(ifname=cls.IFACE_NAME_KNI)) == 0:
					time.sleep(0.1)
		except TimeoutException:
			self.director.kill()
			self.director.wait()
			self.director = None
			raise

		# bring up the KNI interface
		try:
			idx = ip.link_lookup(ifname=cls.IFACE_NAME_KNI)[0]
			ip.link('set', index=idx, state='up')
		except NetlinkError:
			self.director.kill()
			self.director.wait()
			self.director = None
			raise
	
	def cleanup(self):
		self.director.terminate()
		time.sleep(0.5)
		self.director.kill()
		self.director.wait()
		self.director = None
	
	def reload(self):
		if self.director is not None:
			self.director.send_signal(signal.SIGUSR1)
	
	def kni(self):
		return L2ListenSocket(iface=cls.IFACE_NAME_KNI, promisc=True)

class SystemdNotify(object):
	def __init__(self, unix_path):
		self.unix_path = unix_path
		if os.path.exists(unix_path):
			os.unlink(unix_path)
		
		notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
		notify_sock.bind(unix_path)
		self.notify_sock = notify_sock

	def updated_env(self):
		updated_env = os.environ.copy()
		updated_env['NOTIFY_SOCKET'] = self.unix_path
		return updated_env
	
	def wait(self):
		# wait for it to notify that it's actually bound to the iface.
		self.notify_sock.settimeout(2)
		try:
			data, addr = self.notify_sock.recvfrom(32)
			assert data == 'READY=1' # only thing it will send
		except socket.timeout:
			print 'notify ready timed out'
			raise Exception('Timeout while waiting for director to signal ready, did it crash?\n\n' + open('director-output.txt', 'rb').read())
		
		self.notify_sock.close()

		os.unlink(self.unix_path)

class XDPDirectorControl(DirectorControlBase):
	def __init__(self):
		self.director = None
	
	# veth pair implementation of XDP_TX silently drops packets unless the other side of the veth
	# pair also has xdp enabled. to work around this limitation, we add an XDP program that always
	# passes every packet.
	def setup_pyside(self, iface):
		subprocess.call(['ip', 'link', 'set', 'dev', iface, 'xdp', 'off'])
		subprocess.check_call(['ip', 'link', 'set', 'dev', iface, 'xdp', 'obj', '../glb-director-xdp/bpf/passer.o'])

	def setup(self, iface):
		notify_shim = SystemdNotify('/tmp/glb-notify-shim.sock')
		self.xdp_root = subprocess.Popen(
			[
				'../glb-director-xdp/xdp-root-shim/xdp-root-shim',
				os.path.abspath('../glb-director-xdp/bpf/tailcall.o'),
				'/sys/fs/bpf/root_array@' + iface,
				iface,
			],
			stdout=open('director-output.txt', 'wba'),
			stderr=subprocess.STDOUT,
			env=notify_shim.updated_env(),
		)
		notify_shim.wait()

		self.director_iface = iface
		self.launch_director()
	
	def launch_director(self):
		notify_director = SystemdNotify('/tmp/glb-notify.sock')
		self.director = subprocess.Popen(
			[
				# 'strace',
				'../glb-director-xdp/glb-director-xdp',
				'--xdp-root-path=/sys/fs/bpf/root_array@' + self.director_iface,
				'--debug',
				'--config-file', os.path.abspath('./tests/director-config.json'),
				'--forwarding-table', os.path.abspath('./tests/test-tables.bin'),
				'--bpf-program', os.path.abspath('../glb-director-xdp/bpf/glb_encap.o'),
			],
			stdout=open('director-output.txt', 'wba'),
			stderr=subprocess.STDOUT,
			env=notify_director.updated_env(),
		)

		print 'launched as pid', self.director.pid

		notify_director.wait()

	def cleanup(self):
		for proc in [self.director, self.xdp_root]:
			proc.terminate()
			time.sleep(0.5)
			proc.kill()
			proc.wait()
		self.director = None
		self.xdp_root = None

	def reload(self):
		if self.director is not None:
			old_director = self.director
			self.director = None
			self.launch_director()
			old_director.terminate()

class GLBDirectorTestBase():
	DIRECTOR_GUE_PORT = 19523

	IFACE_NAME_PY = 'vglbtest_py'
	IFACE_NAME_DIRECTOR = 'vglbtest_dpdk'

	eth_tx = None
	kni_tx = None

	@classmethod
	def make_director_backend(cls):
		director_type = os.getenv('GLB_DIRECTOR_TYPE', 'dpdk')
		assert director_type in ('dpdk', 'xdp')
		return {
			'dpdk': DPDKDirectorControl,
			'xdp': XDPDirectorControl,
		}[director_type]()

	@classmethod
	def get_initial_forwarding_config(cls):
		return {
			"tables": [
				{
					"hash_key": "12345678901234561234567890123456",
					"seed": "34567890123456783456789012345678",
					"binds": [
						{ "ip": "1.1.1.1", "proto": "tcp", "port": 80 },
						{ "ip": "1.1.1.1", "proto": "tcp", "port": 443 }
					],
					"backends": [
						{ "ip": "1.2.3.4", "state": "active", "healthy": True },
						{ "ip": "2.3.4.5", "state": "active", "healthy": True },
						{ "ip": "3.4.5.6", "state": "active", "healthy": True }
					]
				},
				{
					"hash_key": "12345678901234561234567890123456",
					"seed": "12345678901234561234567890123456",
					"binds": [
						{ "ip": "1.1.1.2", "proto": "tcp", "port": 80 },
						{ "ip": "1.1.1.3", "proto": "tcp", "port": 80 },
						{ "ip": "fdb4:98ce:52d4::42", "proto": "tcp", "port": 80 }
					],
					"backends": [
						{ "ip": "4.5.6.7", "state": "active", "healthy": True },
						{ "ip": "5.6.7.8", "state": "active", "healthy": True },
						{ "ip": "6.7.8.9", "state": "active", "healthy": True },
						{ "ip": "7.8.9.0", "state": "active", "healthy": True }
					]
				}
			]
		}

	@classmethod
	def get_initial_director_config(cls):
		return {
			"outbound_gateway_mac": GLBDirectorTestBase.py_side_mac,
			"outbound_src_ip": '65.65.65.65',
			"forward_icmp_ping_responses": True,
			"num_worker_queues": 1,
			"flow_paths": [
				{ "rx_port": 0, "rx_queue": 0, "tx_port": 0, "tx_queue": 0 },
			],
			"lcores": {
				"lcore-1": {
					"rx": True,
					"tx": True,
					"flow_paths": [0],

					"dist": True,
					"num_dist_workers": 1,

					"kni": True,
				},
				"lcore-2": {
					"work": True,
					"work_source": 1,
				}
			},
		}

	@classmethod
	def update_running_forwarding_tables(cls, config):
		f = open('tests/test-tables.json', 'wb')
		f.write(json.dumps(config, indent=4))
		f.close()

		GLBDirectorTestBase.running_forwarding_config = config
		subprocess.check_call(['./cli/glb-director-cli', 'build-config', 'tests/test-tables.json', 'tests/test-tables.bin'])

		if hasattr(GLBDirectorTestBase, 'backend') and GLBDirectorTestBase.backend is not None:
			GLBDirectorTestBase.backend.reload()

	@classmethod
	def get_running_forwarding_config(cls):
		# jsonify so we deep copy
		return json.loads(json.dumps(GLBDirectorTestBase.running_forwarding_config))

	@classmethod
	def setup_class(cls):
		initial_config = cls.get_initial_forwarding_config()
		cls.update_running_forwarding_tables(initial_config)

		ip = IPRoute()

		# set up a veth interface from python <-> director
		if len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)) == 0:
			ip.link('add', ifname=cls.IFACE_NAME_PY, peer=cls.IFACE_NAME_DIRECTOR, kind='veth')
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)), 1)
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_DIRECTOR)), 1)

		# bring up both ends of the veth pipe
		for iface in [cls.IFACE_NAME_DIRECTOR, cls.IFACE_NAME_PY]:
			idx = ip.link_lookup(ifname=iface)[0]
			ip.link('set', index=idx, state='up')
		
		GLBDirectorTestBase.py_side_mac = dict(ip.link('get', index=ip.link_lookup(ifname=cls.IFACE_NAME_PY))[0]['attrs'])['IFLA_ADDRESS']

		with open('tests/director-config.json', 'wb') as f:
			f.write(json.dumps(cls.get_initial_director_config(), indent=4))

		GLBDirectorTestBase.backend = GLBDirectorTestBase.make_director_backend()
		GLBDirectorTestBase.backend.setup(iface=cls.IFACE_NAME_DIRECTOR)
		GLBDirectorTestBase.backend.setup_pyside(iface=cls.IFACE_NAME_PY)

		# prepare our listener for return traffic from director
		GLBDirectorTestBase.eth_tx = L2ListenSocket(iface=cls.IFACE_NAME_PY, promisc=True)
		GLBDirectorTestBase.kni_tx = GLBDirectorTestBase.backend.kni()

	@classmethod
	def teardown_class(cls):
		ip = IPRoute()

		# tear down the veth pair
		if len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)) > 0:
			ip.link('remove', ifname=cls.IFACE_NAME_DIRECTOR)
		if len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)) > 0:
			ip.link('remove', ifname=cls.IFACE_NAME_DIRECTOR)
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)), 0)
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_DIRECTOR)), 0)

		# clean up the director
		GLBDirectorTestBase.backend.cleanup()

	def sendp(self, *args, **kwargs):
		sendp(*args, **kwargs)

	def wait_for_packet(self, iface, condition, timeout_seconds=5):
		print 'Waiting for packets on', iface.iff, 'with timeout', timeout_seconds
		try:
			with timeout(timeout_seconds):
				while True:
					packet = iface.recv(MTU)
					print repr(packet)
					if condition(packet):
						return packet
		except:
			with open('director-output.txt', 'rb') as d:
				sys.stdout.write('-' * 50 + '\n')
				sys.stdout.write('Output from glb-director-ng\n')
				sys.stdout.write('-' * 50 + '\n')
				sys.stdout.write(d.read())
				sys.stdout.write('-' * 50 + '\n')
			raise

	def _encode_addr(self, addr):
		family = socket.AF_INET
		if ':' in addr:
			family = socket.AF_INET6
		return socket.inet_pton(family, addr)

	def _encode_port(self, port):
		return struct.pack('!H', port)

	def pkt_hash(self, key, src_addr=None, dst_addr=None, src_port=None, dst_port=None, fields=('src_addr',)):
		hash_parts = []
		if 'src_addr' in fields:
			hash_parts.append(self._encode_addr(src_addr))
		if 'dst_addr' in fields:
			hash_parts.append(self._encode_addr(dst_addr))
		if 'src_port' in fields:
			hash_parts.append(self._encode_port(src_port))
		if 'dst_port' in fields:
			hash_parts.append(self._encode_port(dst_port))
		
		assert len(hash_parts) > 0
		hash_data = ''.join(hash_parts)

		hash_bytes = siphash.SipHash_2_4(key, hash_data).digest()
		hash_num, = struct.unpack('<Q', hash_bytes)
		return hash_num

	def pkt_sport(self, key, src_addr=None, dst_addr=None, src_port=None, dst_port=None, fields=('src_addr',)):
		return 0x8000 | ((self.pkt_hash(key, src_addr=src_addr, dst_addr=dst_addr, src_port=src_port, dst_port=dst_port, fields=fields) ^ src_port) & 0x7fff)

	def route_for_packet(self, test_packet, fields):
		field_data = self._fields_for_packet(test_packet)
		table = self._table_for_bind(field_data['dst_addr'], field_data['dst_port'])
		rt = GLBRendezvousTable(table['seed'].decode('hex'))
		hosts = self._hosts_for_table(table)

		hash_key_bytes = self._key_for_bind(field_data['dst_addr'], field_data['dst_port'])
		hash_row = self.pkt_hash(hash_key_bytes, fields=fields, **field_data) & 0xffff

		return rt.forwarding_table_entry(hash_row, hosts)[:2]

	def _hosts_for_table(self, table):
		return map(lambda b: b['ip'], table['backends'])

	def _table_for_bind(self, dest_ip, dest_port):
		config = GLBDirectorTestBase.running_forwarding_config
		for table in config['tables']:
			for bind in table['binds']:
				port_start = bind.get('port_start', bind.get('port', 0))
				port_end = bind.get('port_end', bind.get('port', 0xffff))
				if IPNetwork(dest_ip) in IPNetwork(bind['ip']) and port_start <= dest_port <= port_end:
					return table
		return None

	def _key_for_bind(self, dest_ip, dest_port):
		table = self._table_for_bind(dest_ip, dest_port)
		if table is None:
			return None
		else:
			return table['hash_key'].decode('hex').rjust(16, '\x00')

	def _fields_for_packet(self, packet):
		ether = packet
		assert isinstance(ether, Ether)
		ip = packet.payload
		assert isinstance(ip, IP) or isinstance(ip, IPv6)
		np = ip.payload

		client_ip = ip.src
		server_ip = ip.dst
		client_port = np.sport
		server_port = np.dport
		if isinstance(np, ICMP) or isinstance(np, ICMPv6PacketTooBig):
			# in ICMP packets, they arrive from an intermediary router.
			# we look up the IP packet inside the ICMP packet instead
			icmp = np
			orig_ip = icmp.payload
			client_ip = orig_ip.dst # the packet was us -> client, and got returned
			server_ip = orig_ip.src
			np = orig_ip.payload
			client_port = np.dport
			server_port = np.sport

		return {
			'src_addr': client_ip,
			'dst_addr': server_ip,
			'src_port': client_port,
			'dst_port': server_port,
		}

	def sport_for_packet(self, packet, fields=('src_addr',)):
		field_data = self._fields_for_packet(packet)

		hash_key_bytes = self._key_for_bind(field_data['dst_addr'], field_data['dst_port'])
		return self.pkt_sport(hash_key_bytes, fields=fields, **field_data)
