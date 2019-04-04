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
from netaddr import IPNetwork
from glb_scapy import GLBGUEChainedRouting, GLBGUE

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

class GLBDirectorTestBase():
	DIRECTOR_GUE_PORT = 19523

	IFACE_NAME_PY = 'vglbtest_py'
	IFACE_NAME_DPDK = 'vglbtest_dpdk'
	IFACE_NAME_KNI = 'vglb_kni0'

	eth_tx = None
	kni_tx = None

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

		if hasattr(GLBDirectorTestBase, 'director') and GLBDirectorTestBase.director is not None:
			GLBDirectorTestBase.director.send_signal(signal.SIGUSR1)

	@classmethod
	def get_running_forwarding_config(cls):
		# jsonify so we deep copy
		return json.loads(json.dumps(GLBDirectorTestBase.running_forwarding_config))

	@classmethod
	def setup_class(cls):
		assert os.path.exists('/dev/kni'), "KNI kernel module not loaded"

		initial_config = cls.get_initial_forwarding_config()
		cls.update_running_forwarding_tables(initial_config)

		ip = IPRoute()

		# set up a veth interface from pythong <-> dpdk
		if len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)) == 0:
			ip.link('add', ifname=cls.IFACE_NAME_PY, peer=cls.IFACE_NAME_DPDK, kind='veth')
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)), 1)
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_DPDK)), 1)

		# bring up both ends of the veth pipe
		for iface in [cls.IFACE_NAME_DPDK, cls.IFACE_NAME_PY]:
			idx = ip.link_lookup(ifname=iface)[0]
			ip.link('set', index=idx, state='up')

		GLBDirectorTestBase.py_side_mac = dict(ip.link('get', index=ip.link_lookup(ifname=cls.IFACE_NAME_PY))[0]['attrs'])['IFLA_ADDRESS']

		# launch the glb director, mocking an eth device with the dpdk end of our veth
		with open('tests/director-config.json', 'wb') as f:
			f.write(json.dumps(GLBDirectorTestBase.get_initial_director_config(), indent=4))
		GLBDirectorTestBase.director = subprocess.Popen(
			[
				'./build/glb-director',
				'--vdev=eth_pcap0,iface=' + cls.IFACE_NAME_DPDK,
				'--',
				'--debug',
				'--config-file', './tests/director-config.json',
				'--forwarding-table', './tests/test-tables.bin'
			],
			stdout=open('director-output.txt', 'wba'),
			stderr=subprocess.STDOUT,
		)

		print 'launched as pid', GLBDirectorTestBase.director.pid

		# wait for the kni interface to come up, indicating the app is ready
		try:
			with timeout(10):
				while len(ip.link_lookup(ifname=cls.IFACE_NAME_KNI)) == 0:
					time.sleep(0.1)
		except TimeoutException:
			GLBDirectorTestBase.director.kill()
			GLBDirectorTestBase.director.wait()
			GLBDirectorTestBase.director = None
			raise

		# bring up the KNI interface
		try:
			idx = ip.link_lookup(ifname=cls.IFACE_NAME_KNI)[0]
			ip.link('set', index=idx, state='up')
		except NetlinkError:
			GLBDirectorTestBase.director.kill()
			GLBDirectorTestBase.director.wait()
			GLBDirectorTestBase.director = None
			raise

		# prepare our listener for return traffic from dpdk
		GLBDirectorTestBase.eth_tx = L2ListenSocket(iface=cls.IFACE_NAME_PY, promisc=True)
		GLBDirectorTestBase.kni_tx = L2ListenSocket(iface=cls.IFACE_NAME_KNI, promisc=True)

	@classmethod
	def teardown_class(cls):
		ip = IPRoute()

		# tear down the veth pair
		if len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)) > 0:
			ip.link('remove', ifname=cls.IFACE_NAME_DPDK)
		if len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)) > 0:
			ip.link('remove', ifname=cls.IFACE_NAME_DPDK)
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_PY)), 0)
		assert_equals(len(ip.link_lookup(ifname=cls.IFACE_NAME_DPDK)), 0)

		# clean up the director
		GLBDirectorTestBase.director.terminate()
		time.sleep(0.5)
		GLBDirectorTestBase.director.kill()
		GLBDirectorTestBase.director.wait()
		GLBDirectorTestBase.director = None

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

	def pkt_hash(self, key, src_ip):
		family = socket.AF_INET
		if ':' in src_ip:
			family = socket.AF_INET6
		hash_bytes = siphash.SipHash_2_4(key, socket.inet_pton(family, src_ip)).digest()
		hash_num, = struct.unpack('<Q', hash_bytes)
		return hash_num

	def pkt_sport(self, key, src_ip, src_port):
		return 0x8000 | ((self.pkt_hash(key, src_ip) ^ src_port) & 0x7fff)

	def key_for_bind(self, dest_ip, dest_port):
		config = GLBDirectorTestBase.running_forwarding_config
		for table in config['tables']:
			for bind in table['binds']:
				port_start = bind.get('port_start', bind.get('port', 0))
				port_end = bind.get('port_end', bind.get('port', 0xffff))
				if IPNetwork(dest_ip) in IPNetwork(bind['ip']) and port_start <= dest_port <= port_end:
					return table['hash_key'].decode('hex').rjust(16, '\x00')
		return None

	def sport_for_packet(self, packet):
		ether = packet
		assert isinstance(ether, Ether)
		ip = packet.payload
		assert isinstance(ip, IP) or isinstance(ip, IPv6)
		np = ip.payload

		client_ip = ip.src
		client_port = np.sport
		server_port = np.dport
		if isinstance(np, ICMP) or isinstance(np, ICMPv6PacketTooBig):
			# in ICMP packets, they arrive from an intermediary router.
			# we look up the IP packet inside the ICMP packet instead
			icmp = np
			orig_ip = icmp.payload
			client_ip = orig_ip.dst # the packet was us -> client, and got returned
			np = orig_ip.payload
			client_port = np.dport
			server_port = np.sport

		hash_key_bytes = self.key_for_bind(ip.dst, server_port)
		return self.pkt_sport(hash_key_bytes, client_ip, client_port)
