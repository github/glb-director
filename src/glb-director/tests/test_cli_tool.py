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

from rendezvous_table import GLBRendezvousTable

def assert_equals(a, b, msg=None):
    if msg is None:
        msg = "%r != %r" % (a, b)
    assert a == b, msg
import glob
import json, subprocess, struct, socket, os, tempfile


class TestGLBBinaryCLI():
	def get_example_config(self):
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

	def write_example_config(self):
		config = self.get_example_config()

		with open('tests/test-config.json', 'w') as f:
			f.write(json.dumps(config, indent=4))

	def get_example_table_reference_implementation(self, table_index):
		table_config = self.get_example_config()['tables'][table_index]
		return GLBRendezvousTable(bytes.fromhex(table_config['seed']))

	def get_example_table_hosts(self, table_index):
		table_config = self.get_example_config()['tables'][table_index]
		return list(map(lambda b: b['ip'], table_config['backends']))

	def test_generate_configs(self):
		self.write_example_config()
		
		subprocess.check_call(['cli/glb-director-cli', 'build-config', 'tests/test-config.json', 'tests/test-config.bin'])

		f = open('tests/test-config.bin', 'rb')
		assert_equals(f.read(4), b'GLBD')

		num_table_entries = 0x10000
		max_num_backends = 0x100
		max_num_binds = 0x100

		file_header = struct.unpack('<IIIII', f.read(5*4))
		assert_equals(file_header, (
			0x02, # version
			2, # number of tables
			num_table_entries, # entries per table
			max_num_backends, # max number of backends
			max_num_binds, # max number of binds
		))

		for i, table in enumerate(self.get_example_config()['tables']):
			rt = self.get_example_table_reference_implementation(i)
			hosts = self.get_example_table_hosts(i)

			# validate backends for this table
			num_backends, = struct.unpack('<I', f.read(4))
			assert_equals(num_backends, len(table['backends']))
			backend_to_index = {}

			for bi in range(max_num_backends):
				inet_family, inet_addr, be_state, be_health = struct.unpack('<I16sHH', f.read(16+4+2+2))
				if bi < num_backends:
					# legitimate entry, validate the contents
					backend = table['backends'][bi]
					if ':' in backend['ip']:
						assert_equals(inet_family, 2)
						assert_equals(inet_addr, socket.inet_pton(socket.AF_INET6, backend['ip']))
					else:
						assert_equals(inet_family, 1)
						assert_equals(inet_addr, socket.inet_pton(socket.AF_INET, backend['ip']).ljust(16, b'\x00'))
					assert_equals(be_state, 1)
					assert_equals(be_health, 1)

			# validate binds for this table
			num_binds, = struct.unpack('<I', f.read(4))
			assert_equals(num_binds, len(table['binds']))

			for bi in range(max_num_binds):
				inet_family, inet_addr, ip_bits, bind_port_start, bind_port_end, bind_proto, _ = struct.unpack('<I16sHHHBB', f.read(16+4+4+2+2))
				if bi < num_binds:
					# legitimate entry, validate the contents
					bind = table['binds'][bi]
					if ':' in bind['ip']:
						assert_equals(inet_family, 2)
						assert_equals(inet_addr, socket.inet_pton(socket.AF_INET6, bind['ip']))
						assert_equals(ip_bits, 128)
					else:
						assert_equals(inet_family, 1)
						assert_equals(inet_addr, socket.inet_pton(socket.AF_INET, bind['ip']).ljust(16, b'\x00'))
						assert_equals(ip_bits, 32)
					assert_equals(bind_port_start, bind['port'])
					assert_equals(bind_port_end, bind['port'])
					assert_equals(bind_proto, 6 if bind['proto'] == 'tcp' else 17)

			# validate hash key for source hashing
			assert_equals(f.read(16), bytes.fromhex(table['hash_key']).rjust(16, b'\x00'))

			# validate table entries
			for table_index in range(num_table_entries):
				primary_idx, secondary_idx = struct.unpack('<II', f.read(4*2))
				
				expected_first_ips = rt.forwarding_table_entry(table_index, hosts)
				actual_first_ips = [
					table['backends'][primary_idx]['ip'],
					table['backends'][secondary_idx]['ip']
				]

				assert_equals(actual_first_ips, expected_first_ips[:2])

		# forwarding_table_seed = '49a3d861d661ae5ab06ed9326871a2f5'.decode('hex')
		# table = GLBRendezvousTable(forwarding_table_seed)
		# assert_equals(table.calculate_forwarding_table_row_seed(0x0000).encode('hex'), '491c53a72df4c837')
		# assert_equals(table.calculate_forwarding_table_row_seed(0xffff).encode('hex'), 'f223c0cc65161620')

	def test_atomic_write_no_temp_file_remains(self):
		"""Verify that no temporary file is left behind after a successful build."""
		self.write_example_config()
		output_dir = 'tests'
		output_file = os.path.join(output_dir, 'test-config.bin')

		# Remove output file if it exists
		if os.path.exists(output_file):
			os.unlink(output_file)

		subprocess.check_call([
			'cli/glb-director-cli', 'build-config',
			'tests/test-config.json', output_file
		])

		# The output file should exist
		assert os.path.exists(output_file), "Output file should exist after build"

		# No temp files should remain in the output directory
		tmp_files = glob.glob(os.path.join(output_dir, '.glb-table-*'))
		assert_equals(len(tmp_files), 0,
			"No temporary files should remain after successful build")

	def test_atomic_write_preserves_existing_on_failure(self):
		"""Verify that an existing valid file is not corrupted by a failed build."""
		self.write_example_config()
		output_file = 'tests/test-config.bin'

		# First, create a valid binary
		subprocess.check_call([
			'cli/glb-director-cli', 'build-config',
			'tests/test-config.json', output_file
		])

		# Record the content of the valid file
		with open(output_file, 'rb') as f:
			valid_content = f.read()

		# Now write a bad JSON config (missing backends)
		bad_config = {
			"tables": [{
				"hash_key": "12345678901234561234567890123456",
				"seed": "34567890123456783456789012345678",
				"binds": [
					{ "ip": "1.1.1.1", "proto": "tcp", "port": 80 }
				]
				# missing "backends" key
			}]
		}
		with open('tests/test-bad-config.json', 'w') as f:
			f.write(json.dumps(bad_config, indent=4))
		result = subprocess.call([
			'cli/glb-director-cli', 'build-config',
			'tests/test-bad-config.json', output_file
		])
		assert result != 0, "Build should fail with bad config"

		# The original file should be unchanged
		with open(output_file, 'rb') as f:
			assert_equals(f.read(), valid_content,
				"Original file should not be modified on failure")

		# Clean up
		os.unlink('tests/test-bad-config.json')

	def test_atomic_write_cleans_temp_on_failure(self):
		"""Verify that temp files are cleaned up when the build fails."""
		output_dir = 'tests'

		bad_config = {
			"tables": [{
				"hash_key": "12345678901234561234567890123456",
				"seed": "34567890123456783456789012345678",
				"binds": [
					{ "ip": "1.1.1.1", "proto": "tcp", "port": 80 }
				]
				# missing "backends" key
			}]
		}
		with open('tests/test-bad-config.json', 'w') as f:
			f.write(json.dumps(bad_config, indent=4))

		subprocess.call([
			'cli/glb-director-cli', 'build-config',
			'tests/test-bad-config.json', 'tests/test-bad-output.bin'
		])

		# No temp files should remain
		tmp_files = glob.glob(os.path.join(output_dir, '.glb-table-*'))
		assert_equals(len(tmp_files), 0,
			"No temporary files should remain after failed build")

		# Clean up
		os.unlink('tests/test-bad-config.json')
		if os.path.exists('tests/test-bad-output.bin'):
			os.unlink('tests/test-bad-output.bin')
