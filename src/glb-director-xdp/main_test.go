package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// cliPath returns the path to the glb-director-cli binary.
// Tests expect it to be pre-built (e.g. via `make -C ../glb-director/cli`).
func cliPath() string {
	return filepath.Join("..", "glb-director", "cli", "glb-director-cli")
}

// buildForwardingTable generates a binary forwarding table from a JSON config
// using glb-director-cli. Returns the path to the binary file.
func buildForwardingTable(t *testing.T, config interface{}) string {
	t.Helper()

	jsonFile, err := ioutil.TempFile("", "glb-test-*.json")
	if err != nil {
		t.Fatalf("failed to create temp json file: %v", err)
	}
	defer os.Remove(jsonFile.Name())

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	if _, err := jsonFile.Write(data); err != nil {
		t.Fatalf("failed to write json: %v", err)
	}
	jsonFile.Close()

	binFile, err := ioutil.TempFile("", "glb-test-*.bin")
	if err != nil {
		t.Fatalf("failed to create temp bin file: %v", err)
	}
	binFile.Close()

	cmd := exec.Command(cliPath(), "build-config", jsonFile.Name(), binFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("glb-director-cli build-config failed: %v\noutput: %s", err, output)
	}

	return binFile.Name()
}

// validTableConfig returns a minimal valid forwarding table JSON config.
func validTableConfig() map[string]interface{} {
	return map[string]interface{}{
		"tables": []interface{}{
			map[string]interface{}{
				"hash_key": "12345678901234561234567890123456",
				"seed":     "34567890123456783456789012345678",
				"binds": []interface{}{
					map[string]interface{}{"ip": "1.1.1.1", "proto": "tcp", "port": 80},
				},
				"backends": []interface{}{
					map[string]interface{}{"ip": "1.2.3.4", "state": "active", "healthy": true},
					map[string]interface{}{"ip": "2.3.4.5", "state": "active", "healthy": true},
				},
			},
		},
	}
}

func TestValidateForwardingTableConfig_ValidConfig(t *testing.T) {
	binPath := buildForwardingTable(t, validTableConfig())
	defer os.Remove(binPath)

	err := ValidateForwardingTableConfig(binPath)
	if err != nil {
		t.Errorf("expected valid config to pass validation, got error: %v", err)
	}
}

func TestValidateForwardingTableConfig_NonexistentFile(t *testing.T) {
	err := ValidateForwardingTableConfig("/tmp/nonexistent-glb-test-file.bin")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestValidateForwardingTableConfig_EmptyFile(t *testing.T) {
	f, err := ioutil.TempFile("", "glb-test-empty-*.bin")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.Close()
	defer os.Remove(f.Name())

	err = ValidateForwardingTableConfig(f.Name())
	if err == nil {
		t.Error("expected error for empty file, got nil")
	}
}

func TestValidateForwardingTableConfig_CorruptFile(t *testing.T) {
	f, err := ioutil.TempFile("", "glb-test-corrupt-*.bin")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	// Write garbage data
	f.Write([]byte("this is not a valid forwarding table"))
	f.Close()
	defer os.Remove(f.Name())

	err = ValidateForwardingTableConfig(f.Name())
	if err == nil {
		t.Error("expected error for corrupt file, got nil")
	}
}

func TestValidateForwardingTableConfig_TruncatedFile(t *testing.T) {
	// Build a valid config first, then truncate it
	binPath := buildForwardingTable(t, validTableConfig())
	defer os.Remove(binPath)

	// Read the file and write only half of it back
	data, err := ioutil.ReadFile(binPath)
	if err != nil {
		t.Fatalf("failed to read bin file: %v", err)
	}

	truncFile, err := ioutil.TempFile("", "glb-test-trunc-*.bin")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	truncFile.Write(data[:len(data)/2])
	truncFile.Close()
	defer os.Remove(truncFile.Name())

	err = ValidateForwardingTableConfig(truncFile.Name())
	if err == nil {
		t.Error("expected error for truncated file, got nil")
	}
}

func TestValidateForwardingTableConfig_MultiTableValid(t *testing.T) {
	config := map[string]interface{}{
		"tables": []interface{}{
			map[string]interface{}{
				"hash_key": "12345678901234561234567890123456",
				"seed":     "34567890123456783456789012345678",
				"binds": []interface{}{
					map[string]interface{}{"ip": "1.1.1.1", "proto": "tcp", "port": 80},
				},
				"backends": []interface{}{
					map[string]interface{}{"ip": "1.2.3.4", "state": "active", "healthy": true},
					map[string]interface{}{"ip": "2.3.4.5", "state": "active", "healthy": true},
				},
			},
			map[string]interface{}{
				"hash_key": "12345678901234561234567890123456",
				"seed":     "12345678901234561234567890123456",
				"binds": []interface{}{
					map[string]interface{}{"ip": "1.1.1.2", "proto": "tcp", "port": 443},
				},
				"backends": []interface{}{
					map[string]interface{}{"ip": "4.5.6.7", "state": "active", "healthy": true},
					map[string]interface{}{"ip": "5.6.7.8", "state": "active", "healthy": true},
					map[string]interface{}{"ip": "6.7.8.9", "state": "active", "healthy": true},
				},
			},
		},
	}

	binPath := buildForwardingTable(t, config)
	defer os.Remove(binPath)

	err := ValidateForwardingTableConfig(binPath)
	if err != nil {
		t.Errorf("expected valid multi-table config to pass validation, got error: %v", err)
	}
}
