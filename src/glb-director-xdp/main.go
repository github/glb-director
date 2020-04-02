/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2020 GitHub.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"github.com/cilium/ebpf"
	"github.com/coreos/go-systemd/daemon"
	"github.com/docopt/docopt-go"

	"log"
	// "runtime"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

/*
#cgo LDFLAGS: -ljansson

#include <stdint.h>
#include "../glb-hashing/pdnet.h"


// meh
#include <sys/resource.h>
int get_more_map_space() {
	int rc;

	struct rlimit rl = {};
	if ((rc = getrlimit(RLIMIT_MEMLOCK, &rl)) != 0)
		return rc;

	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = rl.rlim_max;

	return setrlimit(RLIMIT_MEMLOCK, &rl);
}

typedef struct {
	uint32_t ipv4;
	struct pdnet_ipv6_addr ipv6;
	uint16_t proto;
	uint16_t port;
} glb_bind;

typedef struct {
	uint8_t src_addr;
	uint8_t dst_addr;
	uint8_t src_port;
	uint8_t dst_port;

	uint16_t reserved; // makes this the size of a config var
} glb_director_hash_fields;

// we don't need this to be atomic for our basic usage here
#define NO_DPDK 1

#include "../glb-director/glb_fwd_config.c"

// cgo borked zero-size trailing arrays, so we return the pointer instead.
struct glb_fwd_config_content_table *_get_tables(struct glb_fwd_config_content *content) {
	return content->tables;
}

// cgo can't do unions
uint32_t _get_bind_ipv4(struct glb_fwd_config_content_table_bind *bind) {
	if (bind->family == FAMILY_IPV4) {
		return bind->ipv4_addr;
	} else {
		return 0;
	}
}
struct pdnet_ipv6_addr _get_bind_ipv6(struct glb_fwd_config_content_table_bind *bind) {
	struct pdnet_ipv6_addr v6;
	if (bind->family == FAMILY_IPV6) {
		memcpy(&v6, bind->ipv6_addr, PDNET_IPV6_ADDR_SIZE);
	} else {
		memset(&v6, 0, PDNET_IPV6_ADDR_SIZE);
	}
	return v6;
}

uint16_t _get_bind_icmp_proto(struct glb_fwd_config_content_table_bind *bind) {
	if (bind->family == FAMILY_IPV4) {
		return PDNET_IP_PROTO_ICMPV4;
	} else {
		return PDNET_IP_PROTO_ICMPV6;
	}
}

// convert to the network byte order we expect
uint16_t _get_bind_port(struct glb_fwd_config_content_table_bind *bind) {
	return htons(bind->port_start);
}

// cgo can't do unions, so pull the IP out
uint32_t _get_backend_ipv4(struct glb_fwd_config_content_table_backend *backend) {
	return backend->ipv4_addr;
}
*/
import "C"

type GLBDirectorConfig struct {
	OutboundGatewayMAC       string `json:"outbound_gateway_mac"`
	OutboundSourceIP         string `json:"outbound_src_ip"`
	ForwardICMPPingResponses bool   `json:"forward_icmp_ping_responses"`
	HashFields               *struct {
		SrcAddr bool `json:"src_addr"`
		DstAddr bool `json:"dst_addr"`
		SrcPort bool `json:"src_port"`
		DstPort bool `json:"dst_port"`
	} `json:"hash_fields"`
	AltHashFields *struct {
		SrcAddr bool `json:"src_addr"`
		DstAddr bool `json:"dst_addr"`
		SrcPort bool `json:"src_port"`
		DstPort bool `json:"dst_port"`
	} `json:"alt_hash_fields"`

	// unused by XDP version: num_worker_queues, flow_paths, lcores
}

func LoadDirectorConfig(filename string) (*GLBDirectorConfig, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &GLBDirectorConfig{}
	err = json.Unmarshal(bytes, c)
	if err != nil {
		return nil, err
	}

	return c, nil
}

type Application struct {
	Config     *GLBDirectorConfig
	Program    *ebpf.Program
	Collection *ebpf.Collection
	TableSpec  *ebpf.MapSpec

	ForwardingTablePath string
}

func boolToC(a bool) C.uchar {
	if a {
		return 1
	} else {
		return 0
	}
}

func (app *Application) SyncConfigMap() {
	configMap := app.Collection.Maps["config_bits"]
	if configMap == nil {
		log.Fatal("config_bits maps not found")
	}

	var data [6]byte

	// 0: gateway mac address
	configKey := uint32(0)
	gatewayMAC, err := net.ParseMAC(app.Config.OutboundGatewayMAC)
	if err != nil {
		log.Fatal(err)
	}
	if len(gatewayMAC) != 6 {
		log.Fatal("Expected 6 byte outbound gateway MAC")
	}
	fmt.Printf("Got gateway MAC: %v [%v]\n", gatewayMAC, app.Config.OutboundGatewayMAC)
	copy(data[:], gatewayMAC)
	configMap.Put(unsafe.Pointer(&configKey), unsafe.Pointer(&data))

	// 1: source ip address
	configKey = uint32(1)
	ip := net.ParseIP(app.Config.OutboundSourceIP).To4()
	if ip == nil {
		log.Fatal("outbound source ip was invalid")
	}
	copy(data[:4], ip[:4])
	fmt.Printf("Got source IP: %v [%v]\n", ip, app.Config.OutboundSourceIP)
	configMap.Put(unsafe.Pointer(&configKey), unsafe.Pointer(&data))

	// 2: forward icmp ping enable
	configKey = uint32(2)
	if app.Config.ForwardICMPPingResponses {
		data[0] = 1
	} else {
		data[0] = 0
	}
	configMap.Put(unsafe.Pointer(&configKey), unsafe.Pointer(&data))

	// 3: glb_director_hash_fields
	configKey = uint32(3)
	hashFields := C.glb_director_hash_fields{src_addr: 1, dst_addr: 0, src_port: 0, dst_port: 0}
	if app.Config.HashFields != nil {
		hashFields.src_addr = boolToC(app.Config.HashFields.SrcAddr)
		hashFields.dst_addr = boolToC(app.Config.HashFields.DstAddr)
		hashFields.src_port = boolToC(app.Config.HashFields.SrcPort)
		hashFields.dst_port = boolToC(app.Config.HashFields.DstPort)
	}
	configMap.Put(unsafe.Pointer(&configKey), unsafe.Pointer(&hashFields))

	// 4: glb_director_hash_fields_alt
	configKey = uint32(4)
	hashFields = C.glb_director_hash_fields{src_addr: 0, dst_addr: 0, src_port: 0, dst_port: 0}
	if app.Config.AltHashFields != nil {
		hashFields.src_addr = boolToC(app.Config.AltHashFields.SrcAddr)
		hashFields.dst_addr = boolToC(app.Config.AltHashFields.DstAddr)
		hashFields.src_port = boolToC(app.Config.AltHashFields.SrcPort)
		hashFields.dst_port = boolToC(app.Config.AltHashFields.DstPort)
	}
	configMap.Put(unsafe.Pointer(&configKey), unsafe.Pointer(&hashFields))
}

func (app *Application) ReloadForwardingTable() {
	fwdConfig := C.create_glb_fwd_config(C.CString(app.ForwardingTablePath))
	defer C.glb_fwd_config_ctx_decref(fwdConfig)

	tableMap4 := app.Collection.Maps["glb_binds"]
	if tableMap4 == nil {
		log.Fatal("Could not load map glb_binds")
	}

	tableArray := app.Collection.Maps["glb_tables"]
	if tableArray == nil {
		log.Fatal("Could not load map tables")
	}

	tableSecretsArray := app.Collection.Maps["glb_table_secrets"]
	if tableSecretsArray == nil {
		log.Fatal("Could not load map table_secrets")
	}

	fmt.Printf("Loaded forwarding table version=%d\n", fwdConfig.raw_config.version)
	fmt.Printf("  num_tables=%d\n", fwdConfig.raw_config.num_tables)
	fmt.Printf("  table_entries=%d\n", fwdConfig.raw_config.table_entries)
	fmt.Printf("  max_num_backends=%d\n", fwdConfig.raw_config.max_num_backends)
	fmt.Printf("  max_num_binds=%d\n", fwdConfig.raw_config.max_num_binds)

	// cgo stopped supporting zero-length trailing fields in structs.
	// instead, let's add the size of the struct to get the "end" of it, and cast it to our array :(
	tableBasePtr := C._get_tables(fwdConfig.raw_config)
	// go needs a fixed size array here, but we slice it to get the real size (and it's not really allocated)
	tables := (*[1 << 30]C.struct_glb_fwd_config_content_table)(unsafe.Pointer(tableBasePtr))[:fwdConfig.raw_config.num_tables]

	for i := uint32(0); i < uint32(fwdConfig.raw_config.num_tables); i++ {
		srcTable := tables[i]
		fmt.Printf("  table at index: %d\n", i)
		fmt.Printf("    num_backends=%d\n", srcTable.num_backends)
		fmt.Printf("    num_binds=%d\n", srcTable.num_binds)

		tableName := fmt.Sprintf("table_%d", i)
		tableSpec := app.TableSpec.Copy()
		tableSpec.Name = tableName

		table, err := ebpf.NewMap(tableSpec)
		if err != nil {
			log.Fatal(err)
		}

		for e := uint32(0); e < C.GLB_FMT_TABLE_ENTRIES; e++ {
			tableEntry := srcTable.entries[e]
			var ips [2]C.uint
			ips[0] = C._get_backend_ipv4(&srcTable.backends[tableEntry.primary])
			ips[1] = C._get_backend_ipv4(&srcTable.backends[tableEntry.secondary])
			if err := table.Put(unsafe.Pointer(&e), unsafe.Pointer(&ips)); err != nil {
				log.Fatal(err)
			}
		}

		// now set the table in the tables array
		tableIndex := uint32(i)
		tableFd := table.FD()
		if err := tableArray.Put(unsafe.Pointer(&tableIndex), unsafe.Pointer(&tableFd)); err != nil {
			log.Fatal(err)
		}

		// similarly, set the secret for the table
		if err := tableSecretsArray.Put(unsafe.Pointer(&tableIndex), unsafe.Pointer(&srcTable.secure_key)); err != nil {
			log.Fatal(err)
		}

		// now we have the new table, map it in to the binds
		for b := uint32(0); b < uint32(srcTable.num_binds); b++ {
			bindEntry := srcTable.binds[b]

			bindKey := C.glb_bind{ipv4: C._get_bind_ipv4(&bindEntry), ipv6: C._get_bind_ipv6(&bindEntry), proto: C.ushort(bindEntry.proto), port: C._get_bind_port(&bindEntry)}
			fmt.Printf("      bind: %v\n", bindKey)
			tableIndex := uint32(i)
			if err := tableMap4.Put(unsafe.Pointer(&bindKey), unsafe.Pointer(&tableIndex)); err != nil {
				log.Fatal(err)
			}

			// also map icmp traffic to the table for echo
			bindKey = C.glb_bind{ipv4: C._get_bind_ipv4(&bindEntry), ipv6: C._get_bind_ipv6(&bindEntry), proto: C._get_bind_icmp_proto(&bindEntry), port: C.ushort(0)}
			fmt.Printf("      bind (ICMP): %v\n", bindKey)
			if err := tableMap4.Put(unsafe.Pointer(&bindKey), unsafe.Pointer(&tableIndex)); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func gracefullReloadByExec() {
	fmt.Printf("Reloading by exec-ing a new version of glb-director-xdp\n")

	// give us a temp working dir for socket comm
	tmpDir, err := ioutil.TempDir("/tmp", "glb-xdp")
	if err != nil {
		log.Fatal(err)
	}

	defer os.RemoveAll(tmpDir)

	// prepare a socket where we can match systemd behaviour, waiting for
	// the newly forked process to send READY.
	readySock := tmpDir + "/ready.sock"
	socketAddr := &net.UnixAddr{
		Name: readySock,
		Net:  "unixgram",
	}
	conn, err := net.ListenUnixgram("unixgram", socketAddr)
	if err != nil {
		log.Fatal(err)
	}

	defer conn.Close()

	// we'll rexec with the same command and args that we were called with.
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"NOTIFY_SOCKET=" + readySock,
	)

	err = cmd.Start()
	if err != nil {
		log.Printf("gracefullReloadByExec: Failed to launch, error: %v", err)
		return
	}

	fmt.Printf("New version of glb-director-xdp launched, waiting for READY signal...\n")

	signalChan := make(chan string, 1)

	go func() {
		// wait for ready
		var buf [1024]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			log.Printf("gracefullReloadByExec: Failed to read from notify socket of new process: %v", err)
			signalChan <- "ERROR"
		} else {
			signalChan <- string(buf[:n])
		}
	}()

	select {
	case readyResponse := <-signalChan:
		if readyResponse == "READY=1" {
			// the new proc has said READY, so we can just exit, we won't be processing packets anymore
			fmt.Printf("New process is READY, goodbye!\n")
			os.Exit(0)
		} else {
			log.Printf("gracefullReloadByExec: Expected READY=1, but got '%v', so assuming failure. Not reloading.", readyResponse)
		}
	case <-time.After(30 * time.Second):
		log.Printf("gracefullReloadByExec: Expected READY=1 from new process, but timed out after 30 seconds. Not reloading.")
	}
}

func main() {
	usage := `GLB Director XDP

	Usage:
	glb-director-xdp --pid-file=<pid_file> --xdp-root-path=<root_path>... [--xdp-root-idx=<root_idx>] --config-file=<config> --forwarding-table=<table> --bpf-program=<obj> [--xdpcap-hook-path=<path>] [--debug]
	glb-director-xdp -h | --help
	
	Options:
	-h --help                     Show this screen.
	--pid-file=<pid_file>         Write our PID out to the specified PID file
	--xdp-root-path=<root_path>   Specify the XDP root array to bind on.
	--xdp-root-idx=<root_idx>     Specify the index in the XDP root array to bind on [default: 2].
	--config-file=<config>        Specify the JSON configuration file.
	--forwarding-table=<table>    Specify the forwarding table which contains binds and L4 servers.
	--bpf-program=<obj>           Specify the path to the GLB encapsulation eBPF program ELF object file.
	--xdpcap-hook-path=<path>     Specify the path to pin an xdpcap compatible hook [default: /sys/fs/bpf/glb-director-xdp-capture-hook].
	--debug                       Enable additional debug output, useful during testing.
	`

	arguments, _ := docopt.Parse(usage, nil, true, "GLB Director XDP", false)

	pidFile := arguments["--pid-file"].(string)

	xdpRootPaths := arguments["--xdp-root-path"].([]string)
	xdpRootIndex, err := strconv.Atoi(arguments["--xdp-root-idx"].(string))
	if err != nil {
		log.Fatal(err)
	}
	configFile := arguments["--config-file"].(string)
	bpfProgram := arguments["--bpf-program"].(string)
	forwardingTableFile := arguments["--forwarding-table"].(string)
	xdpcapHookPath := arguments["--xdpcap-hook-path"].(string)
	// debug := arguments["--debug"].(bool)

	cfg, err := LoadDirectorConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}

	spec, err := ebpf.LoadCollectionSpec(bpfProgram)
	if err != nil {
		log.Fatal(err)
	}

	// inject the template
	tableTemplateSpec := &ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 0x10000,
	}
	tableMapSpec, ok := spec.Maps["glb_tables"]
	if !ok {
		log.Fatal("no map named glb_tables found")
	}
	tableMapSpec.InnerMap = tableTemplateSpec

	// get us some more space for maps
	rc := C.get_more_map_space()
	if rc != 0 {
		log.Fatal("could not increase rlimit to get enough map space")
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}
	defer coll.Close()

	// pin the xdpcap_hook, after removing it
	_, err = os.Stat(xdpcapHookPath)
	if !os.IsNotExist(err) {
		syscall.Unlink(xdpcapHookPath)
	}
	err = coll.Maps["xdpcap_hook"].Pin(xdpcapHookPath)
	if err != nil {
		log.Fatal(err)
	}

	prog := coll.DetachProgram("xdp_glb_director")
	if prog == nil {
		log.Fatal("no program named xdp_glb_director found")
	}
	defer prog.Close()

	app := &Application{
		Config:              cfg,
		Collection:          coll,
		Program:             prog,
		TableSpec:           tableTemplateSpec,
		ForwardingTablePath: forwardingTableFile,
	}

	// load up our entire config/forwarding table before we attach
	// this makes the attach itself the atomic cut-over between reloads.
	app.SyncConfigMap()
	app.ReloadForwardingTable()

	/* now get the pinned map specified and drop our prog in that array */
	for _, xdpRootPath := range xdpRootPaths {
		progArray, err := ebpf.LoadPinnedMap(xdpRootPath)
		if err != nil {
			log.Fatal(err)
		}

		rootIndex := uint32(xdpRootIndex)
		progFd := prog.FD()
		if err := progArray.Put(unsafe.Pointer(&rootIndex), unsafe.Pointer(&progFd)); err != nil {
			log.Fatal(err)
		}
	}

	// and now drop out PID file too
	ioutil.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0664)

	// let systemd know we're done; ignore the response, we don't care if it's not supported
	daemon.SdNotify(false, daemon.SdNotifyReady)

	// wait for a signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	signal.Notify(sigs, syscall.SIGUSR1)

	for {
		sig := <-sigs

		if sig == syscall.SIGUSR1 {
			gracefullReloadByExec()
		} else {
			break
		}
	}
}
