all:
	make -C xdp-root-shim/
	make -C bpf/
	go get github.com/cilium/ebpf
	go get github.com/docopt/docopt-go
	go get github.com/coreos/go-systemd/daemon
	go build -o glb-director-xdp main.go

clean:
	make -C bpf/ clean
	rm -rf glb-director-xdp