all:
	make -C xdp-root-shim/
	make -C bpf/
	go build -buildvcs=false -o glb-director-xdp main.go

clean:
	make -C bpf/ clean
	rm -rf glb-director-xdp