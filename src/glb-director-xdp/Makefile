all:
	make -C xdp-root-shim/
	make -C bpf/
	go build -o glb-director-xdp main.go

clean:
	make -C bpf/ clean
	rm -rf glb-director-xdp