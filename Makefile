# Set GLB_SKIP_DPDK_DIRECTOR=1 to skip building the DPDK glb-director package.
# In that mode we still build glb-director-cli (a runtime dep of glb-director-xdp)
# via GLB_CLI_ONLY=1. This is used on distros where DPDK 17 / KNI is unavailable
# (e.g. Ubuntu noble).
GLB_SKIP_DPDK_DIRECTOR ?=

mkdeb:
	make -C src/glb-redirect mkdeb
	make -C src/glb-healthcheck mkdeb
	cd src/glb-director-xdp && script/create-packages
ifeq ($(GLB_SKIP_DPDK_DIRECTOR),)
	cd src/glb-director && script/create-packages
else
	cd src/glb-director && GLB_CLI_ONLY=1 script/create-packages
endif

clean:
	make -C src/glb-redirect clean
	make -C src/glb-healthcheck clean
ifeq ($(GLB_SKIP_DPDK_DIRECTOR),)
	make -C src/glb-director clean
endif
	make -C src/glb-director/cli clean
