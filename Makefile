mkdeb:
	make -C src/glb-redirect mkdeb
	make -C src/glb-healthcheck mkdeb
	cd src/glb-director && script/cibuild

clean:
	make -C src/glb-redirect clean
	make -C src/glb-healthcheck clean
	make -C src/glb-director clean
	make -C src/glb-director/cli clean
