mkdeb:
	make -C src/glb-redirect mkdeb
	make -C src/glb-healthcheck mkdeb

clean:
	make -C src/glb-redirect clean
