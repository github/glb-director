make clean lib
install -d $(pkg-config --variable=xtlibdir xtables)
install -m 0755 libxt_GLBREDIRECT.so $(pkg-config --variable=xtlibdir xtables)
