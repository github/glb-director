KDIR?=/usr/src/linux-headers-$(shell uname -r)
BUILDDIR?=.

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

DKMS_MOD_VER:=$(shell grep 'PACKAGE_VERSION' dkms.conf | cut -d'=' -f2)

obj-m += ipt_GLBREDIRECT.o

all: lib kmod

kmod:
	$(BUILD_VARS) make -C $(KDIR) M=$(ROOT_DIR) modules

clean:
	# we allow the following to fail since in our Docker build env we don't have a valid KDIR
	$(BUILD_VARS) make -C $(KDIR) M=$(ROOT_DIR) clean || true
	rm -rf libxt_GLBREDIRECT.so $(BUILDDIR)/glb-redirect-iptables-dkms_$(DKMS_MOD_VER)_*.deb

.PHONY: lib
lib: libxt_GLBREDIRECT.so

.PHONY: install
install: lib kmod
	install -d $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)
	install -m 0755 libxt_GLBREDIRECT.so $(DESTDIR)$(shell pkg-config --variable=xtlibdir xtables)
	install -d $(DESTDIR)/lib/modules/$(shell uname -r)/updates
	install ipt_GLBREDIRECT.ko $(DESTDIR)/lib/modules/$(shell uname -r)/updates

KSRC=/usr/src/linux-headers-$(shell uname -r)
IPT_CFLAGS=-DPIC -fPIC -Wno-cpp
IPT_LDFLAGS=-lxtables -shared

%.so: %.c
	$(CC) -o $@ $< $(IPT_CFLAGS) $(IPT_LDFLAGS)

mkdeb:
	mkdir -p "$(BUILDDIR)"
	rm -rf "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb"
	cp -R "$(ROOT_DIR)" "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb"
	chown : -R "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb"
	# Works around this bug: https://ubuntuforums.org/showthread.php?t=2234906
	sed -i '/chmod 644/d' "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb/Makefile"
	@if [ -f "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb/debian/control" ]; then \
		sed -i '/^Depends:/ s/$$/, pkg-config, libxtables12 | libxtables10, libxtables-dev | libxtables10/' "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb/debian/control"; \
		sed -i 's/^Maintainer: .*/Maintainer: GitHub <opensource+glb-director@github.com>/' "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb/debian/control"; \
	fi
	@if dkms help 2>/dev/null | grep -q 'mkdeb'; then \
		cd "$(BUILDDIR)/glb-redirect-iptables-dkms-mkdeb" && dkms mkdeb --source-only; \
		mv ../glb-redirect-iptables-dkms_$(DKMS_MOD_VER)_*.deb $(BUILDDIR)/; \
	else \
		echo "dkms mkdeb is not supported on this platform; skipping source deb packaging"; \
	fi
