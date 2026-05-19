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
	@if [ -d /etc/dkms/template-dkms-mkdeb/ ]; then \
		set -e; \
		echo "Using legacy 'dkms mkdeb' workflow"; \
		rm -rf glb-redirect-iptables-dkms-mkdeb; \
		cp -R /etc/dkms/template-dkms-mkdeb/ glb-redirect-iptables-dkms-mkdeb; \
		chown : -R glb-redirect-iptables-dkms-mkdeb; \
		sed -i '/chmod 644/d' glb-redirect-iptables-dkms-mkdeb/Makefile; \
		sed -i '/^Depends:/ s/$$/, pkg-config, libxtables12 | libxtables10, libxtables-dev | libxtables10/' glb-redirect-iptables-dkms-mkdeb/debian/control; \
		sed -i 's/^Maintainer: .*/Maintainer: GitHub <opensource+glb-director@github.com>/' glb-redirect-iptables-dkms-mkdeb/debian/control; \
		dkms mkdeb --source-only; \
		mv ../glb-redirect-iptables-dkms_$(DKMS_MOD_VER)_*.deb $(BUILDDIR)/; \
	elif command -v dh_dkms >/dev/null 2>&1; then \
		set -e; \
		echo "Using modern 'dh-dkms / dpkg-buildpackage' workflow"; \
		$(MAKE) mkdeb-dh-dkms; \
	else \
		echo "Error: neither 'dkms mkdeb' template nor dh-dkms available" >&2; \
		exit 1; \
	fi

# Modern DKMS packaging via dh-dkms + dpkg-buildpackage.
# Produces an "all"-arch source-only DKMS deb that builds the kernel module
# on the installation target (same behavior as the legacy 'dkms mkdeb --source-only').
PKG_NAME := glb-redirect-iptables
PKG_VER  := $(DKMS_MOD_VER)
DH_BUILD := $(BUILDDIR)/dh-dkms-build
SRCDIR_NAME := $(PKG_NAME)-$(PKG_VER)

.PHONY: mkdeb-dh-dkms
mkdeb-dh-dkms:
	rm -rf $(DH_BUILD)
	mkdir -p $(DH_BUILD)/$(SRCDIR_NAME)
	# Copy the kernel module source (everything dkms.conf references).
	cp -a dkms.conf ipt_GLBREDIRECT.c ipt_glbredirect.h Makefile install-ipt.sh \
	    $(DH_BUILD)/$(SRCDIR_NAME)/
	# Generate a minimal debian/ tree that delegates to dh-dkms.
	mkdir -p $(DH_BUILD)/$(SRCDIR_NAME)/debian/source
	echo '3.0 (native)' > $(DH_BUILD)/$(SRCDIR_NAME)/debian/source/format
	printf '%s\n' \
	    'Source: $(PKG_NAME)-dkms' \
	    'Section: misc' \
	    'Priority: optional' \
	    'Maintainer: GitHub <opensource+glb-director@github.com>' \
	    'Build-Depends: debhelper-compat (= 13), dh-dkms' \
	    'Standards-Version: 4.6.0' \
	    '' \
	    'Package: $(PKG_NAME)-dkms' \
	    'Architecture: all' \
	    'Depends: dkms, $${misc:Depends}, pkg-config, libxtables12 | libxtables10, libxtables-dev | libxtables10' \
	    'Description: GLB redirect iptables kernel module (DKMS).' \
	    ' DKMS source for the ipt_GLBREDIRECT iptables target used by GLB.' \
	    > $(DH_BUILD)/$(SRCDIR_NAME)/debian/control
	printf '%s\n' \
	    '$(PKG_NAME)-dkms ($(PKG_VER)) unstable; urgency=medium' \
	    '' \
	    '  * Automated build.' \
	    '' \
	    ' -- GitHub <opensource+glb-director@github.com>  $(shell date -R)' \
	    > $(DH_BUILD)/$(SRCDIR_NAME)/debian/changelog
	# dh_dkms reads the .dkms file and installs it as dkms.conf into
	# /usr/src/<module>-<version>/. The kernel module source files are
	# installed alongside it via debian/install.
	echo 'dkms.conf' > $(DH_BUILD)/$(SRCDIR_NAME)/debian/$(PKG_NAME)-dkms.dkms
	printf '%s\n' \
	    'ipt_GLBREDIRECT.c usr/src/$(SRCDIR_NAME)' \
	    'ipt_glbredirect.h usr/src/$(SRCDIR_NAME)' \
	    'Makefile         usr/src/$(SRCDIR_NAME)' \
	    'install-ipt.sh   usr/src/$(SRCDIR_NAME)' \
	    > $(DH_BUILD)/$(SRCDIR_NAME)/debian/$(PKG_NAME)-dkms.install
	printf '%s\n' \
	    '#!/usr/bin/make -f' \
	    '%:' \
	    '	dh $$@ --with dkms' \
	    'override_dh_auto_build:' \
	    'override_dh_auto_test:' \
	    'override_dh_auto_install:' \
	    > $(DH_BUILD)/$(SRCDIR_NAME)/debian/rules
	chmod +x $(DH_BUILD)/$(SRCDIR_NAME)/debian/rules
	cd $(DH_BUILD)/$(SRCDIR_NAME) && dpkg-buildpackage -us -uc -b
	mv $(DH_BUILD)/$(PKG_NAME)-dkms_$(PKG_VER)_all.deb $(BUILDDIR)/glb-redirect-iptables-dkms_$(PKG_VER)_all.deb
