KDIR?=/usr/src/linux-headers-$(shell uname -r)
BUILDDIR?=.

ROOT_DIR:=$(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

DKMS_MOD_VER:=$(shell grep 'PACKAGE_VERSION' dkms.conf | cut -d'=' -f2)

obj-m += ipt_GLBREDIRECT.o

all: lib kmod

kmod:
	$(BUILD_VARS) make -C $(KDIR) M=$(ROOT_DIR) modules

clean: clean-deb
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

# Build the source-only DKMS .deb using the native debian/ packaging and
# debhelper's dh_dkms. This replaces the old `dkms mkdeb` flow, which was
# removed in dkms 3.x (noble). dh_dkms works on both focal (dkms 2.8) and
# noble (dkms 3.x), so a single path covers every supported distro.
#
# debian/changelog is generated here so the package version always tracks
# dkms.conf's PACKAGE_VERSION (which brew2deb's formula rewrites in place).
mkdeb:
	printf '%s (%s) unstable; urgency=low\n\n  * Automated build.\n\n -- GitHub <opensource+glb-director@github.com>  %s\n' \
		'glb-redirect-iptables' '$(DKMS_MOD_VER)' "$$(date -R)" > debian/changelog
	dpkg-buildpackage -us -uc -b -d
	mv ../glb-redirect-iptables-dkms_$(DKMS_MOD_VER)_*.deb $(BUILDDIR)/
	$(MAKE) clean-deb

# Remove build artifacts produced by dpkg-buildpackage in the source dir.
# NOTE: be careful not to delete the checked-in debian/<pkg>.dkms source file.
# Generated debhelper fragments all end in `.debhelper`, so match those
# explicitly rather than globbing `<pkg>.*` (which would match `<pkg>.dkms`).
.PHONY: clean-deb
clean-deb:
	rm -rf debian/glb-redirect-iptables-dkms debian/.debhelper \
		debian/files debian/debhelper-build-stamp debian/changelog \
		debian/glb-redirect-iptables-dkms.substvars \
		debian/glb-redirect-iptables-dkms.debhelper.log \
		debian/glb-redirect-iptables-dkms.*.debhelper
	rm -f ../glb-redirect-iptables-dkms_$(DKMS_MOD_VER)_*.buildinfo \
		../glb-redirect-iptables-dkms_$(DKMS_MOD_VER)_*.changes \
		../glb-redirect-iptables_$(DKMS_MOD_VER)_*.buildinfo \
		../glb-redirect-iptables_$(DKMS_MOD_VER)_*.changes
