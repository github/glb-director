all: glb_encap.o glb_encap_trace.o passer.o tailcall.o

CLANG=clang-9
LLC=llc-9

ifeq ($(KVER),)
KVER=$(shell uname -r)
endif

%.o: %.c
	$(CLANG) -c -O2 -emit-llvm -o - -D__KERNEL__ \
		-Wall \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-Wno-tautological-compare \
		-Wno-unknown-warning-option \
		-Wno-pointer-sign \
		-Werror \
		-include /usr/src/linux-headers-$(KVER:-amd64=-common)/include/linux/kconfig.h \
		-I /usr/src/linux-headers-$(KVER:-amd64=-common)/arch/x86/include/uapi \
		-I /usr/src/linux-headers-$(KVER:-amd64=-common)/arch/x86/include/uapi \
		-I /usr/src/linux-headers-$(KVER:-amd64=-common)/include/uapi \
		-I /usr/src/linux-headers-$(KVER:-amd64=-common)/include/uapi \
		-I /usr/src/linux-headers-$(KVER:-amd64=-common)/include \
		-I /usr/src/linux-headers-$(KVER)/include \
		-I include/ \
		-I ../.. \
		$< > .tmp.ll
	$(LLC) -march=bpf -filetype=obj -o $@ .tmp.ll
	rm .tmp.ll

clean:
	rm -rf *.o
