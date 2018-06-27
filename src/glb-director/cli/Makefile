all: glb-director-cli glb-config-check glb-director-pcap glb-director-stub-server

CHECK_SRCS = config_check.c \
	../glb_control_loop.c \
	../glb_fwd_config.c \
	../bind_classifier.c \
	../glb_director_config.c \
	../glb_encap.c \
	../siphash24.c \
	../shared_opt.c

PCAP_SRCS = pcap_mode.c \
	../glb_fwd_config.c \
	../glb_director_config.c \
	../glb_encap.c \
	../cmdline_parse.c \
	../cmdline_parse_etheraddr.c \
	../glb_encap_pcap.c \
	../siphash24.c \
	../shared_opt.c

STUB_SRCS = stub_server.c \
	../glb_fwd_config.c \
	../glb_director_config.c \
	../glb_encap.c \
	../cmdline_parse.c \
	../cmdline_parse_etheraddr.c \
	../glb_encap_pcap.c \
	../siphash24.c \
	../shared_opt.c

CFLAGS += -Wall

WERROR_FLAGS += -Werror

CFLAGS += -O3 -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -pie -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS += -fstack-protector-all
CFLAGS += -DCLI_MODE

LDFLAGS += -z relro -z now
LDFLAGS += -ljansson

glb-director-cli: main.c
	gcc \
		$(CFLAGS) $(LDFLAGS) \
		-I`pwd`/.. \
		main.c \
		../siphash24.c \
		-o glb-director-cli

glb-config-check:
	gcc \
		$(CFLAGS) $(LDFLAGS) \
		$(CHECK_SRCS) \
		-o glb-config-check \
		-I`pwd`/.. \
		-I/usr/include/dpdk \
		-I/usr/include/x86_64-linux-gnu \
		-ldpdk -lpcap \
		-m64 -mssse3

glb-director-pcap:
	gcc \
		$(CFLAGS) $(LDFLAGS) \
		$(PCAP_SRCS) \
		-o glb-director-pcap \
		-I`pwd`/.. \
		-I/usr/include/dpdk \
		-I/usr/include/x86_64-linux-gnu \
		-lpcap \
		-DPCAP_MODE \
		-m64 -mssse3

glb-director-stub-server:
	gcc \
		$(CFLAGS) $(LDFLAGS) \
		$(STUB_SRCS) \
		-o glb-director-stub-server \
		-I`pwd`/.. \
		-I/usr/include/dpdk \
		-I/usr/include/x86_64-linux-gnu \
		-DPCAP_MODE \
		-m64 -mssse3

clean:
	rm -rf glb-director-cli glb-config-check glb-director-pcap glb-director-stub-server
