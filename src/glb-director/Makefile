#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Default SDK and target, can be overriden by command line or environment
RTE_SDK ?= /usr/share/dpdk
RTE_TARGET ?= x86_64-default-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = glb-director

# all source are stored in SRCS-y
SRCS-y := main.c bind_classifier.c glb_kni.c glb_fwd_config.c \
glb_encap.c glb_encap_dpdk.c glb_control_loop.c glb_processor_loop.c \
siphash24.c glb_director_config.c statsd-client.c shared_opt.c

#WERROR_FLAGS += -Werror

CFLAGS += -O3 -g
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -pie -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1 -fstack-protector-strong
CFLAGS += -DSTATSD
CFLAGS += -DSYSTEMD
#CFLAGS += -DGLB_DUMP_FULL_PACKET
CFLAGS += -I$(SRCDIR)/../ # for <glb-hashing/...>

LDFLAGS += -z relro -z now
LDFLAGS += -ljansson
LDFLAGS += -lsystemd

# disable since libxenstore.so isn't linked properly
CONFIG_RTE_LIBRTE_PMD_XENVIRT = n

include $(RTE_SDK)/mk/rte.extapp.mk
