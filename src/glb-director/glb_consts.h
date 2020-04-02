/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2019 Roblox Corporation.
 * Copyright (c) 2018 GitHub.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *	 list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *	 this list of conditions and the following disclaimer in the documentation
 *	 and/or other materials provided with the distribution.
 *
 * * Neither the name of the copyright holder nor the names of its
 *	 contributors may be used to endorse or promote products derived from
 *	 this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef __GLB_CONSTS_H__

#define __GLB_CONSTS_H__

#define FILE_FORMAT_VERSION 2
#define MAX_TABLE_ENTRIES 0x10000
#define MAX_NUM_BACKENDS 0x100
#define MAX_NUM_BINDS 0x100

// http://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml

typedef enum {
			  GLB_FAMILY_RESERVED = 0,
			  GLB_FAMILY_IPV4 = 1,
			  GLB_FAMILY_IPV6 = 2,
			  GLB_FAMILY_MAX
} glb_config_addr_family;

const char *glb_addr_family_names[GLB_FAMILY_MAX] =	\
  {"", "IPv4", "IPv6"};

typedef enum {
			  GLB_BACKEND_STATE_FILLING = 0,
			  GLB_BACKEND_STATE_ACTIVE = 1,
			  GLB_BACKEND_STATE_DRAINING_INACTIVE = 2,
			  GLB_BACKEND_STATE_MAX
} glb_config_host_state;

const char *glb_state_names[GLB_BACKEND_STATE_MAX] =	\
  {"Filling", "Active", "Draining_Inactive",};

typedef enum {
			  GLB_BACKEND_HEALTH_DOWN = 0,
			  GLB_BACKEND_HEALTH_UP = 1,
			  GLB_BACKEND_HEALTH_MAX = 2
} glb_config_host_health;

const char *glb_backend_health_status[GLB_BACKEND_HEALTH_MAX] = \
  {"UnHealthy", "Healthy"};

#endif  /* __GLB_CONSTS_H__ */
/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 * End:
 */
