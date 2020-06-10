/*
   SipHash reference C implementation

   Copyright (c) 2012-2014 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com> Copyright (c) 2012-2014 Daniel J. Bernstein
   <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef _GLB_SIPHASH24_H_
#define _GLB_SIPHASH24_H_

#include <stdio.h>
#include <stdint.h>

#if defined(__GNUC__) && __GNUC__ >= 7
 #define GLB_FALL_THROUGH __attribute__ ((fallthrough))
#else
 #define GLB_FALL_THROUGH ((void)0)
#endif /* __GNUC__ >= 7 */

/* default: SipHash-2-4 */
#define cROUNDS 2 // can no longer be changed
#define dROUNDS 4

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

/*
#define U32TO8_LE(p, v)                                                        \
	(p)[0] = (uint8_t)((v));                                               \
	(p)[1] = (uint8_t)((v) >> 8);                                          \
	(p)[2] = (uint8_t)((v) >> 16);                                         \
	(p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
	U32TO8_LE((p), (uint32_t)((v)));                                       \
	U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                                           \
	(((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                    \
	 ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |             \
	 ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |             \
	 ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))
*/

// this is much simpler on any BPF target that runs little endian and supports 64bit,
// which is most x86_64 servers
#include <endian.h>
#define U8TO64_LE(p) htole64(*(const uint64_t *)(p))
#define U64TO8_LE(p, v) *(uint64_t *)(p) = le64toh(v);

#define SIPROUND                                                               \
	do {                                                                   \
		v0 += v1;                                                      \
		v1 = ROTL(v1, 13);                                             \
		v1 ^= v0;                                                      \
		v0 = ROTL(v0, 32);                                             \
		v2 += v3;                                                      \
		v3 = ROTL(v3, 16);                                             \
		v3 ^= v2;                                                      \
		v0 += v3;                                                      \
		v3 = ROTL(v3, 21);                                             \
		v3 ^= v0;                                                      \
		v2 += v1;                                                      \
		v1 = ROTL(v1, 17);                                             \
		v1 ^= v2;                                                      \
		v2 = ROTL(v2, 32);                                             \
	} while (0)

#ifdef DEBUG
#define TRACE                                                                  \
	do {                                                                   \
		printf("(%3d) v0 %08x %08x\n", (int)inlen,                     \
		       (uint32_t)(v0 >> 32), (uint32_t)v0);                    \
		printf("(%3d) v1 %08x %08x\n", (int)inlen,                     \
		       (uint32_t)(v1 >> 32), (uint32_t)v1);                    \
		printf("(%3d) v2 %08x %08x\n", (int)inlen,                     \
		       (uint32_t)(v2 >> 32), (uint32_t)v2);                    \
		printf("(%3d) v3 %08x %08x\n", (int)inlen,                     \
		       (uint32_t)(v3 >> 32), (uint32_t)v3);                    \
	} while (0)
#else
#define TRACE
#endif

#define GLB_SIPHASH_REQUIRED_IN_SIZE (5 * sizeof(uint64_t))

/* A limited version of the original siphash, that is manually constant-looped to allow unrolling and eBPF validation.
 * Requires that the `in` buffer is a buffer of size GLB_SIPHASH_REQUIRED_IN_SIZE that has bytes past `inlen` zeroed out.
 */
static __always_inline int glb_siphash(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k)
{
	/* "somepseudorandomlygeneratedbytes" */
	uint64_t v0 = 0x736f6d6570736575ULL;
	uint64_t v1 = 0x646f72616e646f6dULL;
	uint64_t v2 = 0x6c7967656e657261ULL;
	uint64_t v3 = 0x7465646279746573ULL;
	uint64_t b;
	uint64_t k0 = U8TO64_LE(k);
	uint64_t k1 = U8TO64_LE(k + 8);
	int i;
	v3 ^= k1;
	v2 ^= k0;
	v1 ^= k1;
	v0 ^= k0;

#ifdef DOUBLE
	v1 ^= 0xee;
#endif

	/* copy over input into 5 'rounds'.
	 * we allow up to 9x 32bit ints as input or 4.5x 64bit ints.
	 * the last one ends up with the size added into it, giving us 5 rounds max.
	 */
	uint64_t round_data[5];
	int num_rounds = (inlen / sizeof(uint64_t)) + 1;

	/* we require that the caller zeroes out a buffer of size GLB_SIPHASH_REQUIRED_IN_SIZE
	 * before adding buffer data in. this means we can simply copy over the full buffer here.
	 * this means we can use efficient reads even in BPF mode because the size is fixed.
	 * note that the length byte must also be allowed so the input data cannot use the last byte.
	 */
	if (inlen >= GLB_SIPHASH_REQUIRED_IN_SIZE) return 1;
	const uint64_t *input_chunks = (const uint64_t *)in;

	/* switch to LE consistently as per reference implementation. */
	round_data[0] = htole64(input_chunks[0]);
	round_data[1] = htole64(input_chunks[1]);
	round_data[2] = htole64(input_chunks[2]);
	round_data[3] = htole64(input_chunks[3]);
	round_data[4] = htole64(input_chunks[4]);

	/* the last round needs to contain the input length, other than that it's a normal round */
	round_data[num_rounds - 1] |= ((uint64_t)inlen) << 56;

	/* manually unrolled 5-pass siphash 4-2 loop.
	 * unfortunately, the BPF compiler gets confused too easily and ends up creating unrolled
	 * loops that still contain back-edges that fail verification, even with a constant limit.
	 * instead, since this is a trivial and fixed-size, we just unroll it manually.
	 */
	v3 ^= round_data[0];
	TRACE;
	SIPROUND;
	SIPROUND;
	v0 ^= round_data[0];

	if (num_rounds > 1) {
		v3 ^= round_data[1];
		TRACE;
		SIPROUND;
		SIPROUND;
		v0 ^= round_data[1];
	}

	if (num_rounds > 2) {
		v3 ^= round_data[2];
		TRACE;
		SIPROUND;
		SIPROUND;
		v0 ^= round_data[2];
	}

	if (num_rounds > 3) {
		v3 ^= round_data[3];
		TRACE;
		SIPROUND;
		SIPROUND;
		v0 ^= round_data[3];
	}

	if (num_rounds > 4) {
		v3 ^= round_data[4];
		TRACE;
		SIPROUND;
		SIPROUND;
		v0 ^= round_data[4];
	}

#ifndef DOUBLE
	v2 ^= 0xff;
#else
	v2 ^= 0xee;
#endif

	TRACE;
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
	for (i = 0; i < dROUNDS; ++i)
		SIPROUND;

	b = v0 ^ v1 ^ v2 ^ v3;
	U64TO8_LE(out, b);

#ifdef DOUBLE
	v1 ^= 0xdd;

	TRACE;
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
	for (i = 0; i < dROUNDS; ++i)
		SIPROUND;

	b = v0 ^ v1 ^ v2 ^ v3;
	U64TO8_LE(out + 8, b);
#endif

	return 0;
}

#endif /* _GLB_SIPHASH24_H_ */
