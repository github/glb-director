/*
 *https://github.com/github/glb/blob/master/src/director/alloc.h
 */

#ifndef ALLOC_H
#define ALLOC_H

#include <limits.h>
#include <stdint.h>
#include <string.h>

#define bitsizeof(x) (CHAR_BIT * sizeof(x))
#define maximum_unsigned_value_of_type(a)                                      \
	(UINTMAX_MAX >> (bitsizeof(uintmax_t) - bitsizeof(a)))
#define unsigned_add_overflows(a, b)                                           \
	((b) > maximum_unsigned_value_of_type(a) - (a))
#define unsigned_mult_overflows(a, b)                                          \
	((a) && (b) > maximum_unsigned_value_of_type(a) / (a))

/*
 * Allocate a buffer of size "len+1", with the final byte set to NUL.
 */
static inline void *mallocz(size_t len)
{
	unsigned char *ret;

	if (unsigned_add_overflows(len, 1))
		return NULL;

	ret = malloc(len + 1);
	if (!ret)
		return NULL;

	ret[len] = 0;
	return ret;
}

/*
 * Duplicate the memory at "src", with length "len", into a new buffer; the
 * result will also have a NUL byte appended, for a total of `len+1` bytes.
 */
static inline void *memdupz(const void *src, size_t len)
{
	void *ret = mallocz(len);
	if (!ret)
		return NULL;
	memcpy(ret, src, len);
	return ret;
}

/*
 * Like normal realloc, but use calloc-like interface so that we can check
 * for integer overflow in the new size.
 */
static inline void *realloc_array(void *src, size_t nmemb, size_t size)
{
	if (unsigned_mult_overflows(nmemb, size))
		return NULL;
	return realloc(src, nmemb * size);
}

#endif /* ALLOC_H */
