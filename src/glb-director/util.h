#include <rte_branch_prediction.h>
#include <rte_mbuf.h>

static inline void burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

static inline void burst_free_missed_mbufs(struct rte_mbuf **pkts,
					   unsigned total, unsigned sent)
{
	if (unlikely(sent < total)) {
		burst_free_mbufs(&pkts[sent], total - sent);
	}
}

/*
 * https://github.com/github/glb/blob/master/src/director/util.h
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 *
 * FreeBSD
 */
static inline size_t _strlcpy(char *__restrict dst, const char *__restrict src,
			      size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		/* NUL-terminate dst */
		if (siz != 0)
			*d = '\0';
		while (*s++)
			;
	}

	/* count does not include NUL */
	return (s - src - 1);
}

#ifndef strlcpy
#define strlcpy _strlcpy
#endif
