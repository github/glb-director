#ifndef GLB_RTE_ATOMIC_COMPAT_H_
#define GLB_RTE_ATOMIC_COMPAT_H_

#include <stdint.h>

typedef struct {
	volatile int32_t cnt;
} rte_atomic32_t;

typedef struct {
	volatile int64_t cnt;
} rte_atomic64_t;

#define RTE_ATOMIC32_INIT(val)                                                \
	{                                                                     \
		(val)                                                         \
	}

static inline int32_t rte_atomic32_read(const rte_atomic32_t *v)
{
	return __atomic_load_n(&v->cnt, __ATOMIC_SEQ_CST);
}

static inline void rte_atomic32_set(rte_atomic32_t *v, int32_t new_value)
{
	__atomic_store_n(&v->cnt, new_value, __ATOMIC_SEQ_CST);
}

static inline void rte_atomic32_inc(rte_atomic32_t *v)
{
	__atomic_add_fetch(&v->cnt, 1, __ATOMIC_SEQ_CST);
}

static inline int rte_atomic32_dec_and_test(rte_atomic32_t *v)
{
	return __atomic_sub_fetch(&v->cnt, 1, __ATOMIC_SEQ_CST) == 0;
}

static inline int rte_atomic32_test_and_set(rte_atomic32_t *v)
{
	return __atomic_exchange_n(&v->cnt, 1, __ATOMIC_SEQ_CST) == 0;
}

static inline void rte_atomic32_clear(rte_atomic32_t *v)
{
	rte_atomic32_set(v, 0);
}

static inline int64_t rte_atomic64_read(const rte_atomic64_t *v)
{
	return __atomic_load_n(&v->cnt, __ATOMIC_SEQ_CST);
}

static inline void rte_atomic64_set(rte_atomic64_t *v, int64_t new_value)
{
	__atomic_store_n(&v->cnt, new_value, __ATOMIC_SEQ_CST);
}

static inline void rte_atomic64_clear(rte_atomic64_t *v)
{
	rte_atomic64_set(v, 0);
}

static inline void rte_atomic64_inc(rte_atomic64_t *v)
{
	__atomic_add_fetch(&v->cnt, 1, __ATOMIC_SEQ_CST);
}

static inline void rte_atomic64_add(rte_atomic64_t *v, int64_t inc)
{
	__atomic_add_fetch(&v->cnt, inc, __ATOMIC_SEQ_CST);
}

static inline void rte_atomic64_sub(rte_atomic64_t *v, int64_t dec)
{
	__atomic_sub_fetch(&v->cnt, dec, __ATOMIC_SEQ_CST);
}

#endif
