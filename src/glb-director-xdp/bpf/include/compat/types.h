#ifndef _COMPAT_TYPES_H
#define _COMPAT_TYPES_H

/* Provide size_t for kernel headers that reference it (e.g. kcsan-checks.h) */
typedef unsigned long size_t;

#endif /* _COMPAT_TYPES_H */
