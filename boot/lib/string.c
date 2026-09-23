/*
 * memset/memcpy for freestanding tepOS programs. GCC may emit calls to these
 * for struct initialisers and copies even with -ffreestanding.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stddef.h>

/* Keep GCC from turning these loops back into calls to themselves. */
#define NO_LOOP_PATTERNS __attribute__((optimize("no-tree-loop-distribute-patterns")))

NO_LOOP_PATTERNS void *memset(void *dst, int c, size_t n)
{
    unsigned char *d = dst;

    while (n--) {
        *d++ = (unsigned char)c;
    }
    return dst;
}

NO_LOOP_PATTERNS void *memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;

    while (n--) {
        *d++ = *s++;
    }
    return dst;
}
