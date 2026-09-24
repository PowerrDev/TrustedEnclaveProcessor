/*
 * tepOS kernel object allocator on top of untyped memory.
 *
 * A pool is one untyped capability plus a mirror of the kernel's free offset
 * in it (the kernel places a retyped object at the offset rounded up to the
 * object size, then advances past it). The BootInfo untypeds are pools used
 * best-fit by tep_object_alloc(). Services get a private pool carved from
 * them, so everything a service owns can be destroyed at once by revoking
 * that pool, after which the kernel zeroes the memory before reusing it.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

struct tep_pool {
    seL4_CPtr cap;
    seL4_Word paddr;
    seL4_Word size_bits;
    seL4_Word used;         /* mirrored free offset, in bytes */
    int device;
};

/* Object allocator callback, so loaders can allocate from a chosen pool. */
typedef seL4_CPtr (*tep_alloc_fn)(void *ctx, seL4_Word type, seL4_Word size_bits);

int tep_untyped_init(const seL4_BootInfo *bi);

/*
 * Create one kernel object of the given type in a fresh root CNode slot.
 * size_bits only matters for variable-sized objects (CNode: log2 slots,
 * untyped: log2 bytes). Returns the new capability, or seL4_CapNull.
 */
seL4_CPtr tep_object_alloc(seL4_Word type, seL4_Word size_bits);

/* tep_object_alloc() as a tep_alloc_fn; ctx is ignored. */
seL4_CPtr tep_object_alloc_fn(void *ctx, seL4_Word type, seL4_Word size_bits);

/* Same, from one specific pool. */
seL4_CPtr tep_pool_alloc(struct tep_pool *pool, seL4_Word type, seL4_Word size_bits);

/* Carve a new pool of 2^size_bits bytes out of RAM. Returns 0 on success. */
int tep_pool_create(struct tep_pool *pool, seL4_Word size_bits);

/*
 * Destroy every object made from the pool (and every copy of their caps).
 * The root CNode slots that held them are left empty; the caller returns them
 * to the slot allocator.
 */
int tep_pool_revoke(struct tep_pool *pool);

/*
 * The frame capability for the device page holding paddr, made from the
 * device untypeds on first use and the same capability afterwards (callers
 * give services copies of it).
 */
seL4_CPtr tep_device_frame_alloc(seL4_Word paddr);

/* Totals over RAM untypeds, in bytes. */
seL4_Word tep_untyped_ram_total(void);
seL4_Word tep_untyped_ram_used(void);
seL4_Word tep_untyped_ram_count(void);
