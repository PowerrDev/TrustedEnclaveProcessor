/*
 * tepOS kernel object allocator.
 *
 * The free-offset rule mirrored here is the kernel's (src/object/untyped.c):
 * align up to the object size, place the object, advance past it. An untyped
 * with no children is reset to offset 0 by the kernel on its next retype,
 * which is what tep_pool_revoke() relies on.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "cspace.h"
#include "runtime.h"
#include "untyped.h"

static struct tep_pool uts[CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS];
static seL4_Word nuts;

static seL4_Word align_up(seL4_Word v, seL4_Word align)
{
    return (v + align - 1) & ~(align - 1);
}

/* log2 of the object's size in bytes, or 0 for unknown types. */
static seL4_Word object_size_bits(seL4_Word type, seL4_Word size_bits)
{
    switch (type) {
    case seL4_UntypedObject:
        return size_bits;
    case seL4_TCBObject:
        return seL4_TCBBits;
    case seL4_EndpointObject:
        return seL4_EndpointBits;
    case seL4_NotificationObject:
        return seL4_NotificationBits;
    case seL4_CapTableObject:
        return size_bits + seL4_SlotBits;
    case seL4_ARM_SmallPageObject:
        return seL4_PageBits;
    case seL4_ARM_LargePageObject:
        return seL4_LargePageBits;
    case seL4_ARM_HugePageObject:
        return seL4_HugePageBits;
    case seL4_ARM_PageTableObject:
        return seL4_PageTableBits;
    case seL4_ARM_VSpaceObject:
        return seL4_VSpaceBits;
    default:
        return 0;
    }
}

static int pool_fits(const struct tep_pool *pool, seL4_Word obj_bits)
{
    return pool->size_bits >= obj_bits &&
           align_up(pool->used, BIT(obj_bits)) + BIT(obj_bits) <= BIT(pool->size_bits);
}

int tep_untyped_init(const seL4_BootInfo *bi)
{
    nuts = bi->untyped.end - bi->untyped.start;
    if (nuts > CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS) {
        return -1;
    }
    for (seL4_Word i = 0; i < nuts; i++) {
        uts[i].cap = bi->untyped.start + i;
        uts[i].paddr = bi->untypedList[i].paddr;
        uts[i].size_bits = bi->untypedList[i].sizeBits;
        uts[i].device = bi->untypedList[i].isDevice;
        uts[i].used = 0;
    }
    return 0;
}

seL4_CPtr tep_pool_alloc(struct tep_pool *pool, seL4_Word type, seL4_Word size_bits)
{
    seL4_Word obj_bits = object_size_bits(type, size_bits);

    if (obj_bits == 0 || obj_bits > seL4_MaxUntypedBits || !pool_fits(pool, obj_bits)) {
        return seL4_CapNull;
    }

    seL4_CPtr slot = tep_cslot_alloc();
    if (slot == seL4_CapNull) {
        return seL4_CapNull;
    }

    seL4_Error err = seL4_Untyped_Retype(pool->cap, type, size_bits,
                                         seL4_CapInitThreadCNode, 0, 0, slot, 1);
    if (err != seL4_NoError) {
        tep_log_start();
        tep_puts("untyped: retype failed, error ");
        tep_putdec(err);
        tep_puts("\n");
        tep_cslot_free(slot);
        if (err == seL4_NotEnoughMemory) {
            /* Out of step with the kernel: stop offering this pool. */
            pool->used = BIT(pool->size_bits);
        }
        return seL4_CapNull;
    }
    pool->used = align_up(pool->used, BIT(obj_bits)) + BIT(obj_bits);
    return slot;
}

seL4_CPtr tep_object_alloc(seL4_Word type, seL4_Word size_bits)
{
    seL4_Word obj_bits = object_size_bits(type, size_bits);
    struct tep_pool *best = NULL;

    if (obj_bits == 0) {
        return seL4_CapNull;
    }

    /* Best fit: the smallest RAM untyped with room for the aligned object. */
    for (seL4_Word i = 0; i < nuts; i++) {
        struct tep_pool *ut = &uts[i];
        if (ut->device || !pool_fits(ut, obj_bits)) {
            continue;
        }
        if (best == NULL || ut->size_bits < best->size_bits) {
            best = ut;
        }
    }
    return best != NULL ? tep_pool_alloc(best, type, size_bits) : seL4_CapNull;
}

seL4_CPtr tep_object_alloc_fn(void *ctx, seL4_Word type, seL4_Word size_bits)
{
    (void)ctx;
    return tep_object_alloc(type, size_bits);
}

int tep_pool_create(struct tep_pool *pool, seL4_Word size_bits)
{
    seL4_CPtr cap = tep_object_alloc(seL4_UntypedObject, size_bits);

    if (cap == seL4_CapNull) {
        return -1;
    }
    pool->cap = cap;
    pool->paddr = 0;        /* not tracked for child pools */
    pool->size_bits = size_bits;
    pool->used = 0;
    pool->device = 0;
    return 0;
}

int tep_pool_revoke(struct tep_pool *pool)
{
    if (seL4_CNode_Revoke(seL4_CapInitThreadCNode, pool->cap, seL4_WordBits) != seL4_NoError) {
        return -1;
    }
    pool->used = 0;
    return 0;
}

seL4_CPtr tep_device_frame_alloc(seL4_Word paddr)
{
    for (seL4_Word i = 0; i < nuts; i++) {
        struct tep_pool *ut = &uts[i];
        if (!ut->device || paddr < ut->paddr || paddr - ut->paddr >= BIT(ut->size_bits)) {
            continue;
        }

        seL4_Word off = (paddr - ut->paddr) & ~(BIT(seL4_PageBits) - 1);
        if (ut->used > off) {
            return seL4_CapNull;    /* already handed out */
        }

        /*
         * Retype padding untypeds until the page at `off` is next: each step
         * takes the largest naturally aligned block that ends at or before it.
         */
        while (ut->used < off) {
            seL4_Word bits = seL4_PageBits;
            while (bits + 1 < ut->size_bits &&
                   (ut->used & (BIT(bits + 1) - 1)) == 0 &&
                   ut->used + BIT(bits + 1) <= off) {
                bits++;
            }
            if (tep_pool_alloc(ut, seL4_UntypedObject, bits) == seL4_CapNull) {
                return seL4_CapNull;
            }
        }
        return tep_pool_alloc(ut, seL4_ARM_SmallPageObject, 0);
    }
    return seL4_CapNull;
}

seL4_Word tep_untyped_ram_total(void)
{
    seL4_Word total = 0;

    for (seL4_Word i = 0; i < nuts; i++) {
        if (!uts[i].device) {
            total += BIT(uts[i].size_bits);
        }
    }
    return total;
}

seL4_Word tep_untyped_ram_used(void)
{
    seL4_Word used = 0;

    for (seL4_Word i = 0; i < nuts; i++) {
        if (!uts[i].device) {
            used += uts[i].used;
        }
    }
    return used;
}

seL4_Word tep_untyped_ram_count(void)
{
    seL4_Word n = 0;

    for (seL4_Word i = 0; i < nuts; i++) {
        n += !uts[i].device;
    }
    return n;
}
