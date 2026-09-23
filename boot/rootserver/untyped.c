/*
 * tepOS kernel object allocator.
 *
 * The kernel places a retyped object at the untyped's free offset rounded up
 * to the object size, then advances the offset past it (src/object/untyped.c).
 * The same rule is applied here to keep `used` in step with the kernel.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "cspace.h"
#include "runtime.h"
#include "untyped.h"

struct untyped {
    seL4_CPtr cap;
    seL4_Word paddr;
    seL4_Word size_bits;
    seL4_Word used;         /* mirrored free offset, in bytes */
    int device;
};

static struct untyped uts[CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS];
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

seL4_CPtr tep_object_alloc(seL4_Word type, seL4_Word size_bits)
{
    seL4_Word obj_bits = object_size_bits(type, size_bits);
    struct untyped *best = NULL;

    if (obj_bits == 0 || obj_bits > seL4_MaxUntypedBits) {
        return seL4_CapNull;
    }

    /* Best fit: the smallest RAM untyped with room for the aligned object. */
    for (seL4_Word i = 0; i < nuts; i++) {
        struct untyped *ut = &uts[i];
        if (ut->device || ut->size_bits < obj_bits) {
            continue;
        }
        if (align_up(ut->used, BIT(obj_bits)) + BIT(obj_bits) > BIT(ut->size_bits)) {
            continue;
        }
        if (best == NULL || ut->size_bits < best->size_bits) {
            best = ut;
        }
    }
    if (best == NULL) {
        return seL4_CapNull;
    }

    seL4_CPtr slot = tep_cslot_alloc();
    if (slot == seL4_CapNull) {
        return seL4_CapNull;
    }

    seL4_Error err = seL4_Untyped_Retype(best->cap, type, size_bits,
                                         seL4_CapInitThreadCNode, 0, 0, slot, 1);
    if (err != seL4_NoError) {
        tep_puts("tepOS: untyped: retype failed, error ");
        tep_putdec(err);
        tep_puts("\n");
        tep_cslot_free(slot);
        if (err == seL4_NotEnoughMemory) {
            /* Out of step with the kernel: stop offering this untyped. */
            best->used = BIT(best->size_bits);
        }
        return seL4_CapNull;
    }
    best->used = align_up(best->used, BIT(obj_bits)) + BIT(obj_bits);
    return slot;
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
