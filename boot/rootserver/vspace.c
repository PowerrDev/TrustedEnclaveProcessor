/*
 * tepOS root task virtual memory.
 *
 * Frames and page tables come from the untyped allocator. seL4 reports a
 * missing paging level on Page_Map as seL4_FailedLookup; each retry maps one
 * more page table (all AArch64 levels are seL4_ARM_PageTableObject) until the
 * frame fits.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "runtime.h"
#include "untyped.h"
#include "vspace.h"

#define MAX_PT_LEVELS 4

static seL4_Word heap_next;
static seL4_Word npages_mapped;

int tep_vspace_init(void)
{
    heap_next = TEP_HEAP_BASE;
    return 0;
}

int tep_map_frame(seL4_CPtr vspace, seL4_CPtr frame, seL4_Word vaddr,
                  seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,
                  tep_alloc_fn alloc, void *ctx)
{
    for (int i = 0; i <= MAX_PT_LEVELS; i++) {
        seL4_Error err = seL4_ARM_Page_Map(frame, vspace, vaddr, rights, attr);
        if (err == seL4_NoError) {
            return 0;
        }
        if (err != seL4_FailedLookup) {
            return -1;
        }

        seL4_CPtr pt = alloc(ctx, seL4_ARM_PageTableObject, 0);
        if (pt == seL4_CapNull) {
            return -1;
        }
        err = seL4_ARM_PageTable_Map(pt, vspace, vaddr, seL4_ARM_Default_VMAttributes);
        if (err != seL4_NoError) {
            return -1;
        }
    }
    return -1;
}

void *tep_pages_alloc(seL4_Word npages)
{
    seL4_Word base = heap_next;

    if (npages == 0 || npages > (TEP_HEAP_BASE + TEP_HEAP_SIZE - base) >> seL4_PageBits) {
        return NULL;
    }
    for (seL4_Word i = 0; i < npages; i++) {
        seL4_CPtr frame = tep_object_alloc(seL4_ARM_SmallPageObject, 0);
        if (frame == seL4_CapNull ||
            tep_map_frame(seL4_CapInitThreadVSpace, frame, base + (i << seL4_PageBits),
                          seL4_ReadWrite,
                          seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever,
                          tep_object_alloc_fn, NULL) != 0) {
            /* Already-mapped pages stay behind heap_next and are not reused. */
            heap_next = base + ((i + 1) << seL4_PageBits);
            return NULL;
        }
        npages_mapped++;
    }
    heap_next = base + (npages << seL4_PageBits);
    return (void *)base;
}

seL4_Word tep_pages_mapped(void)
{
    return npages_mapped;
}
