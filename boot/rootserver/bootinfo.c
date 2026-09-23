/*
 * seL4 BootInfo validation for the tepOS root task.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "bootinfo.h"
#include "runtime.h"

#define PAGE_MASK (BIT(seL4_PageBits) - 1)

static int region_ok(seL4_SlotRegion r, seL4_Word slots)
{
    return r.start <= r.end && r.end <= slots;
}

/* Walk the extra BootInfo headers that follow the BootInfo frame. */
static const char *validate_extra(const seL4_BootInfo *bi)
{
    seL4_Word base = (seL4_Word)bi + BIT(seL4_BootInfoFrameBits);
    seL4_Word off = 0;

    while (off < bi->extraLen) {
        const seL4_BootInfoHeader *h = (const seL4_BootInfoHeader *)(base + off);

        if (bi->extraLen - off < sizeof(*h)) {
            return "truncated extra bootinfo header";
        }
        if (h->len < sizeof(*h) || h->len > bi->extraLen - off) {
            return "bad extra bootinfo header length";
        }
        off += h->len;
    }
    return NULL;
}

const char *tep_bootinfo_validate(const seL4_BootInfo *bi)
{
    if (bi == NULL) {
        return "no bootinfo pointer";
    }
    if ((seL4_Word)bi & PAGE_MASK) {
        return "bootinfo not page aligned";
    }
    if (bi->numNodes == 0 || bi->nodeID >= bi->numNodes) {
        return "bad node id/count";
    }
    if (bi->ipcBuffer == NULL || ((seL4_Word)bi->ipcBuffer & PAGE_MASK)) {
        return "bad IPC buffer";
    }
    if (bi->initThreadCNodeSizeBits == 0 || bi->initThreadCNodeSizeBits >= seL4_WordBits) {
        return "bad initial CNode size";
    }

    seL4_Word slots = BIT(bi->initThreadCNodeSizeBits);

    if (!region_ok(bi->empty, slots) || bi->empty.start == bi->empty.end) {
        return "bad or empty free slot region";
    }
    if (!region_ok(bi->untyped, slots) || bi->untyped.start == bi->untyped.end) {
        return "bad or empty untyped region";
    }
    if (bi->untyped.end - bi->untyped.start > CONFIG_MAX_NUM_BOOTINFO_UNTYPED_CAPS) {
        return "too many untypeds";
    }
    if (!region_ok(bi->userImageFrames, slots) || bi->userImageFrames.start == bi->userImageFrames.end) {
        return "bad user image frame region";
    }
    if (!region_ok(bi->userImagePaging, slots) || !region_ok(bi->sharedFrames, slots) ||
        !region_ok(bi->extraBIPages, slots)) {
        return "bad capability region";
    }

    for (seL4_Word i = 0; i < bi->untyped.end - bi->untyped.start; i++) {
        const seL4_UntypedDesc *ut = &bi->untypedList[i];
        if (ut->sizeBits < seL4_MinUntypedBits || ut->sizeBits > seL4_MaxUntypedBits) {
            return "untyped with invalid size";
        }
    }
    return validate_extra(bi);
}

void tep_bootinfo_report(const seL4_BootInfo *bi)
{
    seL4_Word n_ut = bi->untyped.end - bi->untyped.start;
    seL4_Word ram = 0;
    seL4_Word n_ram = 0;

    for (seL4_Word i = 0; i < n_ut; i++) {
        if (!bi->untypedList[i].isDevice) {
            ram += BIT(bi->untypedList[i].sizeBits);
            n_ram++;
        }
    }

    tep_puts("tepOS: bootinfo at ");
    tep_puthex((seL4_Word)bi);
    tep_puts("\ntepOS: free cslots: ");
    tep_putdec(bi->empty.end - bi->empty.start);
    tep_puts("\ntepOS: untypeds: ");
    tep_putdec(n_ut);
    tep_puts(" (");
    tep_putdec(n_ram);
    tep_puts(" RAM, ");
    tep_putdec(ram >> 10);
    tep_puts(" KiB)\n");
}
