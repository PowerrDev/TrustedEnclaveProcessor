/*
 * tepOS root task: initialisation sequence and main event loop.
 *
 * Validates BootInfo, brings up the runtime (TLS + IPC buffer) and the
 * capability, kernel object and page allocators, creates the root task's
 * event notification and blocks on it forever. The service manager, IPC
 * infrastructure and security services are later phases and are
 * deliberately not reported as initialised here.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>

#include "bootinfo.h"
#include "cspace.h"
#include "runtime.h"
#include "untyped.h"
#include "vspace.h"

/* Root task event notification; badge bits will identify event sources. */
static seL4_CPtr event_ntfn;

/*
 * Exercise the allocators end to end before anything depends on them: a slot
 * round trip, and freshly mapped pages that must read as zero and hold data.
 */
static const char *memory_selftest(void)
{
    seL4_Word nfree = tep_cslots_free_count();
    seL4_CPtr slot = tep_cslot_alloc();

    if (slot == seL4_CapNull || tep_cslots_free_count() != nfree - 1) {
        return "cslot allocation failed";
    }
    tep_cslot_free(slot);
    if (tep_cslots_free_count() != nfree) {
        return "cslot free failed";
    }

    const seL4_Word npages = 2;
    volatile seL4_Word *p = tep_pages_alloc(npages);
    const seL4_Word nwords = (npages << seL4_PageBits) / sizeof(seL4_Word);

    if (p == NULL) {
        return "page allocation failed";
    }
    for (seL4_Word i = 0; i < nwords; i++) {
        if (p[i] != 0) {
            return "new page not zeroed";
        }
        p[i] = i ^ 0x7465704f53UL;
    }
    for (seL4_Word i = 0; i < nwords; i++) {
        if (p[i] != (i ^ 0x7465704f53UL)) {
            return "page readback mismatch";
        }
    }
    return NULL;
}

static void __attribute__((noreturn)) event_loop(void)
{
    tep_log("entering main event loop");

    for (;;) {
        seL4_Word badge = 0;

        seL4_Wait(event_ntfn, &badge);

        /* No event sources are registered yet. */
        tep_puts("tepOS: unhandled event, badge ");
        tep_puthex(badge);
        tep_puts("\n");
    }
}

int main(seL4_BootInfo *bi)
{
    const char *err;

    tep_puts("\ntepOS " TEPOS_VERSION "\n");
    tep_puts("Trusted Enclave Processor Operating System\n\n");

    err = tep_bootinfo_validate(bi);
    if (err != NULL) {
        tep_fatal(err);
    }
    tep_log("bootinfo received");
    tep_bootinfo_report(bi);

    if (tep_runtime_init(bi) != 0) {
        tep_fatal("runtime initialization failed");
    }
    tep_log("runtime initialized");

    if (tep_cspace_init(bi) != 0) {
        tep_fatal("capability allocator initialization failed");
    }
    tep_log("capability allocator initialized");

    if (tep_untyped_init(bi) != 0 || tep_vspace_init() != 0) {
        tep_fatal("memory allocator initialization failed");
    }
    tep_log("memory allocator initialized");

    err = memory_selftest();
    if (err != NULL) {
        tep_fatal(err);
    }
    tep_log("memory allocator self-test passed");

    event_ntfn = tep_object_alloc(seL4_NotificationObject, 0);
    if (event_ntfn == seL4_CapNull) {
        tep_fatal("event notification allocation failed");
    }
    tep_log("root task initialized");

    tep_puts("tepOS: free cslots: ");
    tep_putdec(tep_cslots_free_count());
    tep_puts("\ntepOS: RAM used: ");
    tep_putdec(tep_untyped_ram_used());
    tep_puts(" bytes of ");
    tep_putdec(tep_untyped_ram_total() >> 10);
    tep_puts(" KiB in ");
    tep_putdec(tep_untyped_ram_count());
    tep_puts(" untypeds\ntepOS: pages mapped: ");
    tep_putdec(tep_pages_mapped());
    tep_puts("\n");

    event_loop();
}
