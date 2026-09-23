/*
 * tepOS root task: initialisation sequence and main event loop.
 *
 * Validates BootInfo, brings up the runtime (TLS + IPC buffer), the
 * capability, kernel object and page allocators and the watchdog tick, hands
 * the services to TEPManager and then serves the root endpoint forever:
 * service control messages and faults, and watchdog ticks through the bound
 * notification. The security services themselves are later phases.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>

#include "bootinfo.h"
#include "cspace.h"
#include "manager.h"
#include "runtime.h"
#include "service.h"
#include "timer.h"
#include "untyped.h"
#include "vspace.h"

/* Root task event notification, bound to our TCB; badges name event sources. */
static seL4_CPtr event_ntfn;

/* Root task endpoint: service control messages and service faults. */
static seL4_CPtr root_ep;

extern const char diag_elf_start[], diag_elf_end[];

static struct tep_service services[] = {
    { .name = "diag", .id = 1, .priority = 200, .pool_bits = 18, .required = 1 },
};

#define NSERVICES (sizeof(services) / sizeof(services[0]))

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
        seL4_MessageInfo_t info = seL4_Recv(root_ep, &badge);

        if (badge & TEP_BADGE_SERVICE) {
            tep_manager_message(badge, info);
            continue;
        }

        /* Bound notification. */
        if (badge & TEP_EVENT_TIMER) {
            tep_timer_tick();
            tep_manager_tick();
            badge &= ~TEP_EVENT_TIMER;
        }
        if (badge != 0) {
            tep_log_start();
            tep_puts("unhandled event, badge ");
            tep_puthex(badge);
            tep_puts("\n");
        }
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
    root_ep = tep_object_alloc(seL4_EndpointObject, 0);
    if (event_ntfn == seL4_CapNull || root_ep == seL4_CapNull) {
        tep_fatal("root endpoint/notification allocation failed");
    }
    if (seL4_TCB_BindNotification(seL4_CapInitThreadTCB, event_ntfn) != seL4_NoError) {
        tep_fatal("binding event notification failed");
    }
    tep_log("root task initialized");

    /* Without the tick, services still run but hangs go undetected. */
    err = tep_timer_init(event_ntfn, TEP_EVENT_TIMER);
    if (err != NULL) {
        tep_log_start();
        tep_puts("watchdog unavailable (");
        tep_puts(err);
        tep_puts("); service deadlines and restarts disabled\n");
    } else {
        tep_log("watchdog tick running (PL031, 1 s)");
    }

    services[0].image = diag_elf_start;
    services[0].image_size = diag_elf_end - diag_elf_start;
    tep_manager_init(services, NSERVICES, root_ep, err == NULL);
    tep_log("service manager initialized");
    tep_manager_start_all();

    tep_log_start();
    tep_puts("free cslots: ");
    tep_putdec(tep_cslots_free_count());
    tep_puts(", RAM used: ");
    tep_putdec(tep_untyped_ram_used() >> 10);
    tep_puts(" of ");
    tep_putdec(tep_untyped_ram_total() >> 10);
    tep_puts(" KiB\n");

    event_loop();
}
