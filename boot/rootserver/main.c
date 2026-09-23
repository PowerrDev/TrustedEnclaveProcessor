/*
 * tepOS root task: initialisation sequence and main event loop.
 *
 * Phase 1 scope: validate BootInfo, bring up the runtime (TLS + IPC buffer),
 * create the root task's event notification and block on it forever. The
 * capability/memory allocators, service manager, IPC infrastructure and
 * security services are later phases and are deliberately not reported as
 * initialised here.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>

#include "bootinfo.h"
#include "runtime.h"

/* Root task event notification; badge bits will identify event sources. */
static seL4_CPtr event_ntfn;

/*
 * Retype a notification from the smallest RAM untyped that can hold one, into
 * the first free slot. This is a single fixed allocation; the general
 * capability and memory allocators arrive in phase 2.
 */
static const char *create_event_notification(const seL4_BootInfo *bi)
{
    seL4_Word n_ut = bi->untyped.end - bi->untyped.start;
    seL4_Word best = n_ut;

    for (seL4_Word i = 0; i < n_ut; i++) {
        const seL4_UntypedDesc *ut = &bi->untypedList[i];
        if (ut->isDevice || ut->sizeBits < seL4_NotificationBits) {
            continue;
        }
        if (best == n_ut || ut->sizeBits < bi->untypedList[best].sizeBits) {
            best = i;
        }
    }
    if (best == n_ut) {
        return "no RAM untyped for event notification";
    }

    seL4_CPtr slot = bi->empty.start;
    seL4_Error err = seL4_Untyped_Retype(bi->untyped.start + best, seL4_NotificationObject, 0,
                                         seL4_CapInitThreadCNode, 0, 0, slot, 1);
    if (err != seL4_NoError) {
        return "event notification retype failed";
    }
    event_ntfn = slot;
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

    err = create_event_notification(bi);
    if (err != NULL) {
        tep_fatal(err);
    }
    tep_log("root task initialized");

    event_loop();
}
