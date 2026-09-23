/*
 * tepOS root task: initialisation sequence and main event loop.
 *
 * Validates BootInfo, brings up the runtime (TLS + IPC buffer) and the
 * capability, kernel object and page allocators, starts the diagnostic
 * service in its own protection domain and then serves the root endpoint
 * forever: service control messages, service faults, and (through the bound
 * notification) future asynchronous events. Service lifecycle management
 * and the security services are later phases and are deliberately not
 * reported as initialised here.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>

#include "bootinfo.h"
#include "cspace.h"
#include "runtime.h"
#include "service.h"
#include "untyped.h"
#include "vspace.h"

/* Root task event notification, bound to our TCB; badges name event sources. */
static seL4_CPtr event_ntfn;

/* Root task endpoint: service control messages and service faults. */
static seL4_CPtr root_ep;

extern const char diag_elf_start[], diag_elf_end[];

static struct tep_service services[] = {
    { .name = "diag", .id = 1, .priority = 200 },
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

static struct tep_service *service_by_badge(seL4_Word badge)
{
    seL4_Word id = (badge >> TEP_BADGE_ID_SHIFT) & TEP_BADGE_ID_MASK;

    for (seL4_Word i = 0; i < NSERVICES; i++) {
        if (services[i].id == id) {
            return &services[i];
        }
    }
    return NULL;
}

static const char *fault_name(seL4_Word label)
{
    switch (label) {
    case seL4_Fault_CapFault:
        return "capability fault";
    case seL4_Fault_UnknownSyscall:
        return "unknown syscall";
    case seL4_Fault_UserException:
        return "user exception";
    case seL4_Fault_VMFault:
        return "VM fault";
    default:
        return "fault";
    }
}

/* A service faulted. It stays blocked (no reply) and is stopped. */
static void handle_fault(struct tep_service *svc, seL4_MessageInfo_t info)
{
    seL4_Word label = seL4_MessageInfo_get_label(info);

    tep_log_start();
    tep_puts(svc->name);
    tep_puts(": ");
    tep_puts(fault_name(label));
    if (label == seL4_Fault_VMFault) {
        tep_puts(" at pc ");
        tep_puthex(seL4_GetMR(seL4_VMFault_IP));
        tep_puts(", address ");
        tep_puthex(seL4_GetMR(seL4_VMFault_Addr));
    }
    tep_puts("\n");
    tep_service_fail(svc, "faulted");
}

static enum tep_status check_message(seL4_MessageInfo_t info, seL4_Word len)
{
    if (seL4_MessageInfo_get_length(info) != len || seL4_MessageInfo_get_extraCaps(info) != 0) {
        return TEP_STATUS_BAD_LENGTH;
    }
    if (seL4_GetMR(0) != TEP_IPC_VERSION) {
        return TEP_STATUS_BAD_VERSION;
    }
    return TEP_STATUS_OK;
}

/*
 * A service called the root endpoint. Every path replies exactly once with
 * seL4_Reply, which never blocks the root task.
 */
static void handle_control(struct tep_service *svc, seL4_MessageInfo_t info)
{
    enum tep_status status;
    seL4_Word pongs = 0;

    switch (seL4_MessageInfo_get_label(info)) {
    case TEP_IPC_READY:
        status = check_message(info, TEP_IPC_READY_LEN);
        if (status == TEP_STATUS_OK && svc->state != TEP_SVC_STARTING) {
            status = TEP_STATUS_DENIED;
        }
        break;
    case TEP_IPC_PONG:
        status = check_message(info, TEP_IPC_PONG_LEN);
        pongs = seL4_GetMR(1);
        if (status == TEP_STATUS_OK && (svc->state != TEP_SVC_READY || pongs > svc->pings_sent)) {
            status = TEP_STATUS_DENIED;
        }
        break;
    default:
        status = TEP_STATUS_BAD_LABEL;
        break;
    }
    seL4_Reply(seL4_MessageInfo_new(status, 0, 0, 0));

    if (status != TEP_STATUS_OK) {
        tep_service_fail(svc, "protocol error");
        return;
    }

    tep_log_start();
    tep_puts(svc->name);
    if (svc->state == TEP_SVC_STARTING) {
        svc->state = TEP_SVC_READY;
        tep_puts(": ready\n");
        tep_service_ping(svc);
    } else {
        tep_puts(": pong ");
        tep_putdec(pongs);
        tep_puts(", protocol v");
        tep_putdec(TEP_IPC_VERSION);
        tep_puts("\n");
    }
}

static void __attribute__((noreturn)) event_loop(void)
{
    tep_log("entering main event loop");

    for (;;) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t info = seL4_Recv(root_ep, &badge);

        if (!(badge & TEP_BADGE_SERVICE)) {
            /* Bound notification: no event sources are registered yet. */
            tep_log_start();
            tep_puts("unhandled event, badge ");
            tep_puthex(badge);
            tep_puts("\n");
            continue;
        }

        struct tep_service *svc = service_by_badge(badge);
        if (svc == NULL) {
            /* Unknown badge: we only mint badges for known services. */
            tep_log("message with unknown service badge dropped");
            continue;
        }
        if (badge & TEP_BADGE_FAULT) {
            handle_fault(svc, info);
        } else {
            handle_control(svc, info);
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

    services[0].image = diag_elf_start;
    services[0].image_size = diag_elf_end - diag_elf_start;
    for (seL4_Word i = 0; i < NSERVICES; i++) {
        struct tep_service *svc = &services[i];
        if (tep_service_start(svc, root_ep) == NULL) {
            tep_log_start();
            tep_puts(svc->name);
            tep_puts(": started, service id ");
            tep_putdec(svc->id);
            tep_puts("\n");
        }
    }

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
