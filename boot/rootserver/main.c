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
extern const char mailbox_elf_start[], mailbox_elf_end[];
extern const char crypto_elf_start[], crypto_elf_end[];
extern const char keystore_elf_start[], keystore_elf_end[];
extern const char auth_elf_start[], auth_elf_end[];
extern const char bootpolicy_elf_start[], bootpolicy_elf_end[];

/* QEMU virt: the second pl011 (serial1) is the NXU mailbox link. */
#define MAILBOX_UART_PADDR 0x9040000UL
#define MAILBOX_UART_IRQ   (32 + 8)

/* Makefile TEP_QEMU_DEVICES. Polled, so no IRQs. */
#define CRYPTO_RNG_PADDR   0x0a000000UL     /* virtio-mmio slot 0: virtio-rng */
#define KEYSTORE_BLK_PADDR 0x0a001000UL     /* virtio-mmio slot 8: virtio-blk */
#define FW_CFG_PADDR       0x09020000UL     /* QEMU fw_cfg: the key store's sealing key */

static struct tep_service services[] = {
    { .name = "diag", .id = 1, .priority = 200, .pool_bits = 18, .required = 1 },
    { .name = "mailbox", .id = 2, .priority = 190, .pool_bits = 18, .required = 1,
      .perms = TEP_PERM_HEALTH, .dev_paddr = MAILBOX_UART_PADDR, .dev_irq = MAILBOX_UART_IRQ,
      .uses = BIT(TEP_SVC_ID_CRYPTO) | BIT(TEP_SVC_ID_KEYSTORE) | BIT(TEP_SVC_ID_AUTH) |
              BIT(TEP_SVC_ID_BOOT) },
    { .name = "crypto", .id = TEP_SVC_ID_CRYPTO, .priority = 180, .pool_bits = 18, .required = 1,
      .dev_paddr = CRYPTO_RNG_PADDR, .dma = 1, .serves = 1 },
    { .name = "keystore", .id = TEP_SVC_ID_KEYSTORE, .priority = 170, .pool_bits = 18, .required = 1,
      .serves = 1, .uses = BIT(TEP_SVC_ID_CRYPTO),
      .dev_paddr = KEYSTORE_BLK_PADDR, .dev2_paddr = FW_CFG_PADDR, .dma = 1 },
    /* 1 MiB pool: Argon2id works in 256 KiB. fw_cfg carries the recovery reset flag. */
    { .name = "auth", .id = TEP_SVC_ID_AUTH, .priority = 160, .pool_bits = 20, .required = 1,
      .serves = 1, .uses = BIT(TEP_SVC_ID_CRYPTO) | BIT(TEP_SVC_ID_KEYSTORE),
      .perms = TEP_PERM_TIME, .dev_paddr = FW_CFG_PADDR },
    { .name = "bootpolicy", .id = TEP_SVC_ID_BOOT, .priority = 160, .pool_bits = 18, .required = 1,
      .serves = 1, .uses = BIT(TEP_SVC_ID_KEYSTORE) },
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
    services[1].image = mailbox_elf_start;
    services[1].image_size = mailbox_elf_end - mailbox_elf_start;
    services[2].image = crypto_elf_start;
    services[2].image_size = crypto_elf_end - crypto_elf_start;
    services[3].image = keystore_elf_start;
    services[3].image_size = keystore_elf_end - keystore_elf_start;
    services[4].image = auth_elf_start;
    services[4].image_size = auth_elf_end - auth_elf_start;
    services[5].image = bootpolicy_elf_start;
    services[5].image_size = bootpolicy_elf_end - bootpolicy_elf_start;
    /* Boot id for the mailbox HELLO: the RTC seconds at boot, 0 without it. */
    tep_manager_init(services, NSERVICES, root_ep, err == NULL, err == NULL ? tep_timer_seconds() : 0);
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
