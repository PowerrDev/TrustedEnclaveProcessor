/*
 * tepOS internal IPC protocol between the root task and services.
 *
 * This is the seL4 endpoint protocol inside the Trusted Enclave Processor. It
 * is not the NXU mailbox protocol, which is a separate, external transport.
 *
 * Messages carry their request or status in the seL4 message label and fixed,
 * per-label arguments in message registers. Receivers check the exact length
 * for every label and reject anything else with TEP_STATUS_BAD_LENGTH.
 * Capabilities are never transferred in these messages.
 *
 * The root task never blocks on a service: it only replies to services'
 * calls (seL4_Reply does not block) and signals services' notifications.
 * A service that hangs or faults therefore cannot stall the root task.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

#define TEP_IPC_VERSION 1

/*
 * Request labels. They start well above the seL4 fault labels (0..5 on
 * AArch64); faults are also told apart by badge, see below.
 */
enum tep_ipc_label {
    TEP_IPC_READY = 0x100,      /* service -> root: MR0 = TEP_IPC_VERSION */
    TEP_IPC_PONG  = 0x101,      /* service -> root: MR0 = TEP_IPC_VERSION,
                                 * MR1 = pings answered so far */
    TEP_IPC_HEALTH = 0x102,     /* service -> root: MR0 = TEP_IPC_VERSION;
                                 * needs TEP_PERM_HEALTH */
    TEP_IPC_TIME   = 0x103,     /* service -> root: MR0 = TEP_IPC_VERSION;
                                 * needs TEP_PERM_TIME. Reply: MR0 = version,
                                 * MR1 = RTC seconds. The RTC is the host's
                                 * clock: not a trusted time source. */
};

#define TEP_IPC_READY_LEN  1
#define TEP_IPC_PONG_LEN   2
#define TEP_IPC_HEALTH_LEN 1
#define TEP_IPC_TIME_LEN   1
#define TEP_IPC_TIME_REPLY_LEN 2

/*
 * HEALTH reply: MR0 = TEP_IPC_VERSION, MR1 = boot id, MR2 = health
 * (enum tep_mb_health), MR3 = n services, then n words of
 * id | state << 8 | restarts << 16 (state as enum tep_mb_service_state).
 */
#define TEP_IPC_MAX_SERVICES      8
#define TEP_IPC_HEALTH_REPLY_LEN(n) (4 + (n))

/* Per-service permissions for requests to the root task. */
#define TEP_PERM_HEALTH (1UL << 0)
#define TEP_PERM_TIME   (1UL << 1)

/* Bits the root task signals on a service's notification. */
#define TEP_SVC_EVENT_PING (1UL << 0)   /* answer with TEP_IPC_PONG */
#define TEP_SVC_EVENT_IRQ  (1UL << 1)   /* the service's device interrupt fired */

/* Reply labels. */
enum tep_status {
    TEP_STATUS_OK          = 0,
    TEP_STATUS_BAD_LABEL   = 1,     /* unknown request */
    TEP_STATUS_BAD_LENGTH  = 2,     /* wrong message length for the label */
    TEP_STATUS_BAD_VERSION = 3,     /* protocol version mismatch */
    TEP_STATUS_DENIED      = 4,     /* not allowed, or not in this state */
    TEP_STATUS_NOT_FOUND   = 5,     /* no such object for this caller */
    TEP_STATUS_UNAVAILABLE = 6,     /* a service this request needs failed */
    TEP_STATUS_FULL        = 7,     /* no room for another object */
    TEP_STATUS_RETRY_LATER = 8,     /* not now: MR0 = seconds to wait */
    TEP_STATUS_LOCKED      = 9,     /* refused until a recovery reset */
    TEP_STATUS_ROLLBACK    = 10,    /* older than the newest accepted: MR0 = that version */
};

/*
 * Badges on endpoint capabilities.
 *
 * The root task's endpoint receives both service control messages and
 * service faults. TEP_BADGE_SERVICE marks a message from a service, bits
 * 1..8 carry the service id and bit 0 is set on the fault endpoint copy.
 * The root task's bound notification never uses TEP_BADGE_SERVICE.
 */
#define TEP_BADGE_SERVICE   (1UL << 62)
#define TEP_BADGE_FAULT     1UL
#define TEP_BADGE_ID_SHIFT  1
#define TEP_BADGE_ID_MASK   0xffUL

#define TEP_SERVICE_BADGE(id, fault) \
    (TEP_BADGE_SERVICE | ((seL4_Word)(id) << TEP_BADGE_ID_SHIFT) | ((fault) ? TEP_BADGE_FAULT : 0))

/*
 * Badge of a client's capability to a service's endpoint: TEP_BADGE_CLIENT
 * and the client's service id. A server's notification is bound to its TCB,
 * so seL4_Recv on its endpoint also returns TEP_SVC_EVENT_* bits; those never
 * carry TEP_BADGE_CLIENT.
 */
#define TEP_BADGE_CLIENT (1UL << 61)
#define TEP_CLIENT_BADGE(id) (TEP_BADGE_CLIENT | ((seL4_Word)(id) & TEP_BADGE_ID_MASK))

/* Service ids other services address by (the root task's service table). */
#define TEP_SVC_ID_DIAG     1
#define TEP_SVC_ID_MAILBOX  2
#define TEP_SVC_ID_CRYPTO   3
#define TEP_SVC_ID_KEYSTORE 4
#define TEP_SVC_ID_AUTH     5
#define TEP_SVC_ID_BOOT     6

/* Bits signalled on the root task's bound notification (never TEP_BADGE_SERVICE). */
#define TEP_EVENT_TIMER (1UL << 0)

/*
 * Capability layout of every service's CSpace (a single-level CNode; slot 0
 * stays empty so seL4_CapNull never resolves).
 */
enum tep_service_slot {
    TEP_SVC_SLOT_NOTIFY   = 1,  /* the service's notification, wait only */
    TEP_SVC_SLOT_CONTROL  = 2,  /* root task endpoint, badged per service */
    TEP_SVC_SLOT_FAULT    = 3,  /* root task endpoint, badged as fault source */
    TEP_SVC_SLOT_IRQ      = 4,  /* IRQ handler, only for services with a device */
    TEP_SVC_SLOT_ENDPOINT = 5,  /* a server's own endpoint, receive side */
    TEP_SVC_SLOT_SERVER_BASE = 8,   /* + server id: send cap to that server */
};

/* Slot holding a client's capability to server `id` (empty until it runs). */
#define TEP_SVC_SLOT_SERVER(id) (TEP_SVC_SLOT_SERVER_BASE + (id))

#define TEP_SVC_CNODE_BITS 4

/* Fixed virtual addresses in every service's address space. */
#define TEP_SVC_IPC_BUFFER  0x3ff000UL      /* just below the image at 0x400000 */
#define TEP_SVC_DEVICE_BASE 0x10000000UL    /* the service's device page, if any */
#define TEP_SVC_DMA_BASE    0x10001000UL    /* its DMA page, if any */
#define TEP_SVC_DEVICE2_BASE 0x10002000UL   /* its second device page, if any */

/*
 * A service starts with x0 = IPC buffer address, x1 = service id,
 * x2 = physical address of its DMA page (0 if none), x3 = offset of its
 * device's registers within the device page.
 */
