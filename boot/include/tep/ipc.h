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
};

#define TEP_IPC_READY_LEN  1
#define TEP_IPC_PONG_LEN   2
#define TEP_IPC_HEALTH_LEN 1

/*
 * HEALTH reply: MR0 = TEP_IPC_VERSION, MR1 = boot id, MR2 = health
 * (enum tep_mb_health), MR3 = n services, then n words of
 * id | state << 8 | restarts << 16 (state as enum tep_mb_service_state).
 */
#define TEP_IPC_MAX_SERVICES      8
#define TEP_IPC_HEALTH_REPLY_LEN(n) (4 + (n))

/* Per-service permissions for requests to the root task. */
#define TEP_PERM_HEALTH (1UL << 0)

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
    TEP_SVC_SLOT_COUNT
};

#define TEP_SVC_CNODE_BITS 4

/* Fixed virtual addresses in every service's address space. */
#define TEP_SVC_IPC_BUFFER  0x3ff000UL      /* just below the image at 0x400000 */
#define TEP_SVC_DEVICE_BASE 0x10000000UL    /* the service's device page, if any */
