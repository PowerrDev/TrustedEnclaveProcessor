/*
 * tepOS service protection domains.
 *
 * Each service runs in its own VSpace and CSpace with its own TCB. Its
 * CSpace holds exactly the capabilities laid out in <tep/ipc.h>: its own
 * notification (wait only) and two badged send capabilities to the root
 * task's endpoint, one for control messages and one registered as its fault
 * endpoint.
 *
 * A service may also own one device: its MMIO page is mapped at
 * TEP_SVC_DEVICE_BASE and its IRQ handler is placed in TEP_SVC_SLOT_IRQ, with
 * the interrupt delivered as TEP_SVC_EVENT_IRQ on the service's notification.
 * The root task keeps the original device frame and IRQ handler capabilities
 * and gives each new instance of the service fresh copies.
 *
 * Every kernel object of a service comes from its private pool, so stopping
 * a service revokes the pool: the kernel destroys all of it and zeroes the
 * memory before it is reused, and a restart starts from nothing.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

#include "untyped.h"

#define TEP_SVC_MAX_SLOTS 256
#define TEP_SVC_DEFAULT_POOL_BITS 18    /* 256 KiB */

enum tep_service_state {
    TEP_SVC_STOPPED,
    TEP_SVC_STARTING,       /* thread running, READY not yet received */
    TEP_SVC_READY,
    TEP_SVC_FAILED,         /* stopped by fault/protocol error/timeout; may restart */
    TEP_SVC_DISABLED,       /* restart budget exhausted */
};

struct tep_service {
    /* Configuration. */
    const char *name;
    seL4_Word id;           /* 1..TEP_BADGE_ID_MASK */
    const void *image;
    seL4_Word image_size;
    seL4_Word priority;
    seL4_Word pool_bits;    /* log2 bytes of private memory; 0 = default */
    int required;           /* tepOS is unhealthy without it */
    seL4_Word perms;        /* TEP_PERM_* requests it may make to the root task */
    seL4_Word dev_paddr;    /* device MMIO page, or 0 */
    seL4_Word dev_irq;      /* device interrupt, or 0 */
    int dma;                /* give it one DMA page (TEP_SVC_DMA_BASE) */

    /* Protection domain (valid while STARTING/READY/FAILED). */
    enum tep_service_state state;
    int have_pool;
    struct tep_pool pool;
    seL4_CPtr slots[TEP_SVC_MAX_SLOTS];     /* root CNode slots to reclaim */
    seL4_Word nslots;
    seL4_CPtr tcb;
    seL4_CPtr cnode;
    seL4_CPtr vspace;
    seL4_CPtr notify;       /* the service's notification (original cap) */
    seL4_CPtr ping;         /* root's signal cap to it, badged TEP_SVC_EVENT_PING */
    seL4_CPtr dev_frame;    /* root-owned device frame, kept across restarts */
    seL4_CPtr irq_handler;  /* root-owned IRQ handler, kept across restarts */
    seL4_Word dma_paddr;    /* physical address of the DMA page, this instance */

    /* Lifecycle bookkeeping, owned by the manager. */
    seL4_Word state_ticks;  /* timer ticks spent in the current state */
    seL4_Word pings_sent;
    seL4_Word pongs;
    seL4_Word restarts;
    const char *last_error;
};

/*
 * Build the protection domain and start the service's thread. root_ep is the
 * root task's endpoint for control messages and faults. Returns NULL on
 * success; on failure everything built so far is torn down, the state is
 * TEP_SVC_FAILED and the error is returned.
 */
const char *tep_service_start(struct tep_service *svc, seL4_CPtr root_ep);

/* Stop the thread and mark the service failed. Resources stay until stop. */
void tep_service_fail(struct tep_service *svc, const char *why);

/* Destroy the protection domain and reclaim its memory and slots. */
void tep_service_stop(struct tep_service *svc);

/* Ask the service to answer with PONG. Never blocks. */
void tep_service_ping(struct tep_service *svc);
