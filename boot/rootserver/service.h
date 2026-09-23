/*
 * tepOS service protection domains.
 *
 * Each service runs in its own VSpace and CSpace with its own TCB. Its
 * CSpace holds exactly the capabilities laid out in <tep/ipc.h>: its own
 * notification (wait only) and two badged send capabilities to the root
 * task's endpoint, one for control messages and one registered as its fault
 * endpoint.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

enum tep_service_state {
    TEP_SVC_STOPPED,
    TEP_SVC_STARTING,       /* thread running, READY not yet received */
    TEP_SVC_READY,
    TEP_SVC_FAILED,
};

struct tep_service {
    const char *name;
    seL4_Word id;           /* 1..TEP_BADGE_ID_MASK */
    const void *image;
    seL4_Word image_size;
    seL4_Word priority;

    enum tep_service_state state;
    seL4_CPtr tcb;
    seL4_CPtr cnode;
    seL4_CPtr vspace;
    seL4_CPtr notify;       /* the service's notification (original cap) */
    seL4_CPtr ping;         /* root's signal cap to it, badged TEP_SVC_EVENT_PING */
    seL4_Word pings_sent;
};

/*
 * Build the protection domain and start the service's thread. root_ep is the
 * root task's endpoint for control messages and faults. Returns NULL on
 * success, otherwise a static string; the service is then TEP_SVC_FAILED.
 */
const char *tep_service_start(struct tep_service *svc, seL4_CPtr root_ep);

/* Stop a service's thread after a fault or protocol error. */
void tep_service_fail(struct tep_service *svc, const char *why);

/* Ask the service to answer with PONG. Never blocks. */
void tep_service_ping(struct tep_service *svc);
