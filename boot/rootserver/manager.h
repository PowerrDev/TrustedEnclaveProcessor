/*
 * TEPManager: service lifecycle and processor health.
 *
 * Runs inside the root task, which holds the authority to build and destroy
 * service protection domains. It starts services, enforces deadlines with the
 * watchdog tick, restarts failed services within a budget and derives the
 * processor's health from service state.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>
#include <tep/mailbox.h>

#include "service.h"

#define TEP_START_TIMEOUT_TICKS 3   /* READY must arrive within this */
#define TEP_PONG_MISSES_MAX     3   /* unanswered pings before "unresponsive" */
#define TEP_MAX_RESTARTS        3   /* per stability window */
#define TEP_STABLE_TICKS        60  /* READY this long refills the restart budget */

/* Values match enum tep_mb_health, so they go on the wire unchanged. */
enum tep_health {
    TEP_HEALTH_STARTING = TEP_MB_HEALTH_STARTING,   /* not every service has been ready yet */
    TEP_HEALTH_OK       = TEP_MB_HEALTH_OK,         /* every service ready */
    TEP_HEALTH_DEGRADED = TEP_MB_HEALTH_DEGRADED,   /* a service is down but may recover */
    TEP_HEALTH_FAILED   = TEP_MB_HEALTH_FAILED,     /* a required service is disabled */
};

/*
 * have_timer = 0 disables deadlines and restarts: failures are then final.
 * boot_id is reported to services asking for health (TEP_IPC_HEALTH).
 */
void tep_manager_init(struct tep_service *services, seL4_Word n, seL4_CPtr root_ep,
                      int have_timer, seL4_Word boot_id);
void tep_manager_start_all(void);

/* A message on the root endpoint with TEP_BADGE_SERVICE set. */
void tep_manager_message(seL4_Word badge, seL4_MessageInfo_t info);

/* One watchdog tick. */
void tep_manager_tick(void);

enum tep_health tep_manager_health(void);
const char *tep_health_name(enum tep_health health);
