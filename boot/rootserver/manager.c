/*
 * TEPManager: service lifecycle and processor health.
 *
 * Service messages are handled with seL4_Reply only; the manager never calls
 * into a service, so no service can stall it.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <tep/ipc.h>

#include "manager.h"
#include "runtime.h"
#include "timer.h"

static struct tep_service *svcs;
static seL4_Word nsvcs;
static seL4_CPtr root_ep;
static int watchdog;
static seL4_Word boot_id;
static int all_ready_once;
static enum tep_health health = TEP_HEALTH_STARTING;

static void svc_log(const struct tep_service *svc, const char *msg)
{
    tep_log_start();
    tep_puts(svc->name);
    tep_puts(": ");
    tep_puts(msg);
    tep_puts("\n");
}

const char *tep_health_name(enum tep_health h)
{
    switch (h) {
    case TEP_HEALTH_STARTING:
        return "starting";
    case TEP_HEALTH_OK:
        return "ok";
    case TEP_HEALTH_DEGRADED:
        return "degraded";
    default:
        return "failed";
    }
}

static void update_health(void)
{
    int all_ready = 1;
    int required_down = 0;
    enum tep_health h;

    for (seL4_Word i = 0; i < nsvcs; i++) {
        all_ready &= svcs[i].state == TEP_SVC_READY;
        if (svcs[i].required && svcs[i].state == TEP_SVC_DISABLED) {
            required_down = 1;
        }
        if (svcs[i].required && svcs[i].state == TEP_SVC_FAILED && !watchdog) {
            required_down = 1;      /* no restarts without the watchdog */
        }
    }
    if (all_ready) {
        all_ready_once = 1;
        h = TEP_HEALTH_OK;
    } else if (required_down) {
        h = TEP_HEALTH_FAILED;
    } else {
        h = all_ready_once ? TEP_HEALTH_DEGRADED : TEP_HEALTH_STARTING;
    }

    if (h != health) {
        health = h;
        tep_log_start();
        tep_puts("health: ");
        tep_puts(tep_health_name(h));
        tep_puts("\n");
    }
}

static void start(struct tep_service *svc)
{
    const char *err = tep_service_start(svc, root_ep);

    if (err != NULL) {
        tep_log_start();
        tep_puts(svc->name);
        tep_puts(": start failed: ");
        tep_puts(err);
        tep_puts("\n");
        return;
    }
    tep_log_start();
    tep_puts(svc->name);
    tep_puts(": started, service id ");
    tep_putdec(svc->id);
    tep_puts("\n");

    /* Wire it to the servers it uses, and to the clients that use it. */
    for (seL4_Word i = 0; i < nsvcs; i++) {
        tep_service_connect(svc, &svcs[i]);
        tep_service_connect(&svcs[i], svc);
    }
}

void tep_manager_init(struct tep_service *services, seL4_Word n, seL4_CPtr ep,
                      int have_timer, seL4_Word id)
{
    boot_id = id;
    svcs = services;
    nsvcs = n;
    root_ep = ep;
    watchdog = have_timer;
}

void tep_manager_start_all(void)
{
    for (seL4_Word i = 0; i < nsvcs; i++) {
        start(&svcs[i]);
    }
    update_health();
}

enum tep_health tep_manager_health(void)
{
    return health;
}

/* ---- service messages ---------------------------------------------------- */

static struct tep_service *service_by_badge(seL4_Word badge)
{
    seL4_Word id = (badge >> TEP_BADGE_ID_SHIFT) & TEP_BADGE_ID_MASK;

    for (seL4_Word i = 0; i < nsvcs; i++) {
        if (svcs[i].id == id) {
            return &svcs[i];
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

static seL4_Word wire_state(enum tep_service_state state)
{
    switch (state) {
    case TEP_SVC_STARTING:
        return TEP_MB_SVC_STARTING;
    case TEP_SVC_READY:
        return TEP_MB_SVC_READY;
    case TEP_SVC_FAILED:
        return TEP_MB_SVC_FAILED;
    case TEP_SVC_DISABLED:
        return TEP_MB_SVC_DISABLED;
    default:
        return TEP_MB_SVC_STOPPED;
    }
}

/* Answer TEP_IPC_HEALTH with seL4_Reply. The request was already checked. */
static void reply_health(void)
{
    seL4_Word n = nsvcs < TEP_IPC_MAX_SERVICES ? nsvcs : TEP_IPC_MAX_SERVICES;

    seL4_SetMR(0, TEP_IPC_VERSION);
    seL4_SetMR(1, boot_id);
    seL4_SetMR(2, health);
    seL4_SetMR(3, n);
    for (seL4_Word i = 0; i < n; i++) {
        seL4_Word restarts = svcs[i].restarts > 0xff ? 0xff : svcs[i].restarts;
        seL4_SetMR(4 + i, (svcs[i].id & 0xff) | wire_state(svcs[i].state) << 8 | restarts << 16);
    }
    seL4_Reply(seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, TEP_IPC_HEALTH_REPLY_LEN(n)));
}

/* Every path replies exactly once with seL4_Reply, which never blocks. */
static void handle_control(struct tep_service *svc, seL4_MessageInfo_t info)
{
    enum tep_status status;
    seL4_Word label = seL4_MessageInfo_get_label(info);

    switch (label) {
    case TEP_IPC_TIME:
        status = check_message(info, TEP_IPC_TIME_LEN);
        if (status == TEP_STATUS_OK &&
            (!(svc->perms & TEP_PERM_TIME) || svc->state != TEP_SVC_READY)) {
            status = TEP_STATUS_DENIED;
        }
        if (status == TEP_STATUS_OK && !watchdog) {
            status = TEP_STATUS_UNAVAILABLE;    /* no RTC: no time to give */
        }
        if (status == TEP_STATUS_OK) {
            seL4_SetMR(0, TEP_IPC_VERSION);
            seL4_SetMR(1, tep_timer_seconds());
            seL4_Reply(seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, TEP_IPC_TIME_REPLY_LEN));
            return;
        }
        seL4_Reply(seL4_MessageInfo_new(status, 0, 0, 0));
        return;
    case TEP_IPC_HEALTH:
        status = check_message(info, TEP_IPC_HEALTH_LEN);
        if (status == TEP_STATUS_OK && !(svc->perms & TEP_PERM_HEALTH)) {
            status = TEP_STATUS_DENIED;
        }
        if (status == TEP_STATUS_OK && svc->state != TEP_SVC_READY) {
            status = TEP_STATUS_DENIED;
        }
        if (status == TEP_STATUS_OK) {
            reply_health();
            return;
        }
        /* A refused query is not a protocol violation worth a restart. */
        seL4_Reply(seL4_MessageInfo_new(status, 0, 0, 0));
        return;
    case TEP_IPC_READY:
        status = check_message(info, TEP_IPC_READY_LEN);
        if (status == TEP_STATUS_OK && svc->state != TEP_SVC_STARTING) {
            status = TEP_STATUS_DENIED;
        }
        break;
    case TEP_IPC_PONG:
        status = check_message(info, TEP_IPC_PONG_LEN);
        /* The service counts its own pongs; it must agree with ours. */
        if (status == TEP_STATUS_OK &&
            (svc->state != TEP_SVC_READY || svc->pongs >= svc->pings_sent ||
             seL4_GetMR(1) != svc->pongs + 1)) {
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
    if (label == TEP_IPC_READY) {
        svc->state = TEP_SVC_READY;
        svc->state_ticks = 0;
        svc_log(svc, "ready");
        tep_service_ping(svc);
    } else if (++svc->pongs == 1) {
        svc_log(svc, "answering health checks");
    }
}

void tep_manager_message(seL4_Word badge, seL4_MessageInfo_t info)
{
    struct tep_service *svc = service_by_badge(badge);

    if (svc == NULL) {
        /* We only mint badges for known services. */
        tep_log("message with unknown service badge dropped");
        return;
    }
    if (svc->state != TEP_SVC_STARTING && svc->state != TEP_SVC_READY) {
        /* Cannot happen: a stopped service's thread and caps are gone. */
        svc_log(svc, "message while not running dropped");
        return;
    }
    if (badge & TEP_BADGE_FAULT) {
        handle_fault(svc, info);
    } else {
        handle_control(svc, info);
    }
    update_health();
}

/* ---- watchdog -------------------------------------------------------------- */

static void restart_or_disable(struct tep_service *svc)
{
    tep_service_stop(svc);
    if (svc->restarts >= TEP_MAX_RESTARTS) {
        svc->state = TEP_SVC_DISABLED;
        tep_log_start();
        tep_puts(svc->name);
        tep_puts(": disabled after ");
        tep_putdec(svc->restarts);
        tep_puts(" restarts, last error: ");
        tep_puts(svc->last_error ? svc->last_error : "none");
        tep_puts("\n");
        return;
    }
    svc->restarts++;
    tep_log_start();
    tep_puts(svc->name);
    tep_puts(": restarting, attempt ");
    tep_putdec(svc->restarts);
    tep_puts(" of ");
    tep_putdec(TEP_MAX_RESTARTS);
    tep_puts("\n");
    start(svc);
}

void tep_manager_tick(void)
{
    for (seL4_Word i = 0; i < nsvcs; i++) {
        struct tep_service *svc = &svcs[i];

        svc->state_ticks++;
        switch (svc->state) {
        case TEP_SVC_STARTING:
            if (svc->state_ticks > TEP_START_TIMEOUT_TICKS) {
                tep_service_fail(svc, "not ready in time");
            }
            break;
        case TEP_SVC_READY:
            if (svc->pings_sent - svc->pongs > TEP_PONG_MISSES_MAX) {
                tep_service_fail(svc, "unresponsive");
                break;
            }
            if (svc->state_ticks == TEP_STABLE_TICKS && svc->restarts != 0) {
                svc->restarts = 0;
                svc_log(svc, "stable, restart budget refilled");
            }
            tep_service_ping(svc);
            break;
        case TEP_SVC_FAILED:
            /* One tick after failing: a crude backoff before restarting. */
            restart_or_disable(svc);
            break;
        default:
            break;
        }
    }
    update_health();
}
