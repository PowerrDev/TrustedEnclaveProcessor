/*
 * tepOS diagnostic service.
 *
 * The first service that runs in its own seL4 protection domain: its own
 * CSpace, VSpace and TCB, holding only the capabilities listed in
 * <tep/ipc.h>. It answers the root task's ping with PONG, the health check
 * every service will implement. It holds no secrets and no device access.
 *
 * Started by the root task with x0 = IPC buffer address, x1 = service id.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>

#include "console.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS/diag";

static seL4_Word pongs;

/*
 * Give up. A service has no authority over its own TCB, so it faults on
 * purpose: the root task receives the fault on this service's fault
 * endpoint and marks the service failed.
 */
static void __attribute__((noreturn)) svc_fail(const char *msg)
{
    tep_log_start();
    tep_puts("FATAL: ");
    tep_puts(msg);
    tep_puts("\n");
    for (;;) {
        *(volatile seL4_Word *)0 = 0;
    }
}

static void pong(void)
{
    pongs++;
    seL4_SetMR(0, TEP_IPC_VERSION);
    seL4_SetMR(1, pongs);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL,
                                        seL4_MessageInfo_new(TEP_IPC_PONG, 0, 0, TEP_IPC_PONG_LEN));
    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK) {
        svc_fail("root task rejected PONG");
    }
}

int main(seL4_Word ipc_buffer, seL4_Word id)
{
    (void)id;

    if (tep_tls_init() == 0) {
        svc_fail("TLS setup failed");
    }
    seL4_SetIPCBuffer((seL4_IPCBuffer *)ipc_buffer);
    tep_log("started");

    seL4_SetMR(0, TEP_IPC_VERSION);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL,
                                        seL4_MessageInfo_new(TEP_IPC_READY, 0, 0, TEP_IPC_READY_LEN));
    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK) {
        svc_fail("root task rejected READY");
    }

    for (;;) {
        seL4_Word events;

        seL4_Wait(TEP_SVC_SLOT_NOTIFY, &events);
        if (events & TEP_SVC_EVENT_PING) {
            pong();
        }
    }
}
