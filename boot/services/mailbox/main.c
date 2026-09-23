/*
 * tepOS MailboxService: the NXU <-> tepOS mailbox endpoint.
 *
 * Runs in its own protection domain with exactly: the second PL011 (the
 * serial link to NXU) mapped at TEP_SVC_DEVICE_BASE, that UART's IRQ
 * handler, its notification, and badged send caps to the root task. It
 * holds no key material and cannot reach other services' memory; the only
 * thing it may ask the root task for is health (TEP_PERM_HEALTH).
 *
 * Started by the root task with x0 = IPC buffer address, x1 = service id.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>
#include <tep/mailbox.h>

#include "console.h"
#include "frame.h"
#include "pl011.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS/mailbox";

/* tepOS 0.1.0 */
#define TEPOS_VERSION_WORD ((0u << 16) | (1u << 8) | 0u)

static seL4_Word pongs;
static struct mb_frame req, resp;

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

static void call_root_or_fail(seL4_Word label, seL4_Word len, const char *what)
{
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL, seL4_MessageInfo_new(label, 0, 0, len));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK) {
        svc_fail(what);
    }
}

static void pong(void)
{
    pongs++;
    seL4_SetMR(0, TEP_IPC_VERSION);
    seL4_SetMR(1, pongs);
    call_root_or_fail(TEP_IPC_PONG, TEP_IPC_PONG_LEN, "root task rejected PONG");
}

/*
 * Ask the root task for health. Returns 0 and fills the reply fields, or -1.
 * The root task answers with seL4_Reply at once, so this does not stall.
 */
static int query_health(seL4_Word *boot_id, seL4_Word *health, seL4_Word *n, seL4_Word *entries)
{
    seL4_SetMR(0, TEP_IPC_VERSION);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL,
                                        seL4_MessageInfo_new(TEP_IPC_HEALTH, 0, 0, TEP_IPC_HEALTH_LEN));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK || seL4_GetMR(0) != TEP_IPC_VERSION) {
        return -1;
    }
    *n = seL4_GetMR(3);
    if (*n > TEP_IPC_MAX_SERVICES || *n > TEP_MB_MAX_SERVICES ||
        seL4_MessageInfo_get_length(info) != TEP_IPC_HEALTH_REPLY_LEN(*n)) {
        return -1;
    }
    *boot_id = seL4_GetMR(1);
    *health = seL4_GetMR(2);
    for (seL4_Word i = 0; i < *n; i++) {
        entries[i] = seL4_GetMR(4 + i);
    }
    return 0;
}

static void put32(seL4_Uint8 *p, seL4_Uint32 v)
{
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

/* Fill resp (status and payload) for a well-formed request frame. */
static void handle_request(void)
{
    seL4_Word boot_id, health, n, entries[TEP_IPC_MAX_SERVICES];

    resp.status = TEP_MB_OK;
    resp.payload_len = 0;

    if (req.version != TEP_MB_VERSION) {
        resp.status = TEP_MB_BAD_VERSION;
        return;
    }

    switch (req.command) {
    case TEP_MB_CMD_HELLO:
        if (req.payload_len != 0) {
            resp.status = TEP_MB_BAD_LENGTH;
            return;
        }
        if (query_health(&boot_id, &health, &n, entries) != 0) {
            resp.status = TEP_MB_INTERNAL;
            return;
        }
        resp.payload[0] = TEP_MB_VERSION;
        resp.payload[1] = 0;
        resp.payload[2] = 0;
        resp.payload[3] = 0;
        put32(&resp.payload[4], TEPOS_VERSION_WORD);
        put32(&resp.payload[8], boot_id);
        resp.payload_len = TEP_MB_HELLO_LEN;
        tep_log("HELLO from NXU");
        return;

    case TEP_MB_CMD_GET_HEALTH:
        if (req.payload_len != 0) {
            resp.status = TEP_MB_BAD_LENGTH;
            return;
        }
        if (query_health(&boot_id, &health, &n, entries) != 0) {
            resp.status = TEP_MB_INTERNAL;
            return;
        }
        resp.payload[0] = health;
        resp.payload[1] = n;
        resp.payload[2] = 0;
        resp.payload[3] = 0;
        for (seL4_Word i = 0; i < n; i++) {
            resp.payload[4 + 4 * i] = entries[i] & 0xff;
            resp.payload[5 + 4 * i] = (entries[i] >> 8) & 0xff;
            resp.payload[6 + 4 * i] = (entries[i] >> 16) & 0xff;
            resp.payload[7 + 4 * i] = 0;
        }
        resp.payload_len = TEP_MB_HEALTH_LEN(n);
        return;

    default:
        resp.status = TEP_MB_BAD_COMMAND;
        return;
    }
}

/*
 * Clear the UART interrupt first, then drain: a byte that arrives after the
 * drain raises the interrupt again. Clearing after the drain would wipe the
 * interrupt of such a byte and leave it unread until the next one arrives.
 */
static void service_uart(void)
{
    int c;

    pl011_clear_irq();
    while ((c = pl011_getc()) >= 0) {
        if (!mb_feed((seL4_Uint8)c, &req)) {
            continue;
        }
        if (req.type != TEP_MB_TYPE_REQUEST) {
            continue;   /* tepOS only answers; it never accepts responses */
        }
        handle_request();
        resp.version = TEP_MB_VERSION;
        resp.type = TEP_MB_TYPE_RESPONSE;
        resp.command = req.command;
        resp.request_id = req.request_id;
        mb_send(&resp);
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

    if (pl011_init(TEP_SVC_DEVICE_BASE) != 0) {
        svc_fail("mailbox UART not found (QEMU needs a second -serial)");
    }
    /* Drain anything that arrived while no instance was running. */
    service_uart();
    seL4_IRQHandler_Ack(TEP_SVC_SLOT_IRQ);

    seL4_SetMR(0, TEP_IPC_VERSION);
    call_root_or_fail(TEP_IPC_READY, TEP_IPC_READY_LEN, "root task rejected READY");
    tep_log("listening on serial1");

    for (;;) {
        seL4_Word events;

        seL4_Wait(TEP_SVC_SLOT_NOTIFY, &events);
        if (events & TEP_SVC_EVENT_IRQ) {
            service_uart();
            seL4_IRQHandler_Ack(TEP_SVC_SLOT_IRQ);
        }
        if (events & TEP_SVC_EVENT_PING) {
            pong();
        }
    }
}
