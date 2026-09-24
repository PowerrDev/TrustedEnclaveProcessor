/*
 * tepOS AuthenticationService: one passcode, checked inside tepOS.
 *
 * The passcode is never stored: only a random 16-byte salt and its Argon2id
 * hash (vendored Monocypher), kept with a failure counter in a KeyStore
 * record (sealed on disk, scoped to this service). Nothing about them leaves
 * this protection domain; callers learn only OK / DENIED / RETRY_LATER /
 * LOCKED.
 *
 * Attempt limits: after TEP_AUTH_MAX_FAILURES wrong attempts in a row the
 * passcode is locked until a recovery reset; before that, from the fifth
 * failure on, each attempt must wait (1 min, 5 min, 15 min, 1 h, 1 h). The
 * counter is saved *before* a passcode is checked, so cutting power during a
 * check does not erase the attempt. The waits use tepOS's RTC, i.e. the
 * host's clock: they are not a defence against the host, and a clock that
 * went backwards is treated as no time having passed.
 *
 * Recovery reset: if tepOS's QEMU is given fw_cfg opt/org.tepos/auth-reset,
 * the passcode and counters are cleared at start. That is only in the hands
 * of whoever runs tepOS's machine; NXU cannot ask for it.
 *
 * Started with x0 = IPC buffer, x1 = service id; fw_cfg is its device page.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>
#include <tep/services.h>

#include "console.h"
#include "fw_cfg.h"
#include "ipc_bytes.h"
#include "monocypher.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS/auth";

#define STATE_SLOT 0
#define STATE_SIZE 64
#define STATE_VERSION 1
#define SALT_SIZE 16
#define HASH_SIZE 32
#define RESET_NAME "opt/org.tepos/auth-reset"

/* Argon2id: 256 KiB, 3 passes. */
#define ARGON2_BLOCKS 256
#define ARGON2_PASSES 3

struct auth_state {
    int set;
    int locked;
    unsigned failures;
    uint64_t last_failure;          /* RTC seconds */
    uint8_t salt[SALT_SIZE];
    uint8_t hash[HASH_SIZE];
};

static uint64_t work_area[ARGON2_BLOCKS * 1024 / 8];
static seL4_Word pongs;

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

static seL4_MessageInfo_t status_reply(enum tep_status status)
{
    return seL4_MessageInfo_new(status, 0, 0, 0);
}

/* Seconds a caller must wait before another attempt after `failures` in a row. */
static uint64_t required_delay(unsigned failures)
{
    static const uint64_t delays[] = { 60, 300, 900, 3600, 3600 };

    if (failures < 5) {
        return 0;
    }
    if (failures - 5 < sizeof(delays) / sizeof(delays[0])) {
        return delays[failures - 5];
    }
    return 3600;
}

static int now(uint64_t *seconds)
{
    seL4_SetMR(0, TEP_IPC_VERSION);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL,
                                        seL4_MessageInfo_new(TEP_IPC_TIME, 0, 0, TEP_IPC_TIME_LEN));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK ||
        seL4_MessageInfo_get_length(info) != TEP_IPC_TIME_REPLY_LEN || seL4_GetMR(0) != TEP_IPC_VERSION) {
        return -1;
    }
    *seconds = seL4_GetMR(1);
    return 0;
}

static int get_random(uint8_t *out, seL4_Word n)
{
    seL4_SetMR(0, n);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_SERVER(TEP_SVC_ID_CRYPTO),
                                        seL4_MessageInfo_new(TEP_CRYPTO_RANDOM, 0, 0, 1));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK || seL4_GetMR(0) != n ||
        seL4_MessageInfo_get_length(info) != 1 + TEP_BYTES_WORDS(n)) {
        return -1;
    }
    ipc_get_bytes(1, out, n);
    return 0;
}

/* ---- state in the KeyStore ------------------------------------------------ */

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;

    for (int i = 7; i >= 0; i--) {
        v = v << 8 | p[i];
    }
    return v;
}

/* Returns 0 (state filled; an unset state if none is stored) or -1. */
static int load_state(struct auth_state *st)
{
    uint8_t buf[STATE_SIZE];

    crypto_wipe(st, sizeof(*st));
    seL4_SetMR(0, STATE_SLOT);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_SERVER(TEP_SVC_ID_KEYSTORE),
                                        seL4_MessageInfo_new(TEP_KS_RECORD_GET, 0, 0, 1));
    seL4_Word label = seL4_MessageInfo_get_label(info);

    if (label == TEP_STATUS_NOT_FOUND) {
        return 0;
    }
    if (label != TEP_STATUS_OK || seL4_GetMR(0) != STATE_SIZE ||
        seL4_MessageInfo_get_length(info) != 1 + TEP_BYTES_WORDS(STATE_SIZE)) {
        return -1;
    }
    ipc_get_bytes(1, buf, STATE_SIZE);
    if (buf[0] != STATE_VERSION) {
        crypto_wipe(buf, sizeof(buf));
        return -1;
    }
    st->set = buf[1];
    st->locked = buf[2];
    st->failures = buf[3];
    st->last_failure = get64(buf + 8);
    for (int i = 0; i < SALT_SIZE; i++) {
        st->salt[i] = buf[16 + i];
    }
    for (int i = 0; i < HASH_SIZE; i++) {
        st->hash[i] = buf[32 + i];
    }
    crypto_wipe(buf, sizeof(buf));
    return 0;
}

/* Returns 0 once the state is sealed on disk, or -1. */
static int save_state(const struct auth_state *st)
{
    uint8_t buf[STATE_SIZE] = { 0 };

    buf[0] = STATE_VERSION;
    buf[1] = (uint8_t)st->set;
    buf[2] = (uint8_t)st->locked;
    buf[3] = (uint8_t)st->failures;
    put64(buf + 8, st->last_failure);
    for (int i = 0; i < SALT_SIZE; i++) {
        buf[16 + i] = st->salt[i];
    }
    for (int i = 0; i < HASH_SIZE; i++) {
        buf[32 + i] = st->hash[i];
    }
    seL4_SetMR(0, STATE_SLOT);
    seL4_SetMR(1, STATE_SIZE);
    seL4_Word words = ipc_put_bytes(2, buf, STATE_SIZE);
    crypto_wipe(buf, sizeof(buf));
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_SERVER(TEP_SVC_ID_KEYSTORE),
                                        seL4_MessageInfo_new(TEP_KS_RECORD_PUT, 0, 0, 2 + words));
    return seL4_MessageInfo_get_label(info) == TEP_STATUS_OK ? 0 : -1;
}

static void derive(const uint8_t *passcode, seL4_Word n, const uint8_t salt[SALT_SIZE],
                   uint8_t hash[HASH_SIZE])
{
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_ID, .nb_blocks = ARGON2_BLOCKS, .nb_passes = ARGON2_PASSES, .nb_lanes = 1,
    };
    crypto_argon2_inputs inputs = {
        .pass = passcode, .salt = salt, .pass_size = (uint32_t)n, .salt_size = SALT_SIZE,
    };

    crypto_argon2(hash, HASH_SIZE, work_area, config, inputs, crypto_argon2_no_extras);
    crypto_wipe(work_area, sizeof(work_area));
}

/* ---- requests ------------------------------------------------------------- */

static seL4_MessageInfo_t retry_later(uint64_t seconds)
{
    seL4_SetMR(0, seconds);
    return seL4_MessageInfo_new(TEP_STATUS_RETRY_LATER, 0, 0, 1);
}

/*
 * Check `passcode` against the stored hash, with the attempt limits.
 * Returns TEP_STATUS_OK on a match; otherwise the reply to send is in *reply.
 */
static enum tep_status check_passcode(struct auth_state *st, const uint8_t *passcode, seL4_Word n,
                                      seL4_MessageInfo_t *reply)
{
    uint64_t t;
    uint8_t hash[HASH_SIZE];

    if (st->locked) {
        *reply = status_reply(TEP_STATUS_LOCKED);
        return TEP_STATUS_LOCKED;
    }
    if (now(&t) != 0) {
        *reply = status_reply(TEP_STATUS_UNAVAILABLE);
        return TEP_STATUS_UNAVAILABLE;
    }
    uint64_t delay = required_delay(st->failures);
    uint64_t elapsed = t >= st->last_failure ? t - st->last_failure : 0;
    if (elapsed < delay) {
        *reply = retry_later(delay - elapsed);
        return TEP_STATUS_RETRY_LATER;
    }

    /* Count the attempt on disk before looking at the passcode. */
    st->failures++;
    st->last_failure = t;
    if (st->failures >= TEP_AUTH_MAX_FAILURES) {
        st->locked = 1;
    }
    if (save_state(st) != 0) {
        *reply = status_reply(TEP_STATUS_UNAVAILABLE);
        return TEP_STATUS_UNAVAILABLE;
    }

    derive(passcode, n, st->salt, hash);
    int match = crypto_verify32(hash, st->hash) == 0;
    crypto_wipe(hash, sizeof(hash));

    if (!match) {
        if (st->locked) {
            tep_log("passcode locked after too many failed attempts");
            *reply = status_reply(TEP_STATUS_LOCKED);
            return TEP_STATUS_LOCKED;
        }
        seL4_SetMR(0, st->failures);
        *reply = seL4_MessageInfo_new(TEP_STATUS_DENIED, 0, 0, 1);
        return TEP_STATUS_DENIED;
    }
    st->failures = 0;
    st->locked = 0;
    st->last_failure = 0;
    if (save_state(st) != 0) {
        tep_log("could not clear the failure counter after a correct passcode");
    }
    return TEP_STATUS_OK;
}

static seL4_MessageInfo_t handle_request(seL4_MessageInfo_t info)
{
    seL4_Word len = seL4_MessageInfo_get_length(info);
    uint8_t buf[2 * TEP_AUTH_PASSCODE_MAX];
    struct auth_state st;
    seL4_MessageInfo_t reply;

    if (seL4_MessageInfo_get_extraCaps(info) != 0) {
        return status_reply(TEP_STATUS_BAD_LENGTH);
    }
    seL4_Word label = seL4_MessageInfo_get_label(info);
    seL4_Word a = seL4_GetMR(0), b = seL4_GetMR(1);

    switch (label) {
    case TEP_AUTH_VERIFY: {
        if (a < TEP_AUTH_PASSCODE_MIN || a > TEP_AUTH_PASSCODE_MAX || len != 1 + TEP_BYTES_WORDS(a)) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        ipc_get_bytes(1, buf, a);
        if (load_state(&st) != 0) {
            reply = status_reply(TEP_STATUS_UNAVAILABLE);
        } else if (!st.set) {
            reply = status_reply(TEP_STATUS_NOT_FOUND);
        } else if (check_passcode(&st, buf, a, &reply) == TEP_STATUS_OK) {
            reply = status_reply(TEP_STATUS_OK);
        }
        break;
    }

    case TEP_AUTH_SET: {
        /* MR0 = old n, MR1 = new n, then old || new. */
        if (a > TEP_AUTH_PASSCODE_MAX || b < TEP_AUTH_PASSCODE_MIN || b > TEP_AUTH_PASSCODE_MAX ||
            len != 2 + TEP_BYTES_WORDS(a + b) || (a != 0 && a < TEP_AUTH_PASSCODE_MIN)) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        ipc_get_bytes(2, buf, a + b);
        if (load_state(&st) != 0) {
            reply = status_reply(TEP_STATUS_UNAVAILABLE);
            break;
        }
        if (st.set && (a == 0 || check_passcode(&st, buf, a, &reply) != TEP_STATUS_OK)) {
            if (a == 0) {
                reply = status_reply(TEP_STATUS_DENIED);
            }
            break;
        }
        if (!st.set && a != 0) {
            reply = status_reply(TEP_STATUS_NOT_FOUND);
            break;
        }
        if (get_random(st.salt, SALT_SIZE) != 0) {
            reply = status_reply(TEP_STATUS_UNAVAILABLE);
            break;
        }
        derive(buf + a, b, st.salt, st.hash);
        st.set = 1;
        st.failures = 0;
        st.locked = 0;
        st.last_failure = 0;
        reply = status_reply(save_state(&st) == 0 ? TEP_STATUS_OK : TEP_STATUS_UNAVAILABLE);
        break;
    }

    case TEP_AUTH_STATUS: {
        uint64_t t = 0, wait = 0;
        if (len != 0) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        if (load_state(&st) != 0) {
            return status_reply(TEP_STATUS_UNAVAILABLE);
        }
        if (st.set && !st.locked && now(&t) == 0) {
            uint64_t delay = required_delay(st.failures);
            uint64_t elapsed = t >= st.last_failure ? t - st.last_failure : 0;
            wait = elapsed < delay ? delay - elapsed : 0;
        }
        seL4_SetMR(0, (seL4_Word)st.set);
        seL4_SetMR(1, st.failures);
        seL4_SetMR(2, (seL4_Word)st.locked);
        seL4_SetMR(3, wait);
        reply = seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, TEP_AUTH_STATUS_LEN);
        break;
    }

    default:
        return status_reply(TEP_STATUS_BAD_LABEL);
    }

    crypto_wipe(buf, sizeof(buf));
    crypto_wipe(&st, sizeof(st));
    return reply;
}

static void call_root_or_fail(seL4_Word label, seL4_Word len, const char *what)
{
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL, seL4_MessageInfo_new(label, 0, 0, len));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK) {
        svc_fail(what);
    }
}

int main(seL4_Word ipc_buffer, seL4_Word id, seL4_Word dma_paddr, seL4_Word dev_offset)
{
    uint8_t flag[1];

    (void)id;
    (void)dma_paddr;

    if (tep_tls_init() == 0) {
        svc_fail("TLS setup failed");
    }
    seL4_SetIPCBuffer((seL4_IPCBuffer *)ipc_buffer);
    tep_log("started");

    if (fw_cfg_read_file(TEP_SVC_DEVICE_BASE + dev_offset, RESET_NAME, flag, sizeof(flag)) >= 0) {
        struct auth_state st;
        crypto_wipe(&st, sizeof(st));
        if (save_state(&st) != 0) {
            svc_fail("recovery reset requested but the state could not be cleared");
        }
        tep_log("recovery reset: passcode and failure counter cleared");
    }

    seL4_SetMR(0, TEP_IPC_VERSION);
    call_root_or_fail(TEP_IPC_READY, TEP_IPC_READY_LEN, "root task rejected READY");
    tep_log("serving passcode requests (Argon2id; delays use the host's clock)");

    for (;;) {
        seL4_Word badge;
        seL4_MessageInfo_t info = seL4_Recv(TEP_SVC_SLOT_ENDPOINT, &badge);

        if (badge & TEP_BADGE_CLIENT) {
            seL4_Reply(handle_request(info));
            continue;
        }
        if (badge & TEP_SVC_EVENT_PING) {
            pongs++;
            seL4_SetMR(0, TEP_IPC_VERSION);
            seL4_SetMR(1, pongs);
            call_root_or_fail(TEP_IPC_PONG, TEP_IPC_PONG_LEN, "root task rejected PONG");
        }
    }
}
