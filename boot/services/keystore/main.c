/*
 * tepOS KeyStore: key objects behind opaque handles.
 *
 * Runs in its own protection domain; its key table exists only in its own
 * memory, which no other service maps. Keys are generated here from seeds
 * the CryptoService provides, named by random non-zero 32-bit handles, and
 * used here: clients get public keys and signatures, never private keys.
 * A key belongs to the client that generated it (identified by the badge
 * the root task minted); to any other client it does not exist.
 *
 * Requests (<tep/services.h>): TEP_KS_GENERATE, TEP_KS_PUBLIC, TEP_KS_SIGN,
 * TEP_KS_DELETE. Ed25519 comes from the vendored Monocypher.
 *
 * Keys are kept in memory only for now; they are lost when the KeyStore
 * restarts.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>
#include <tep/services.h>

#include "console.h"
#include "ipc_bytes.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS/keystore";

struct key {
    int in_use;
    uint32_t handle;
    seL4_Word owner;                /* client badge */
    uint8_t secret[64];             /* Monocypher Ed25519 secret key (seed || public) */
    uint8_t public[TEP_KS_PUBLIC_KEY_SIZE];
};

static struct key keys[TEP_KS_MAX_KEYS];
static seL4_Word pongs;

static void __attribute__((noreturn)) svc_fail(const char *msg)
{
    tep_log_start();
    tep_puts("FATAL: ");
    tep_puts(msg);
    tep_puts("\n");
    crypto_wipe(keys, sizeof(keys));
    for (;;) {
        *(volatile seL4_Word *)0 = 0;
    }
}

static seL4_MessageInfo_t status_reply(enum tep_status status)
{
    return seL4_MessageInfo_new(status, 0, 0, 0);
}

/* n random bytes from the CryptoService. Returns 0 or -1. */
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

static struct key *find(uint32_t handle, seL4_Word owner)
{
    for (int i = 0; i < TEP_KS_MAX_KEYS; i++) {
        if (keys[i].in_use && keys[i].handle == handle && keys[i].owner == owner) {
            return &keys[i];
        }
    }
    return NULL;
}

static int handle_taken(uint32_t handle)
{
    for (int i = 0; i < TEP_KS_MAX_KEYS; i++) {
        if (keys[i].in_use && keys[i].handle == handle) {
            return 1;
        }
    }
    return 0;
}

static seL4_MessageInfo_t generate(seL4_Word owner, seL4_Word algorithm)
{
    struct key *k = NULL;
    uint8_t seed[32];
    uint8_t h[4];
    uint32_t handle;

    if (algorithm != TEP_KS_ALG_ED25519) {
        return status_reply(TEP_STATUS_BAD_LABEL);
    }
    for (int i = 0; i < TEP_KS_MAX_KEYS && k == NULL; i++) {
        if (!keys[i].in_use) {
            k = &keys[i];
        }
    }
    if (k == NULL) {
        return status_reply(TEP_STATUS_FULL);
    }

    do {
        if (get_random(h, sizeof(h)) != 0) {
            return status_reply(TEP_STATUS_UNAVAILABLE);
        }
        handle = (uint32_t)h[0] | (uint32_t)h[1] << 8 | (uint32_t)h[2] << 16 | (uint32_t)h[3] << 24;
    } while (handle == 0 || handle_taken(handle));

    if (get_random(seed, sizeof(seed)) != 0) {
        crypto_wipe(seed, sizeof(seed));
        return status_reply(TEP_STATUS_UNAVAILABLE);
    }
    crypto_ed25519_key_pair(k->secret, k->public, seed);   /* wipes seed */
    k->handle = handle;
    k->owner = owner;
    k->in_use = 1;

    seL4_SetMR(0, handle);
    return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, 1);
}

static seL4_MessageInfo_t handle_request(seL4_Word badge, seL4_MessageInfo_t info)
{
    seL4_Word len = seL4_MessageInfo_get_length(info);
    seL4_Word owner = badge;
    struct key *k;

    if (seL4_MessageInfo_get_extraCaps(info) != 0) {
        return status_reply(TEP_STATUS_BAD_LENGTH);
    }

    switch (seL4_MessageInfo_get_label(info)) {
    case TEP_KS_GENERATE:
        if (len != 1) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        return generate(owner, seL4_GetMR(0));

    case TEP_KS_PUBLIC:
        if (len != 1) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        k = find((uint32_t)seL4_GetMR(0), owner);
        if (k == NULL || seL4_GetMR(0) > 0xffffffffUL) {
            return status_reply(TEP_STATUS_NOT_FOUND);
        }
        return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, ipc_put_bytes(0, k->public, sizeof(k->public)));

    case TEP_KS_SIGN: {
        seL4_Word n = seL4_GetMR(1);
        uint8_t msg[TEP_KS_SIGN_MAX];
        uint8_t sig[TEP_KS_SIGNATURE_SIZE];

        if (len < 2 || n == 0 || n > TEP_KS_SIGN_MAX || len != 2 + TEP_BYTES_WORDS(n)) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        k = find((uint32_t)seL4_GetMR(0), owner);
        if (k == NULL || seL4_GetMR(0) > 0xffffffffUL) {
            return status_reply(TEP_STATUS_NOT_FOUND);
        }
        ipc_get_bytes(2, msg, n);
        crypto_ed25519_sign(sig, k->secret, msg, n);
        return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, ipc_put_bytes(0, sig, sizeof(sig)));
    }

    case TEP_KS_DELETE:
        if (len != 1) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        k = find((uint32_t)seL4_GetMR(0), owner);
        if (k == NULL || seL4_GetMR(0) > 0xffffffffUL) {
            return status_reply(TEP_STATUS_NOT_FOUND);
        }
        crypto_wipe(k, sizeof(*k));
        return status_reply(TEP_STATUS_OK);

    default:
        return status_reply(TEP_STATUS_BAD_LABEL);
    }
}

static void call_root_or_fail(seL4_Word label, seL4_Word len, const char *what)
{
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL, seL4_MessageInfo_new(label, 0, 0, len));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK) {
        svc_fail(what);
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
    call_root_or_fail(TEP_IPC_READY, TEP_IPC_READY_LEN, "root task rejected READY");
    tep_log("serving key requests (keys held in memory only)");

    for (;;) {
        seL4_Word badge;
        seL4_MessageInfo_t info = seL4_Recv(TEP_SVC_SLOT_ENDPOINT, &badge);

        if (badge & TEP_BADGE_CLIENT) {
            seL4_Reply(handle_request(badge, info));
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
