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
 * The table is sealed onto its virtio-blk disk after every change and loaded
 * at start (store.h): keys survive reboots, but the sealing key is a host
 * file, so this is NOT a protection boundary against the host. A store that
 * exists but does not open stops the KeyStore (fail closed).
 *
 * Started with x0 = IPC buffer, x1 = service id, x2 = DMA page physical
 * address, x3 = virtio-blk register offset in its device page; fw_cfg is
 * the second device page (<tep/ipc.h>).
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
#include "store.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS/keystore";

static struct key keys[TEP_KS_MAX_KEYS];
static struct record records[TEP_KS_MAX_RECORDS];
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

/* Seal the table under a fresh nonce. Returns 0 or -1. */
static int save(void)
{
    uint8_t nonce[STORE_NONCE_SIZE];

    if (get_random(nonce, sizeof(nonce)) != 0) {
        return -1;
    }
    return store_save(keys, TEP_KS_MAX_KEYS, records, TEP_KS_MAX_RECORDS, nonce);
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

    /* A handle is only returned for a key that will survive a reboot. */
    if (save() != 0) {
        crypto_wipe(k, sizeof(*k));
        return status_reply(TEP_STATUS_UNAVAILABLE);
    }

    seL4_SetMR(0, handle);
    return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, 1);
}

static struct record *find_record(seL4_Word owner, seL4_Word slot)
{
    for (int i = 0; i < TEP_KS_MAX_RECORDS; i++) {
        if (records[i].in_use && records[i].owner == owner && records[i].slot == slot) {
            return &records[i];
        }
    }
    return NULL;
}

/* TEP_KS_RECORD_PUT: replies once the record is sealed on disk. */
static seL4_MessageInfo_t record_put(seL4_Word owner, seL4_Word len)
{
    seL4_Word slot = seL4_GetMR(0), n = seL4_GetMR(1);
    struct record *r, saved;
    int fresh = 0;

    if (len < 2 || slot >= TEP_KS_RECORD_SLOTS || n > TEP_KS_RECORD_MAX || len != 2 + TEP_BYTES_WORDS(n)) {
        return status_reply(TEP_STATUS_BAD_LENGTH);
    }
    r = find_record(owner, slot);
    for (int i = 0; i < TEP_KS_MAX_RECORDS && r == NULL; i++) {
        if (!records[i].in_use) {
            r = &records[i];
            fresh = 1;
        }
    }
    if (r == NULL) {
        return status_reply(TEP_STATUS_FULL);
    }
    saved = *r;
    r->in_use = 1;
    r->owner = owner;
    r->slot = (uint8_t)slot;
    r->len = (uint8_t)n;
    crypto_wipe(r->data, sizeof(r->data));
    ipc_get_bytes(2, r->data, n);
    if (save() != 0) {
        *r = saved;
        if (fresh) {
            crypto_wipe(r, sizeof(*r));
        }
        crypto_wipe(&saved, sizeof(saved));
        return status_reply(TEP_STATUS_UNAVAILABLE);
    }
    crypto_wipe(&saved, sizeof(saved));
    return status_reply(TEP_STATUS_OK);
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
        /* On failure the key is gone now but still sealed on disk until the next save. */
        return status_reply(save() == 0 ? TEP_STATUS_OK : TEP_STATUS_UNAVAILABLE);

    case TEP_KS_RECORD_PUT:
        return record_put(owner, len);

    case TEP_KS_RECORD_GET: {
        struct record *r;
        if (len != 1) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        r = find_record(owner, seL4_GetMR(0));
        if (r == NULL) {
            return status_reply(TEP_STATUS_NOT_FOUND);
        }
        seL4_SetMR(0, r->len);
        return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, 1 + ipc_put_bytes(1, r->data, r->len));
    }

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

int main(seL4_Word ipc_buffer, seL4_Word id, seL4_Word dma_paddr, seL4_Word dev_offset)
{
    const char *err;
    int loaded;

    (void)id;

    if (tep_tls_init() == 0) {
        svc_fail("TLS setup failed");
    }
    seL4_SetIPCBuffer((seL4_IPCBuffer *)ipc_buffer);
    tep_log("started");

    if (dma_paddr == 0) {
        svc_fail("no DMA page");
    }
    err = store_init(TEP_SVC_DEVICE_BASE + dev_offset, (void *)TEP_SVC_DMA_BASE, dma_paddr,
                     TEP_SVC_DEVICE2_BASE);
    if (err != NULL) {
        svc_fail(err);
    }
    err = store_load(keys, TEP_KS_MAX_KEYS, records, TEP_KS_MAX_RECORDS, &loaded);
    if (err != NULL) {
        svc_fail(err);
    }
    tep_log_start();
    tep_puts("key store opened: ");
    tep_putdec((seL4_Word)loaded);
    tep_puts(" key(s)\n");
    tep_log("sealing key comes from the host (fw_cfg): NOT a protection boundary");

    seL4_SetMR(0, TEP_IPC_VERSION);
    call_root_or_fail(TEP_IPC_READY, TEP_IPC_READY_LEN, "root task rejected READY");
    tep_log("serving key requests");

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
