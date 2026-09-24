/*
 * tepOS BootPolicyService: checks signed boot manifests for NXU images.
 *
 * Holds only the public half of the host's boot-signing key (built in from
 * build/boot_pubkey.h, made by tools/boot_sign keygen). A caller sends a
 * manifest (<tep/boot_manifest.h>) and the SHA-256 it measured of the image;
 * the verdict is OK only if the signature is the key's, the digests match,
 * and the version is not below the highest this tepOS has accepted for that
 * name (kept in a KeyStore record). An accepted version becomes the new
 * minimum.
 *
 * This does not claim secure boot: NXU measures its own image and only
 * reports the verdict; no boot stage enforces it yet.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/boot_manifest.h>
#include <tep/ipc.h>
#include <tep/services.h>

#include "boot_pubkey.h"
#include "console.h"
#include "ipc_bytes.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS/bootpolicy";

#define MIN_SLOT 0
#define MIN_ENTRIES 4                   /* names with a recorded minimum version */
#define MIN_ENTRY_SIZE (TEP_BOOT_NAME_SIZE + 4)

static const uint8_t public_key[32] = TEP_BOOT_PUBLIC_KEY;
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

static seL4_MessageInfo_t status_reply(enum tep_status status, int with_value, seL4_Word value)
{
    if (with_value) {
        seL4_SetMR(0, value);
    }
    return seL4_MessageInfo_new(status, 0, 0, with_value ? 1 : 0);
}

static uint32_t get32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

/* The minimum-version table, from our KeyStore record. Returns 0 or -1. */
static int load_minimums(uint8_t table[MIN_ENTRIES * MIN_ENTRY_SIZE])
{
    for (int i = 0; i < MIN_ENTRIES * MIN_ENTRY_SIZE; i++) {
        table[i] = 0;
    }
    seL4_SetMR(0, MIN_SLOT);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_SERVER(TEP_SVC_ID_KEYSTORE),
                                        seL4_MessageInfo_new(TEP_KS_RECORD_GET, 0, 0, 1));
    seL4_Word label = seL4_MessageInfo_get_label(info);

    if (label == TEP_STATUS_NOT_FOUND) {
        return 0;
    }
    if (label != TEP_STATUS_OK || seL4_GetMR(0) != MIN_ENTRIES * MIN_ENTRY_SIZE ||
        seL4_MessageInfo_get_length(info) != 1 + TEP_BYTES_WORDS(MIN_ENTRIES * MIN_ENTRY_SIZE)) {
        return -1;
    }
    ipc_get_bytes(1, table, MIN_ENTRIES * MIN_ENTRY_SIZE);
    return 0;
}

static int save_minimums(const uint8_t table[MIN_ENTRIES * MIN_ENTRY_SIZE])
{
    seL4_SetMR(0, MIN_SLOT);
    seL4_SetMR(1, MIN_ENTRIES * MIN_ENTRY_SIZE);
    seL4_Word words = ipc_put_bytes(2, table, MIN_ENTRIES * MIN_ENTRY_SIZE);
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_SERVER(TEP_SVC_ID_KEYSTORE),
                                        seL4_MessageInfo_new(TEP_KS_RECORD_PUT, 0, 0, 2 + words));
    return seL4_MessageInfo_get_label(info) == TEP_STATUS_OK ? 0 : -1;
}

static int same_name(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < TEP_BOOT_NAME_SIZE; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static seL4_MessageInfo_t verify(seL4_MessageInfo_t info)
{
    uint8_t buf[TEP_BOOT_VERIFY_BYTES];
    uint8_t table[MIN_ENTRIES * MIN_ENTRY_SIZE];
    const uint8_t *manifest = buf;
    const uint8_t *measured = buf + TEP_BOOT_MANIFEST_SIZE;

    if (seL4_MessageInfo_get_length(info) != TEP_BYTES_WORDS(TEP_BOOT_VERIFY_BYTES) ||
        seL4_MessageInfo_get_extraCaps(info) != 0) {
        return status_reply(TEP_STATUS_BAD_LENGTH, 0, 0);
    }
    ipc_get_bytes(0, buf, sizeof(buf));

    for (int i = 0; i < 8; i++) {
        if (manifest[i] != (uint8_t)TEP_BOOT_MAGIC[i]) {
            return status_reply(TEP_STATUS_DENIED, 1, TEP_BOOT_BAD_FORMAT);
        }
    }
    if (get32(manifest + 8) != TEP_BOOT_FORMAT_VERSION) {
        return status_reply(TEP_STATUS_DENIED, 1, TEP_BOOT_BAD_FORMAT);
    }
    if (crypto_ed25519_check(manifest + TEP_BOOT_SIGNED_SIZE, public_key, manifest,
                             TEP_BOOT_SIGNED_SIZE) != 0) {
        return status_reply(TEP_STATUS_DENIED, 1, TEP_BOOT_BAD_SIGNATURE);
    }
    if (crypto_verify32(manifest + 40, measured) != 0) {
        return status_reply(TEP_STATUS_DENIED, 1, TEP_BOOT_WRONG_IMAGE);
    }

    uint32_t version = get32(manifest + 12);
    const uint8_t *name = manifest + 24;
    int slot = -1;

    if (load_minimums(table) != 0) {
        return status_reply(TEP_STATUS_UNAVAILABLE, 0, 0);
    }
    for (int i = 0; i < MIN_ENTRIES; i++) {
        uint8_t *e = table + i * MIN_ENTRY_SIZE;
        if (same_name(e, name)) {
            slot = i;
            break;
        }
        if (slot < 0 && e[0] == 0) {
            slot = i;       /* first free entry, if the name has none */
        }
    }
    if (slot < 0) {
        return status_reply(TEP_STATUS_FULL, 0, 0);
    }
    uint8_t *e = table + slot * MIN_ENTRY_SIZE;
    uint32_t minimum = same_name(e, name) ? get32(e + TEP_BOOT_NAME_SIZE) : 0;
    if (version < minimum) {
        return status_reply(TEP_STATUS_ROLLBACK, 1, minimum);
    }
    if (version > minimum || !same_name(e, name)) {
        for (int i = 0; i < TEP_BOOT_NAME_SIZE; i++) {
            e[i] = name[i];
        }
        put32(e + TEP_BOOT_NAME_SIZE, version);
        if (save_minimums(table) != 0) {
            return status_reply(TEP_STATUS_UNAVAILABLE, 0, 0);
        }
    }
    return status_reply(TEP_STATUS_OK, 1, version);
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
    tep_log("checking boot manifests (reported, not enforced)");

    for (;;) {
        seL4_Word badge;
        seL4_MessageInfo_t info = seL4_Recv(TEP_SVC_SLOT_ENDPOINT, &badge);

        if (badge & TEP_BADGE_CLIENT) {
            seL4_Reply(seL4_MessageInfo_get_label(info) == TEP_BOOT_VERIFY
                           ? verify(info)
                           : status_reply(TEP_STATUS_BAD_LABEL, 0, 0));
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
