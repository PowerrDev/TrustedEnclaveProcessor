/*
 * Requests between tepOS services (seL4 IPC on a server's endpoint).
 *
 * Same rules as <tep/ipc.h>: the label names the request or, in a reply, the
 * status (enum tep_status); arguments sit in message registers with an exact
 * length per label; byte strings are packed little-endian into whole words
 * after a length word (boot/lib/ipc_bytes.h). No capabilities cross.
 *
 * Servers identify the caller by its badge (TEP_CLIENT_BADGE), which only the
 * root task mints; a client can never name another client.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <tep/ipc.h>

#define TEP_WORD_BYTES sizeof(seL4_Word)
#define TEP_BYTES_WORDS(n) (((n) + TEP_WORD_BYTES - 1) / TEP_WORD_BYTES)

/* ---- CryptoService (TEP_SVC_ID_CRYPTO) ------------------------------------ */

enum tep_crypto_label {
    TEP_CRYPTO_RANDOM = 0x200,  /* MR0 = n -> OK, MR0 = n, MR1.. = n random bytes */
    TEP_CRYPTO_SHA256 = 0x201,  /* MR0 = n, MR1.. = n bytes -> OK, MR0.. = 32-byte digest */
};

#define TEP_CRYPTO_RANDOM_MAX 64
#define TEP_CRYPTO_SHA256_MAX 240

/* ---- KeyStore (TEP_SVC_ID_KEYSTORE) ---------------------------------------- */

/*
 * Keys are generated inside the KeyStore and named by an opaque, random,
 * non-zero 32-bit handle. Private keys never leave it: only public keys and
 * signatures do. A key belongs to the client that generated it; for any
 * other client it does not exist (TEP_STATUS_NOT_FOUND).
 */
enum tep_keystore_label {
    TEP_KS_GENERATE = 0x300,    /* MR0 = algorithm -> OK, MR0 = handle */
    TEP_KS_PUBLIC   = 0x301,    /* MR0 = handle -> OK, MR0.. = 32-byte public key */
    TEP_KS_SIGN     = 0x302,    /* MR0 = handle, MR1 = n, MR2.. = message -> OK, MR0.. = 64-byte signature */
    TEP_KS_DELETE   = 0x303,    /* MR0 = handle -> OK */

    /*
     * Small sealed records for other services' state (the AuthService's
     * credential and counters), stored with the keys and scoped to the
     * calling client like them. PUT returns once the record is on disk.
     */
    TEP_KS_RECORD_PUT = 0x304,  /* MR0 = slot, MR1 = n, MR2.. = n bytes -> OK */
    TEP_KS_RECORD_GET = 0x305,  /* MR0 = slot -> OK, MR0 = n, MR1.. = n bytes; NOT_FOUND */
};

#define TEP_KS_ALG_ED25519 1
#define TEP_KS_PUBLIC_KEY_SIZE 32
#define TEP_KS_SIGNATURE_SIZE 64
#define TEP_KS_SIGN_MAX 224         /* message bytes per signature request */
#define TEP_KS_MAX_KEYS 32
#define TEP_KS_RECORD_SLOTS 4       /* per client */
#define TEP_KS_RECORD_MAX 96        /* bytes */
#define TEP_KS_MAX_RECORDS 8        /* in the whole store */

/* ---- AuthenticationService (TEP_SVC_ID_AUTH) ------------------------------- */

/*
 * One passcode, checked inside tepOS against a salted Argon2id hash; the
 * hash, salt and failure counter never leave it. Wrong attempts bring
 * growing delays and, after TEP_AUTH_MAX_FAILURES, a lockout that only a
 * recovery reset on the tepOS side lifts. Delays use tepOS's RTC, which the
 * host controls: they are not a defence against the host.
 */
enum tep_auth_label {
    TEP_AUTH_SET    = 0x400,    /* MR0 = old n (0 if none set), MR1 = new n, MR2.. = old || new
                                 * -> OK | DENIED | RETRY_LATER (MR0 = s) | LOCKED */
    TEP_AUTH_VERIFY = 0x401,    /* MR0 = n, MR1.. = passcode
                                 * -> OK | DENIED | RETRY_LATER (MR0 = s) | LOCKED | NOT_FOUND */
    TEP_AUTH_STATUS = 0x402,    /* -> OK, MR0 = passcode set, MR1 = failures, MR2 = locked,
                                 *    MR3 = seconds before the next attempt is allowed */
};

#define TEP_AUTH_PASSCODE_MIN 4
#define TEP_AUTH_PASSCODE_MAX 64
#define TEP_AUTH_MAX_FAILURES 10
#define TEP_AUTH_STATUS_LEN 4

/* ---- BootPolicyService (TEP_SVC_ID_BOOT) ----------------------------------- */

/*
 * Checks a signed boot manifest (<tep/boot_manifest.h>) against the image
 * digest the caller measured: the signature must be the host boot-signing
 * key's (tepOS holds only its public key), the digests must match, and the
 * version must not be below the highest accepted for that name, which then
 * becomes the new minimum. This reports; nothing enforces the verdict yet.
 */
enum tep_boot_label {
    TEP_BOOT_VERIFY = 0x500,    /* MR0.. = manifest || measured SHA-256
                                 * -> OK, MR0 = image version | DENIED, MR0 = reason
                                 *  | ROLLBACK, MR0 = minimum version */
};

#define TEP_BOOT_VERIFY_BYTES (136 + 32)

enum tep_boot_reason {
    TEP_BOOT_BAD_FORMAT    = 1,     /* not a manifest this tepOS understands */
    TEP_BOOT_BAD_SIGNATURE = 2,     /* not signed by the boot-signing key */
    TEP_BOOT_WRONG_IMAGE   = 3,     /* signed, but for another image than measured */
};
