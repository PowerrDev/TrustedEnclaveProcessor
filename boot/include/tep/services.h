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
};

#define TEP_KS_ALG_ED25519 1
#define TEP_KS_PUBLIC_KEY_SIZE 32
#define TEP_KS_SIGNATURE_SIZE 64
#define TEP_KS_SIGN_MAX 224         /* message bytes per signature request */
#define TEP_KS_MAX_KEYS 32
