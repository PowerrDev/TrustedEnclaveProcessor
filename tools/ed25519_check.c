/*
 * Host tool: verify an Ed25519 signature, independently of tepOS.
 *
 *   ed25519_check <public key hex> <signature hex> <message hex>
 *
 * Exits 0 if the signature is valid, 1 if not, 2 on bad arguments. Used by
 * tools/mailbox_client.py --selftest to check signatures tepOS's KeyStore
 * produced. Built by `make ed25519-check` from the vendored Monocypher.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>

#include "monocypher-ed25519.h"

static int unhex(const char *s, uint8_t *out, size_t max, size_t *n)
{
    size_t len = strlen(s);

    if (len % 2 != 0 || len / 2 > max) {
        return -1;
    }
    for (size_t i = 0; i < len / 2; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    *n = len / 2;
    return 0;
}

int main(int argc, char **argv)
{
    uint8_t pk[32], sig[64], msg[4096];
    size_t pk_n, sig_n, msg_n;

    if (argc != 4 || unhex(argv[1], pk, sizeof(pk), &pk_n) != 0 || pk_n != 32 ||
        unhex(argv[2], sig, sizeof(sig), &sig_n) != 0 || sig_n != 64 ||
        unhex(argv[3], msg, sizeof(msg), &msg_n) != 0) {
        fprintf(stderr, "usage: ed25519_check <public key hex> <signature hex> <message hex>\n");
        return 2;
    }
    return crypto_ed25519_check(sig, pk, msg, msg_n) == 0 ? 0 : 1;
}
