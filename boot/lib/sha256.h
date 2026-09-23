/*
 * SHA-256 (FIPS 180-4) and HMAC-SHA-256 (RFC 2104) for tepOS.
 *
 * Freestanding: only <stddef.h>/<stdint.h>, so tools/crypto_test.c builds the
 * same file on the host and checks it against the published test vectors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define SHA256_BLOCK_SIZE  64
#define SHA256_DIGEST_SIZE 32

struct sha256_ctx {
    uint32_t state[8];
    uint64_t length;            /* bytes hashed so far */
    uint8_t block[SHA256_BLOCK_SIZE];
    size_t used;                /* bytes in block */
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const void *data, size_t size);
void sha256_final(struct sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
void sha256(const void *data, size_t size, uint8_t digest[SHA256_DIGEST_SIZE]);

struct hmac_sha256_ctx {
    struct sha256_ctx inner;
    struct sha256_ctx outer;
};

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const void *key, size_t key_size);
void hmac_sha256_update(struct hmac_sha256_ctx *ctx, const void *data, size_t size);
void hmac_sha256_final(struct hmac_sha256_ctx *ctx, uint8_t mac[SHA256_DIGEST_SIZE]);
void hmac_sha256(const void *key, size_t key_size, const void *data, size_t size,
                 uint8_t mac[SHA256_DIGEST_SIZE]);

/* Overwrite memory in a way the compiler may not drop (for secrets). */
void secure_wipe(void *p, size_t size);
