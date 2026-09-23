/*
 * SHA-256 (FIPS 180-4) and HMAC-SHA-256 (RFC 2104).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static void compress(uint32_t state[8], const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int t = 0; t < 16; t++) {
        w[t] = (uint32_t)block[4 * t] << 24 | (uint32_t)block[4 * t + 1] << 16 |
               (uint32_t)block[4 * t + 2] << 8 | block[4 * t + 3];
    }
    for (int t = 16; t < 64; t++) {
        uint32_t s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint32_t s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (int t = 0; t < 64; t++) {
        uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[t] + w[t];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;

    secure_wipe(w, sizeof(w));
}

void sha256_init(struct sha256_ctx *ctx)
{
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    for (int i = 0; i < 8; i++) {
        ctx->state[i] = iv[i];
    }
    ctx->length = 0;
    ctx->used = 0;
}

void sha256_update(struct sha256_ctx *ctx, const void *data, size_t size)
{
    const uint8_t *p = data;

    ctx->length += size;
    while (size > 0) {
        size_t n = SHA256_BLOCK_SIZE - ctx->used;
        if (n > size) {
            n = size;
        }
        for (size_t i = 0; i < n; i++) {
            ctx->block[ctx->used + i] = p[i];
        }
        ctx->used += n;
        p += n;
        size -= n;
        if (ctx->used == SHA256_BLOCK_SIZE) {
            compress(ctx->state, ctx->block);
            ctx->used = 0;
        }
    }
}

void sha256_final(struct sha256_ctx *ctx, uint8_t digest[SHA256_DIGEST_SIZE])
{
    uint64_t bits = ctx->length * 8;

    ctx->block[ctx->used++] = 0x80;
    if (ctx->used > SHA256_BLOCK_SIZE - 8) {
        while (ctx->used < SHA256_BLOCK_SIZE) {
            ctx->block[ctx->used++] = 0;
        }
        compress(ctx->state, ctx->block);
        ctx->used = 0;
    }
    while (ctx->used < SHA256_BLOCK_SIZE - 8) {
        ctx->block[ctx->used++] = 0;
    }
    for (int i = 0; i < 8; i++) {
        ctx->block[SHA256_BLOCK_SIZE - 1 - i] = (uint8_t)(bits >> (8 * i));
    }
    compress(ctx->state, ctx->block);

    for (int i = 0; i < 8; i++) {
        digest[4 * i] = (uint8_t)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[4 * i + 3] = (uint8_t)ctx->state[i];
    }
    secure_wipe(ctx, sizeof(*ctx));
}

void sha256(const void *data, size_t size, uint8_t digest[SHA256_DIGEST_SIZE])
{
    struct sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, data, size);
    sha256_final(&ctx, digest);
}

void hmac_sha256_init(struct hmac_sha256_ctx *ctx, const void *key, size_t key_size)
{
    uint8_t k[SHA256_BLOCK_SIZE] = { 0 };
    uint8_t pad[SHA256_BLOCK_SIZE];

    /* Keys longer than a block are hashed first (RFC 2104 section 2). */
    if (key_size > SHA256_BLOCK_SIZE) {
        sha256(key, key_size, k);
    } else {
        for (size_t i = 0; i < key_size; i++) {
            k[i] = ((const uint8_t *)key)[i];
        }
    }

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        pad[i] = k[i] ^ 0x36;
    }
    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, pad, sizeof(pad));

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        pad[i] = k[i] ^ 0x5c;
    }
    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, pad, sizeof(pad));

    secure_wipe(k, sizeof(k));
    secure_wipe(pad, sizeof(pad));
}

void hmac_sha256_update(struct hmac_sha256_ctx *ctx, const void *data, size_t size)
{
    sha256_update(&ctx->inner, data, size);
}

void hmac_sha256_final(struct hmac_sha256_ctx *ctx, uint8_t mac[SHA256_DIGEST_SIZE])
{
    uint8_t inner[SHA256_DIGEST_SIZE];

    sha256_final(&ctx->inner, inner);
    sha256_update(&ctx->outer, inner, sizeof(inner));
    sha256_final(&ctx->outer, mac);
    secure_wipe(inner, sizeof(inner));
}

void hmac_sha256(const void *key, size_t key_size, const void *data, size_t size,
                 uint8_t mac[SHA256_DIGEST_SIZE])
{
    struct hmac_sha256_ctx ctx;

    hmac_sha256_init(&ctx, key, key_size);
    hmac_sha256_update(&ctx, data, size);
    hmac_sha256_final(&ctx, mac);
}

void secure_wipe(void *p, size_t size)
{
    volatile uint8_t *v = p;

    while (size--) {
        *v++ = 0;
    }
}
