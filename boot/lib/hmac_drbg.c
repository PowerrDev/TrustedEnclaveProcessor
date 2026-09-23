/*
 * HMAC_DRBG with SHA-256 (NIST SP 800-90A Rev. 1, section 10.1.2).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "hmac_drbg.h"

/* HMAC_DRBG_Update (10.1.2.2) with provided_data = a || b || c. */
static void update(struct hmac_drbg *d,
                   const void *a, size_t a_size,
                   const void *b, size_t b_size,
                   const void *c, size_t c_size)
{
    int have_data = a_size + b_size + c_size != 0;

    for (uint8_t round = 0x00; round <= 0x01; round++) {
        struct hmac_sha256_ctx h;

        hmac_sha256_init(&h, d->key, sizeof(d->key));
        hmac_sha256_update(&h, d->v, sizeof(d->v));
        hmac_sha256_update(&h, &round, 1);
        hmac_sha256_update(&h, a, a_size);
        hmac_sha256_update(&h, b, b_size);
        hmac_sha256_update(&h, c, c_size);
        hmac_sha256_final(&h, d->key);

        hmac_sha256(d->key, sizeof(d->key), d->v, sizeof(d->v), d->v);

        if (!have_data) {
            break;
        }
    }
}

void hmac_drbg_instantiate(struct hmac_drbg *d,
                           const void *entropy, size_t entropy_size,
                           const void *nonce, size_t nonce_size,
                           const void *pers, size_t pers_size)
{
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        d->key[i] = 0x00;
        d->v[i] = 0x01;
    }
    update(d, entropy, entropy_size, nonce, nonce_size, pers, pers_size);
    d->reseed_counter = 1;
    d->instantiated = 1;
}

void hmac_drbg_reseed(struct hmac_drbg *d,
                      const void *entropy, size_t entropy_size,
                      const void *additional, size_t additional_size)
{
    update(d, entropy, entropy_size, additional, additional_size, NULL, 0);
    d->reseed_counter = 1;
}

int hmac_drbg_generate(struct hmac_drbg *d, void *out, size_t size,
                       const void *additional, size_t additional_size)
{
    uint8_t *p = out;

    if (!d->instantiated || size > HMAC_DRBG_MAX_REQUEST) {
        return -1;
    }
    if (additional_size != 0) {
        update(d, additional, additional_size, NULL, 0, NULL, 0);
    }
    while (size > 0) {
        size_t n = size < sizeof(d->v) ? size : sizeof(d->v);

        hmac_sha256(d->key, sizeof(d->key), d->v, sizeof(d->v), d->v);
        for (size_t i = 0; i < n; i++) {
            p[i] = d->v[i];
        }
        p += n;
        size -= n;
    }
    update(d, additional, additional_size, NULL, 0, NULL, 0);
    d->reseed_counter++;
    return 0;
}

void hmac_drbg_wipe(struct hmac_drbg *d)
{
    secure_wipe(d, sizeof(*d));
}
