/*
 * HMAC_DRBG with SHA-256 (NIST SP 800-90A Rev. 1, section 10.1.2).
 *
 * Deterministic: all randomness comes from the entropy the caller supplies
 * at instantiate and reseed time. tepOS's CryptoService feeds it from its
 * hardware entropy source and reseeds it periodically.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

/* SP 800-90A table 2: at most 2^48 requests between reseeds; tepOS uses far less. */
#define HMAC_DRBG_MAX_REQUEST 65536     /* bytes per generate call (2^19 bits allowed) */

struct hmac_drbg {
    uint8_t key[SHA256_DIGEST_SIZE];
    uint8_t v[SHA256_DIGEST_SIZE];
    uint64_t reseed_counter;
    int instantiated;
};

/* entropy || nonce || personalization, as in section 10.1.2.3. */
void hmac_drbg_instantiate(struct hmac_drbg *d,
                           const void *entropy, size_t entropy_size,
                           const void *nonce, size_t nonce_size,
                           const void *pers, size_t pers_size);

void hmac_drbg_reseed(struct hmac_drbg *d,
                      const void *entropy, size_t entropy_size,
                      const void *additional, size_t additional_size);

/*
 * Returns 0, or -1 if the DRBG is not instantiated or the request is too
 * large; on -1 nothing is written. The caller decides when to reseed
 * (reseed_counter counts generate calls since the last (re)seed).
 */
int hmac_drbg_generate(struct hmac_drbg *d, void *out, size_t size,
                       const void *additional, size_t additional_size);

void hmac_drbg_wipe(struct hmac_drbg *d);
