/*
 * Host test for tepOS's cryptographic primitives: boot/lib/sha256.c against
 * the FIPS 180-4 / NIST and RFC 4231 vectors, and the vendored Monocypher's
 * Ed25519 (RFC 8032 test 1) and XChaCha20-Poly1305 as tepOS uses them.
 * Built and run by `make test-crypto`.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static int failures;

static void hex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(s + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void check(const char *name, const uint8_t *got, const char *want_hex, size_t n)
{
    uint8_t want[128];

    hex(want_hex, want, n);
    int ok = memcmp(got, want, n) == 0;
    printf("%-44s %s\n", name, ok ? "ok" : "FAIL");
    failures += !ok;
}

static void check_true(const char *name, int ok)
{
    printf("%-44s %s\n", name, ok ? "ok" : "FAIL");
    failures += !ok;
}

static void sha256_vectors(void)
{
    uint8_t d[SHA256_DIGEST_SIZE];

    sha256("", 0, d);
    check("SHA-256 empty", d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);
    sha256("abc", 3, d);
    check("SHA-256 abc", d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);

    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m448, strlen(m448), d);
    check("SHA-256 448-bit message", d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 32);

    const char *m896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                       "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    sha256(m896, strlen(m896), d);
    check("SHA-256 896-bit message", d, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", 32);

    /* One million 'a', fed in uneven pieces to exercise block boundaries. */
    struct sha256_ctx ctx;
    uint8_t a[997];
    memset(a, 'a', sizeof(a));
    sha256_init(&ctx);
    size_t left = 1000000;
    while (left > 0) {
        size_t n = left < sizeof(a) ? left : sizeof(a);
        sha256_update(&ctx, a, n);
        left -= n;
    }
    sha256_final(&ctx, d);
    check("SHA-256 one million 'a'", d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 32);
}

static void hmac_vectors(void)
{
    uint8_t mac[SHA256_DIGEST_SIZE];
    uint8_t key[131];

    memset(key, 0x0b, 20);
    hmac_sha256(key, 20, "Hi There", 8, mac);
    check("HMAC-SHA-256 RFC 4231 case 1", mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", 32);

    const char *d2 = "what do ya want for nothing?";
    hmac_sha256("Jefe", 4, d2, strlen(d2), mac);
    check("HMAC-SHA-256 RFC 4231 case 2", mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32);

    const char *d6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    memset(key, 0xaa, 131);
    hmac_sha256(key, 131, d6, strlen(d6), mac);
    check("HMAC-SHA-256 RFC 4231 case 6 (long key)", mac, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", 32);
}

static void ed25519_vector(void)
{
    uint8_t seed[32], sk[64], pk[32], sig[64];

    hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", seed, 32);
    crypto_ed25519_key_pair(sk, pk, seed);
    check("Ed25519 RFC 8032 test 1 public key", pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", 32);
    crypto_ed25519_sign(sig, sk, (const uint8_t *)"", 0);
    check("Ed25519 RFC 8032 test 1 signature", sig,
          "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", 64);
    check_true("Ed25519 signature verifies", crypto_ed25519_check(sig, pk, (const uint8_t *)"", 0) == 0);
    sig[0] ^= 1;
    check_true("Ed25519 altered signature rejected", crypto_ed25519_check(sig, pk, (const uint8_t *)"", 0) != 0);
}

static void aead_roundtrip(void)
{
    uint8_t key[32], nonce[24], mac[16];
    uint8_t plain[40] = "tepOS sealed key material, 40 bytes...";
    uint8_t sealed[40], opened[40];

    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(0xa0 + i);

    crypto_aead_lock(sealed, mac, key, nonce, (const uint8_t *)"hdr", 3, plain, sizeof(plain));
    check_true("XChaCha20-Poly1305 ciphertext differs", memcmp(sealed, plain, sizeof(plain)) != 0);
    check_true("XChaCha20-Poly1305 opens", crypto_aead_unlock(opened, mac, key, nonce, (const uint8_t *)"hdr", 3, sealed, sizeof(sealed)) == 0 &&
                                          memcmp(opened, plain, sizeof(plain)) == 0);
    sealed[5] ^= 1;
    check_true("XChaCha20-Poly1305 tampering rejected", crypto_aead_unlock(opened, mac, key, nonce, (const uint8_t *)"hdr", 3, sealed, sizeof(sealed)) != 0);
    sealed[5] ^= 1;
    check_true("XChaCha20-Poly1305 wrong header rejected", crypto_aead_unlock(opened, mac, key, nonce, (const uint8_t *)"HDR", 3, sealed, sizeof(sealed)) != 0);
}

int main(void)
{
    sha256_vectors();
    hmac_vectors();
    ed25519_vector();
    aead_roundtrip();
    printf("crypto_test: %s\n", failures == 0 ? "passed" : "FAILED");
    return failures != 0;
}
