/*
 * Host test for tepOS's cryptographic primitives: boot/lib/sha256.c against
 * the FIPS 180-4 / NIST and RFC 4231 vectors, boot/lib/hmac_drbg.c against
 * NIST CAVP HMAC_DRBG (SHA-256, no reseed) vectors, and the vendored
 * Monocypher's Ed25519 (RFC 8032 test 1) and XChaCha20-Poly1305 as tepOS
 * uses them.
 * Built and run by `make test-crypto`.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <string.h>

#include "hmac_drbg.h"
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

/*
 * CAVP procedure (drbgvectors_no_reseed, HMAC_DRBG.rsp, [SHA-256]): instantiate,
 * generate 1024 bits and discard, generate 1024 bits and compare.
 */
static void drbg_case(const char *name, const char *entropy_hex, const char *nonce_hex,
                      const char *pers_hex, const char *add1_hex, const char *add2_hex,
                      const char *returned_hex)
{
    uint8_t entropy[32], nonce[16], pers[32], add1[32], add2[32], out[128];
    size_t pers_n = strlen(pers_hex) / 2, add1_n = strlen(add1_hex) / 2, add2_n = strlen(add2_hex) / 2;
    struct hmac_drbg d;

    hex(entropy_hex, entropy, 32);
    hex(nonce_hex, nonce, 16);
    hex(pers_hex, pers, pers_n);
    hex(add1_hex, add1, add1_n);
    hex(add2_hex, add2, add2_n);

    hmac_drbg_instantiate(&d, entropy, 32, nonce, 16, pers, pers_n);
    hmac_drbg_generate(&d, out, sizeof(out), add1, add1_n);
    hmac_drbg_generate(&d, out, sizeof(out), add2, add2_n);
    check(name, out, returned_hex, sizeof(out));
}

static void drbg_vectors(void)
{
    drbg_case("HMAC_DRBG CAVP SHA-256 count 0", 
              "ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488",
              "659ba96c601dc69fc902940805ec0ca8", "", "", "",
              "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460"
              "b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
              "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8");
    drbg_case("HMAC_DRBG CAVP SHA-256 pers+additional",
              "5d3286bc53a258a53ba781e2c4dcd79a790e43bbe0e89fb3eed39086be34174b",
              "c5422294b7318952ace7055ab7570abf",
              "2dba094d008e150d51c4135bb2f03dcde9cbf3468a12908a1b025c120c985b9d",
              "793a7ef8f6f0482beac542bb785c10f8b7b406a4de92667ab168ecc2cf7573c6",
              "2238cdb4e23d629fe0c2a83dd8d5144ce1a6229ef41dabe2a99ff722e510b530",
              "d04678198ae7e1aeb435b45291458ffde0891560748b43330eaf866b5a6385e74c6fa5a5a44bdb284d436e98d244018d"
              "6acedcdfa2e9f499d8089e4db86ae89a6ab2d19cb705e2f048f97fb597f04106a1fa6a1416ad3d859118e079a0c319eb"
              "95686f4cbcce3b5101c7a0b010ef029c4ef6d06cdfac97efb9773891688c37cf");

    struct hmac_drbg d = { 0 };
    uint8_t out[16];
    check_true("HMAC_DRBG refuses before instantiate", hmac_drbg_generate(&d, out, sizeof(out), NULL, 0) != 0);
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
    drbg_vectors();
    ed25519_vector();
    aead_roundtrip();
    printf("crypto_test: %s\n", failures == 0 ? "passed" : "FAILED");
    return failures != 0;
}
