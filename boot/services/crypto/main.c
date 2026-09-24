/*
 * tepOS CryptoService: entropy and the random bit generator.
 *
 * Runs in its own protection domain with the virtio-rng device (QEMU:
 * -device virtio-rng-device,bus=virtio-mmio-bus.0, fed from the host's
 * random source) and one DMA page. It never sees key material held by other
 * services.
 *
 * At start it runs power-on self-tests (SHA-256 and HMAC_DRBG known
 * answers), checks each batch of entropy with the SP 800-90B repetition
 * count test, and seeds an HMAC_DRBG (SP 800-90A) from it. Any failure
 * stops the service: tepOS then reports it failed and nothing downstream
 * gets random numbers (fail closed).
 *
 * Other services call it on its endpoint (<tep/services.h>): TEP_CRYPTO_RANDOM
 * returns DRBG output, TEP_CRYPTO_SHA256 hashes up to TEP_CRYPTO_SHA256_MAX
 * bytes.
 *
 * Started with x0 = IPC buffer, x1 = service id, x2 = DMA page physical
 * address, x3 = device register offset in the device page (<tep/ipc.h>).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <tep/ipc.h>
#include <tep/services.h>

#include "console.h"
#include "hmac_drbg.h"
#include "ipc_bytes.h"
#include "sha256.h"
#include "tls.h"
#include "virtio_mmio.h"

const char tep_log_prefix[] = "tepOS/crypto";

/*
 * Repetition count test cutoff: 1 + ceil(-log2(2^-20) / H) with a
 * conservative claim of H = 1 bit of min-entropy per byte.
 */
#define RCT_CUTOFF 21
#define ENTROPY_BYTES 32
#define NONCE_BYTES 16
#define RESEED_INTERVAL 1024
#define RNG_BUFFER VIRTIO_DMA_BUFFERS
#define RNG_MAX_POLLS 100000

static struct virtio_dev rng;
static struct hmac_drbg drbg;
static seL4_Word pongs;

static void __attribute__((noreturn)) svc_fail(const char *msg)
{
    tep_log_start();
    tep_puts("FATAL: ");
    tep_puts(msg);
    tep_puts("\n");
    hmac_drbg_wipe(&drbg);
    for (;;) {
        *(volatile seL4_Word *)0 = 0;
    }
}

static void yield(void)
{
    seL4_Yield();
}

static int bytes_equal(const uint8_t *a, const char *hex_expected, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned hi = hex_expected[2 * i], lo = hex_expected[2 * i + 1];
        hi = hi <= '9' ? hi - '0' : hi - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
        if (a[i] != (uint8_t)(hi << 4 | lo)) {
            return 0;
        }
    }
    return 1;
}

static void hex_decode(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned hi = hex[2 * i], lo = hex[2 * i + 1];
        hi = hi <= '9' ? hi - '0' : hi - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
}

/* Power-on known-answer tests (the same vectors as tools/crypto_test.c). */
static void self_tests(void)
{
    uint8_t d[SHA256_DIGEST_SIZE];
    uint8_t entropy[32], nonce[16], out[128];
    struct hmac_drbg kat;

    sha256("abc", 3, d);
    if (!bytes_equal(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32)) {
        svc_fail("SHA-256 self-test failed");
    }

    hex_decode("ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488", entropy, 32);
    hex_decode("659ba96c601dc69fc902940805ec0ca8", nonce, 16);
    hmac_drbg_instantiate(&kat, entropy, 32, nonce, 16, NULL, 0);
    hmac_drbg_generate(&kat, out, sizeof(out), NULL, 0);
    hmac_drbg_generate(&kat, out, sizeof(out), NULL, 0);
    if (!bytes_equal(out, "e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89"
                          "d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc1"
                          "07694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668"
                          "961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8", 128)) {
        svc_fail("HMAC_DRBG self-test failed");
    }
    hmac_drbg_wipe(&kat);
    tep_log("self-tests passed (SHA-256, HMAC_DRBG)");
}

/*
 * Fill out[] from the virtio-rng device, applying the repetition count test
 * across the whole stream. Returns 0, or -1 on a device error or a failed
 * health test.
 */
static int entropy_get(uint8_t *out, size_t n)
{
    static uint8_t last;
    static unsigned run;
    static int have_last;

    while (n > 0) {
        uint32_t want = n < 256 ? (uint32_t)n : 256;
        struct virtio_buf buf = { .offset = RNG_BUFFER, .len = want, .device_writes = 1 };
        long got = virtio_mmio_transfer(&rng, &buf, 1, yield, RNG_MAX_POLLS);

        if (got <= 0 || (unsigned long)got > want) {
            return -1;
        }
        for (long i = 0; i < got; i++) {
            uint8_t b = rng.dma[RNG_BUFFER + i];
            if (have_last && b == last) {
                if (++run >= RCT_CUTOFF) {
                    return -1;
                }
            } else {
                last = b;
                run = 1;
                have_last = 1;
            }
            *out++ = b;
        }
        n -= (size_t)got;
    }
    secure_wipe(rng.dma + RNG_BUFFER, 256);
    return 0;
}

static void seed_drbg(void)
{
    static const char pers[] = "tepOS CryptoService HMAC_DRBG v1";
    uint8_t seed[ENTROPY_BYTES + NONCE_BYTES];

    if (entropy_get(seed, sizeof(seed)) != 0) {
        secure_wipe(seed, sizeof(seed));
        svc_fail("entropy source failed its health test or stopped responding");
    }
    hmac_drbg_instantiate(&drbg, seed, ENTROPY_BYTES, seed + ENTROPY_BYTES, NONCE_BYTES,
                          pers, sizeof(pers) - 1);
    secure_wipe(seed, sizeof(seed));
}

static int crypto_random(void *out, size_t n)
{
    if (drbg.reseed_counter >= RESEED_INTERVAL) {
        uint8_t fresh[ENTROPY_BYTES];
        if (entropy_get(fresh, sizeof(fresh)) != 0) {
            secure_wipe(fresh, sizeof(fresh));
            return -1;
        }
        hmac_drbg_reseed(&drbg, fresh, sizeof(fresh), NULL, 0);
        secure_wipe(fresh, sizeof(fresh));
    }
    return hmac_drbg_generate(&drbg, out, n, NULL, 0);
}

static seL4_MessageInfo_t status_reply(enum tep_status status)
{
    return seL4_MessageInfo_new(status, 0, 0, 0);
}

/* One request from another service; the reply is sent by the caller. */
static seL4_MessageInfo_t handle_request(seL4_MessageInfo_t info)
{
    seL4_Word len = seL4_MessageInfo_get_length(info);
    uint8_t buf[TEP_CRYPTO_SHA256_MAX];

    if (seL4_MessageInfo_get_extraCaps(info) != 0) {
        return status_reply(TEP_STATUS_BAD_LENGTH);
    }

    switch (seL4_MessageInfo_get_label(info)) {
    case TEP_CRYPTO_RANDOM: {
        seL4_Word n = seL4_GetMR(0);
        if (len != 1) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        if (n == 0 || n > TEP_CRYPTO_RANDOM_MAX) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        if (crypto_random(buf, n) != 0) {
            secure_wipe(buf, sizeof(buf));
            return status_reply(TEP_STATUS_UNAVAILABLE);
        }
        seL4_SetMR(0, n);
        seL4_Word words = ipc_put_bytes(1, buf, n);
        secure_wipe(buf, sizeof(buf));
        return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, 1 + words);
    }
    case TEP_CRYPTO_SHA256: {
        seL4_Word n = seL4_GetMR(0);
        uint8_t digest[SHA256_DIGEST_SIZE];
        if (n == 0 || n > TEP_CRYPTO_SHA256_MAX || len != 1 + TEP_BYTES_WORDS(n)) {
            return status_reply(TEP_STATUS_BAD_LENGTH);
        }
        ipc_get_bytes(1, buf, n);
        sha256(buf, n, digest);
        return seL4_MessageInfo_new(TEP_STATUS_OK, 0, 0, ipc_put_bytes(0, digest, sizeof(digest)));
    }
    default:
        return status_reply(TEP_STATUS_BAD_LABEL);
    }
}

static void call_root_or_fail(seL4_Word label, seL4_Word len, const char *what)
{
    seL4_MessageInfo_t info = seL4_Call(TEP_SVC_SLOT_CONTROL, seL4_MessageInfo_new(label, 0, 0, len));

    if (seL4_MessageInfo_get_label(info) != TEP_STATUS_OK) {
        svc_fail(what);
    }
}

int main(seL4_Word ipc_buffer, seL4_Word id, seL4_Word dma_paddr, seL4_Word dev_offset)
{
    (void)id;

    if (tep_tls_init() == 0) {
        svc_fail("TLS setup failed");
    }
    seL4_SetIPCBuffer((seL4_IPCBuffer *)ipc_buffer);
    tep_log("started");

    self_tests();

    if (dma_paddr == 0) {
        svc_fail("no DMA page");
    }
    int err = virtio_mmio_init(&rng, (void *)(TEP_SVC_DEVICE_BASE + dev_offset),
                               (void *)TEP_SVC_DMA_BASE, dma_paddr, VIRTIO_ID_ENTROPY);
    switch (err) {
    case VIRTIO_OK:
        break;
    case VIRTIO_NOT_VIRTIO:
        svc_fail("virtio-mmio slot 0 is not a modern virtio device "
                 "(QEMU needs the flags from `make qemu-devices`)");
    case VIRTIO_WRONG_DEVICE:
        svc_fail("no virtio-rng on virtio-mmio slot 0 (QEMU needs the flags from `make qemu-devices`)");
    default:
        svc_fail("virtio-rng initialisation failed");
    }
    tep_log("entropy source: virtio-rng");

    seed_drbg();
    tep_log("HMAC_DRBG seeded from the entropy source");

    uint8_t probe[16];
    if (crypto_random(probe, sizeof(probe)) != 0) {
        svc_fail("HMAC_DRBG generate failed");
    }
    secure_wipe(probe, sizeof(probe));

    seL4_SetMR(0, TEP_IPC_VERSION);
    call_root_or_fail(TEP_IPC_READY, TEP_IPC_READY_LEN, "root task rejected READY");

    tep_log("serving random and SHA-256 requests");

    for (;;) {
        seL4_Word badge;
        seL4_MessageInfo_t info = seL4_Recv(TEP_SVC_SLOT_ENDPOINT, &badge);

        if (badge & TEP_BADGE_CLIENT) {
            /* seL4_Reply before anything else: it never blocks, and leaves no reply pending. */
            seL4_Reply(handle_request(info));
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
