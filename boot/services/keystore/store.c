/*
 * KeyStore persistence. See store.h -- in particular, why this is not a
 * protection boundary.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>

#include "fw_cfg.h"
#include "monocypher.h"
#include "store.h"
#include "virtio_mmio.h"

#define SECTOR 512
#define REGION_SECTORS 16
#define MAGIC "TEPKEYS1"
#define FORMAT_VERSION 2u      /* 1: keys only; 2: keys and records (1 still loads) */
#define KEK_NAME "opt/org.tepos/kek"
#define KEK_SIZE 32
#define AD_SIZE 24          /* magic, version, generation, length: authenticated, not secret */

/* virtio-blk (virtio 1.2 section 5.2.6) */
#define BLK_T_IN  0
#define BLK_T_OUT 1
#define BLK_S_OK  0
#define DMA_HDR    0x400
#define DMA_DATA   0x600
#define DMA_STATUS 0x800
#define BLK_MAX_POLLS 1000000

/*
 * Sealed table: u32 key count, u32 record count (0 in version 1), then the
 * keys, then the records.
 */
#define RECORD_SIZE (4 + 4 + 8 + 64 + TEP_KS_PUBLIC_KEY_SIZE)
#define DATA_RECORD_SIZE (8 + 1 + 1 + 2 + 4 + TEP_KS_RECORD_MAX)
#define TABLE_MAX (8 + TEP_KS_MAX_KEYS * RECORD_SIZE + TEP_KS_MAX_RECORDS * DATA_RECORD_SIZE)
_Static_assert(TABLE_MAX <= (REGION_SECTORS - 1) * SECTOR, "sealed table must fit its region");

static struct virtio_dev blk;
static uint64_t capacity;
static uint8_t kek[KEK_SIZE];
static uint64_t newest_generation;
static int newest_region = -1;
static uint8_t table[(REGION_SECTORS - 1) * SECTOR];

static void yield(void)
{
    seL4_Yield();
}

static void put32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static uint32_t get32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t get64(const uint8_t *p)
{
    return get32(p) | (uint64_t)get32(p + 4) << 32;
}

/* Read or write one sector through the DMA page. Returns 0 or -1. */
static int sector_io(uint64_t sector, uint8_t *buf, int write)
{
    if (sector >= capacity) {
        return -1;
    }
    put32(blk.dma + DMA_HDR, write ? BLK_T_OUT : BLK_T_IN);
    put32(blk.dma + DMA_HDR + 4, 0);
    put64(blk.dma + DMA_HDR + 8, sector);
    if (write) {
        for (int i = 0; i < SECTOR; i++) {
            blk.dma[DMA_DATA + i] = buf[i];
        }
    }
    blk.dma[DMA_STATUS] = 0xff;

    struct virtio_buf bufs[3] = {
        { .offset = DMA_HDR, .len = 16, .device_writes = 0 },
        { .offset = DMA_DATA, .len = SECTOR, .device_writes = !write },
        { .offset = DMA_STATUS, .len = 1, .device_writes = 1 },
    };
    if (virtio_mmio_transfer(&blk, bufs, 3, yield, BLK_MAX_POLLS) < 0 || blk.dma[DMA_STATUS] != BLK_S_OK) {
        return -1;
    }
    if (!write) {
        for (int i = 0; i < SECTOR; i++) {
            buf[i] = blk.dma[DMA_DATA + i];
        }
    }
    crypto_wipe(blk.dma + DMA_DATA, SECTOR);
    return 0;
}

const char *store_init(uintptr_t blk_regs, void *dma, uint64_t dma_pa, uintptr_t fw_cfg)
{
    int err = virtio_mmio_init(&blk, (void *)blk_regs, dma, dma_pa, VIRTIO_ID_BLOCK);

    if (err != VIRTIO_OK) {
        return "no key store disk (virtio-blk on virtio-mmio slot 8; see `make qemu-devices`)";
    }
    capacity = virtio_mmio_config32(&blk, 0) | (uint64_t)virtio_mmio_config32(&blk, 4) << 32;
    if (capacity < 2 * REGION_SECTORS) {
        return "key store disk too small";
    }
    if (fw_cfg_read_file(fw_cfg, KEK_NAME, kek, sizeof(kek)) != KEK_SIZE) {
        crypto_wipe(kek, sizeof(kek));
        return "no 32-byte sealing key in fw_cfg " KEK_NAME;
    }
    return NULL;
}

/* Try to open region r into table[]. Returns the plaintext length, or -1. */
static long open_region(int r, uint64_t *generation, int *present)
{
    uint8_t header[SECTOR];
    uint64_t base = (uint64_t)r * REGION_SECTORS;

    *present = 0;
    if (sector_io(base, header, 0) != 0) {
        return -1;
    }
    for (int i = 0; i < 8; i++) {
        if (header[i] != (uint8_t)MAGIC[i]) {
            return -1;
        }
    }
    *present = 1;

    uint32_t length = get32(header + 20);
    uint32_t version = get32(header + 8);
    if ((version != 1 && version != FORMAT_VERSION) || length < 8 || length > TABLE_MAX) {
        return -1;
    }
    for (uint32_t s = 0; s * SECTOR < length; s++) {
        if (sector_io(base + 1 + s, table + s * SECTOR, 0) != 0) {
            return -1;
        }
    }
    /* header: magic[8] version[4] generation[8] length[4] | nonce[24] mac[16] */
    if (crypto_aead_unlock(table, header + AD_SIZE + STORE_NONCE_SIZE, kek, header + AD_SIZE,
                           header, AD_SIZE, table, length) != 0) {
        crypto_wipe(table, sizeof(table));
        return -1;
    }
    *generation = get64(header + 12);
    return (long)length;
}

const char *store_load(struct key *keys, int max, struct record *records, int max_records,
                       int *count)
{
    int any_present = 0;
    int best = -1;
    uint64_t best_generation = 0;

    *count = 0;
    for (int r = 0; r < 2; r++) {
        uint64_t generation;
        int present;
        if (open_region(r, &generation, &present) >= 0 && (best < 0 || generation > best_generation)) {
            best = r;
            best_generation = generation;
        }
        any_present |= present;
    }
    crypto_wipe(table, sizeof(table));

    if (best < 0) {
        if (any_present) {
            return "sealed key store does not open (tampered, corrupt, or a different sealing key)";
        }
        newest_region = -1;     /* blank disk */
        newest_generation = 0;
        return NULL;
    }

    uint64_t generation;
    int present;
    long length = open_region(best, &generation, &present);
    if (length < 0) {
        return "sealed key store changed while loading";
    }
    uint32_t n = get32(table);
    uint32_t nrec = get32(table + 4);
    if (n > (uint32_t)max || nrec > (uint32_t)max_records ||
        8 + (long)n * RECORD_SIZE + (long)nrec * DATA_RECORD_SIZE != length) {
        crypto_wipe(table, sizeof(table));
        return "sealed key store has a malformed table";
    }
    for (uint32_t i = 0; i < nrec; i++) {
        const uint8_t *rec = table + 8 + n * RECORD_SIZE + i * DATA_RECORD_SIZE;
        if (rec[8] >= TEP_KS_RECORD_SLOTS || rec[9] > TEP_KS_RECORD_MAX) {
            crypto_wipe(table, sizeof(table));
            return "sealed key store has a malformed record";
        }
        records[i].in_use = 1;
        records[i].owner = (seL4_Word)get64(rec);
        records[i].slot = rec[8];
        records[i].len = rec[9];
        for (int b = 0; b < TEP_KS_RECORD_MAX; b++) {
            records[i].data[b] = rec[16 + b];
        }
    }
    for (uint32_t i = 0; i < n; i++) {
        const uint8_t *rec = table + 8 + i * RECORD_SIZE;
        keys[i].in_use = 1;
        keys[i].handle = get32(rec);
        keys[i].owner = (seL4_Word)get64(rec + 8);
        for (int b = 0; b < 64; b++) {
            keys[i].secret[b] = rec[16 + b];
        }
        for (int b = 0; b < TEP_KS_PUBLIC_KEY_SIZE; b++) {
            keys[i].public[b] = rec[80 + b];
        }
    }
    crypto_wipe(table, sizeof(table));
    newest_region = best;
    newest_generation = generation;
    *count = (int)n;
    return NULL;
}

int store_save(const struct key *keys, int max, const struct record *records, int max_records,
               const uint8_t nonce[STORE_NONCE_SIZE])
{
    uint8_t header[SECTOR] = { 0 };
    uint32_t n = 0;
    int r = newest_region == 0 ? 1 : 0;
    uint64_t base = (uint64_t)r * REGION_SECTORS;

    for (int i = 0; i < max; i++) {
        if (!keys[i].in_use) {
            continue;
        }
        uint8_t *rec = table + 8 + n * RECORD_SIZE;
        put32(rec, keys[i].handle);
        put32(rec + 4, 0);
        put64(rec + 8, keys[i].owner);
        for (int b = 0; b < 64; b++) {
            rec[16 + b] = keys[i].secret[b];
        }
        for (int b = 0; b < TEP_KS_PUBLIC_KEY_SIZE; b++) {
            rec[80 + b] = keys[i].public[b];
        }
        n++;
    }
    uint32_t nrec = 0;
    for (int i = 0; i < max_records; i++) {
        if (!records[i].in_use) {
            continue;
        }
        uint8_t *rec = table + 8 + n * RECORD_SIZE + nrec * DATA_RECORD_SIZE;
        put64(rec, records[i].owner);
        rec[8] = records[i].slot;
        rec[9] = records[i].len;
        rec[10] = rec[11] = 0;
        put32(rec + 12, 0);
        for (int b = 0; b < TEP_KS_RECORD_MAX; b++) {
            rec[16 + b] = records[i].data[b];
        }
        nrec++;
    }
    put32(table, n);
    put32(table + 4, nrec);
    uint32_t length = 8 + n * RECORD_SIZE + nrec * DATA_RECORD_SIZE;

    for (int i = 0; i < 8; i++) {
        header[i] = (uint8_t)MAGIC[i];
    }
    put32(header + 8, FORMAT_VERSION);
    put64(header + 12, newest_generation + 1);
    put32(header + 20, length);
    for (int i = 0; i < STORE_NONCE_SIZE; i++) {
        header[AD_SIZE + i] = nonce[i];
    }
    crypto_aead_lock(table, header + AD_SIZE + STORE_NONCE_SIZE, kek, header + AD_SIZE,
                     header, AD_SIZE, table, length);

    /* Payload first, header last: the header makes the region count. */
    for (uint32_t s = 0; s * SECTOR < length; s++) {
        if (sector_io(base + 1 + s, table + s * SECTOR, 1) != 0) {
            crypto_wipe(table, sizeof(table));
            return -1;
        }
    }
    crypto_wipe(table, sizeof(table));
    if (sector_io(base, header, 1) != 0) {
        return -1;
    }
    newest_region = r;
    newest_generation++;
    return 0;
}
