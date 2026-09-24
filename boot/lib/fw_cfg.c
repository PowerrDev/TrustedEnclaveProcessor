/*
 * QEMU fw_cfg, MMIO interface (docs/specs/fw_cfg.rst in QEMU): a 16-bit
 * big-endian selector register at +8 and a data register at +0 read a byte
 * at a time. Selector 0x0000 returns the "QEMU" signature; 0x0019 returns
 * the file directory: a big-endian u32 count, then 64-byte entries
 * { u32 size, u16 select, u16 reserved, char name[56] }, all big-endian.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "fw_cfg.h"

#define FW_CFG_DATA     0x00
#define FW_CFG_SELECTOR 0x08

#define FW_CFG_SIGNATURE 0x0000
#define FW_CFG_FILE_DIR  0x0019

static void select_key(uintptr_t base, uint16_t key)
{
    *(volatile uint16_t *)(base + FW_CFG_SELECTOR) = (uint16_t)(key >> 8 | key << 8);
}

static uint8_t read8(uintptr_t base)
{
    return *(volatile uint8_t *)(base + FW_CFG_DATA);
}

static uint32_t read_be32(uintptr_t base)
{
    uint32_t v = 0;

    for (int i = 0; i < 4; i++) {
        v = v << 8 | read8(base);
    }
    return v;
}

long fw_cfg_read_file(uintptr_t base, const char *name, void *out, size_t max)
{
    select_key(base, FW_CFG_SIGNATURE);
    if (read8(base) != 'Q' || read8(base) != 'E' || read8(base) != 'M' || read8(base) != 'U') {
        return -1;
    }

    select_key(base, FW_CFG_FILE_DIR);
    uint32_t count = read_be32(base);

    for (uint32_t e = 0; e < count; e++) {
        uint32_t size = read_be32(base);
        uint16_t key = (uint16_t)(read8(base) << 8);
        key |= read8(base);
        (void)read8(base);
        (void)read8(base);

        int match = 1;
        int ended = 0;
        for (int i = 0; i < 56; i++) {
            char c = (char)read8(base);
            if (ended) {
                continue;
            }
            if (c != name[i]) {
                match = 0;
            }
            if (c == '\0' || name[i] == '\0') {
                ended = 1;
            }
        }
        if (!match) {
            continue;
        }

        select_key(base, key);
        uint8_t *p = out;
        for (uint32_t i = 0; i < size && i < max; i++) {
            p[i] = read8(base);
        }
        return (long)size;
    }
    return -1;
}
