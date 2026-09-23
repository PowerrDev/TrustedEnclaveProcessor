/*
 * Mailbox frame reader and writer.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "frame.h"
#include "pl011.h"

seL4_Word mb_discarded;

static seL4_Uint8 buf[TEP_MB_MAX_FRAME];
static seL4_Word have;

/* IEEE 802.3 CRC-32 (reflected, polynomial 0xEDB88320). */
static seL4_Uint32 crc32_update(seL4_Uint32 crc, const seL4_Uint8 *p, seL4_Word n)
{
    while (n--) {
        crc ^= *p++;
        for (int k = 0; k < 8; k++) {
            crc = (crc >> 1) ^ (0xedb88320u & -(crc & 1));
        }
    }
    return crc;
}

static seL4_Uint16 get16(const seL4_Uint8 *p)
{
    return p[0] | (seL4_Uint16)p[1] << 8;
}

static seL4_Uint32 get32(const seL4_Uint8 *p)
{
    return p[0] | (seL4_Uint32)p[1] << 8 | (seL4_Uint32)p[2] << 16 | (seL4_Uint32)p[3] << 24;
}

static void put16(seL4_Uint8 *p, seL4_Uint16 v)
{
    p[0] = v;
    p[1] = v >> 8;
}

static void put32(seL4_Uint8 *p, seL4_Uint32 v)
{
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

/* Drop the first buffered byte and restart at the next possible magic. */
static void resync(void)
{
    seL4_Word start = 1;

    while (start < have && buf[start] != (TEP_MB_MAGIC & 0xff)) {
        start++;
    }
    mb_discarded += start;
    for (seL4_Word i = start; i < have; i++) {
        buf[i - start] = buf[i];
    }
    have -= start;
}

/* Is the buffered prefix still a possible frame? */
static int prefix_ok(void)
{
    if (have >= 1 && buf[0] != (TEP_MB_MAGIC & 0xff)) {
        return 0;
    }
    if (have >= 2 && buf[1] != (TEP_MB_MAGIC >> 8)) {
        return 0;
    }
    if (have >= TEP_MB_HEADER_LEN && get16(&buf[12]) > TEP_MB_MAX_PAYLOAD) {
        return 0;
    }
    return 1;
}

int mb_feed(seL4_Uint8 byte, struct mb_frame *out)
{
    buf[have++] = byte;

    for (;;) {
        while (have > 0 && !prefix_ok()) {
            resync();
        }
        if (have < TEP_MB_HEADER_LEN) {
            return 0;
        }

        seL4_Word len = get16(&buf[12]);
        seL4_Word total = TEP_MB_HEADER_LEN + len + TEP_MB_CRC_LEN;
        if (have < total) {
            return 0;
        }

        seL4_Uint32 crc = crc32_update(0xffffffffu, buf, TEP_MB_HEADER_LEN + len) ^ 0xffffffffu;
        if (crc != get32(&buf[TEP_MB_HEADER_LEN + len])) {
            resync();
            continue;
        }

        out->version = buf[2];
        out->type = buf[3];
        out->command = get16(&buf[4]);
        out->status = get16(&buf[6]);
        out->request_id = get32(&buf[8]);
        out->payload_len = len;
        for (seL4_Word i = 0; i < len; i++) {
            out->payload[i] = buf[TEP_MB_HEADER_LEN + i];
        }
        /* One frame per call; a frame never shares the buffer with the next. */
        have = 0;
        return 1;
    }
}

void mb_send(const struct mb_frame *f)
{
    seL4_Uint8 hdr[TEP_MB_HEADER_LEN];
    seL4_Uint8 trailer[TEP_MB_CRC_LEN];

    put16(&hdr[0], TEP_MB_MAGIC);
    hdr[2] = f->version;
    hdr[3] = f->type;
    put16(&hdr[4], f->command);
    put16(&hdr[6], f->status);
    put32(&hdr[8], f->request_id);
    put16(&hdr[12], f->payload_len);
    put16(&hdr[14], 0);

    seL4_Uint32 crc = crc32_update(0xffffffffu, hdr, sizeof(hdr));
    crc = crc32_update(crc, f->payload, f->payload_len) ^ 0xffffffffu;
    put32(trailer, crc);

    for (seL4_Word i = 0; i < sizeof(hdr); i++) {
        pl011_putc(hdr[i]);
    }
    for (seL4_Word i = 0; i < f->payload_len; i++) {
        pl011_putc(f->payload[i]);
    }
    for (seL4_Word i = 0; i < sizeof(trailer); i++) {
        pl011_putc(trailer[i]);
    }
}
