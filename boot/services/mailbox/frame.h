/*
 * Mailbox frame reader and writer (see <tep/mailbox.h>).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>
#include <tep/mailbox.h>

struct mb_frame {
    seL4_Uint8 version;
    seL4_Uint8 type;
    seL4_Uint16 command;
    seL4_Uint16 status;
    seL4_Uint32 request_id;
    seL4_Uint16 payload_len;
    seL4_Uint8 payload[TEP_MB_MAX_PAYLOAD];
};

/*
 * Feed one received byte. Returns 1 when *out holds a complete frame with a
 * valid magic, length and CRC; 0 otherwise. Bytes that cannot start or
 * continue a valid frame are discarded, and counted in mb_discarded.
 */
int mb_feed(seL4_Uint8 byte, struct mb_frame *out);

extern seL4_Word mb_discarded;

/* Send a response frame; payload may be NULL when payload_len is 0. */
void mb_send(const struct mb_frame *f);
