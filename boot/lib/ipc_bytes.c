/*
 * Byte strings in seL4 message registers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "ipc_bytes.h"

seL4_Word ipc_put_bytes(seL4_Word first, const void *data, size_t n)
{
    const uint8_t *p = data;
    seL4_Word words = (n + sizeof(seL4_Word) - 1) / sizeof(seL4_Word);

    for (seL4_Word w = 0; w < words; w++) {
        seL4_Word v = 0;
        for (seL4_Word b = 0; b < sizeof(seL4_Word) && w * sizeof(seL4_Word) + b < n; b++) {
            v |= (seL4_Word)p[w * sizeof(seL4_Word) + b] << (8 * b);
        }
        seL4_SetMR(first + w, v);
    }
    return words;
}

void ipc_get_bytes(seL4_Word first, void *out, size_t n)
{
    uint8_t *p = out;

    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(seL4_GetMR(first + i / sizeof(seL4_Word)) >> (8 * (i % sizeof(seL4_Word))));
    }
}
