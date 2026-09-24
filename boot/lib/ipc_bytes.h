/*
 * Byte strings in seL4 message registers: packed little-endian, 8 bytes per
 * register, starting at a given register.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sel4/sel4.h>

/* Write n bytes into MR[first] onwards; returns the registers used. */
seL4_Word ipc_put_bytes(seL4_Word first, const void *data, size_t n);

/* Read n bytes from MR[first] onwards. */
void ipc_get_bytes(seL4_Word first, void *out, size_t n);
