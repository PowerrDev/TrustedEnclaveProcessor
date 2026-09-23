/*
 * tepOS kernel object allocator on top of the BootInfo untypeds.
 *
 * Objects are retyped from RAM untypeds with a best-fit policy. Each untyped's
 * free offset is mirrored from the kernel's retype rules, so the allocator
 * knows what fits without asking. Objects are not freed individually: seL4
 * only reclaims untyped memory when every object carved from it has been
 * deleted, which the root task does not do.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

int tep_untyped_init(const seL4_BootInfo *bi);

/*
 * Create one kernel object of the given type in a fresh root CNode slot.
 * size_bits only matters for variable-sized objects (CNode: log2 slots,
 * untyped: log2 bytes). Returns the new capability, or seL4_CapNull.
 */
seL4_CPtr tep_object_alloc(seL4_Word type, seL4_Word size_bits);

/* Totals over RAM untypeds, in bytes. */
seL4_Word tep_untyped_ram_total(void);
seL4_Word tep_untyped_ram_used(void);
seL4_Word tep_untyped_ram_count(void);
