/*
 * tepOS capability slot allocator for the root task's CNode.
 *
 * Manages the free slot range the kernel reports in BootInfo (bi->empty).
 * The root CNode is a single level, so a slot index is also a CPtr with
 * depth seL4_WordBits.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

int tep_cspace_init(const seL4_BootInfo *bi);

/* Returns an empty slot, or seL4_CapNull when the CNode is full. */
seL4_CPtr tep_cslot_alloc(void);

/*
 * Delete whatever capability is in the slot and return it to the allocator.
 * Deleting the last capability to an object destroys the object.
 */
void tep_cslot_free(seL4_CPtr slot);

seL4_Word tep_cslots_free_count(void);
