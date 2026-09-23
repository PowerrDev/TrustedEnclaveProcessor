/*
 * tepOS root task virtual memory: maps fresh frames into a reserved window of
 * the root task's own address space.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

#include "untyped.h"

/* Window for root task dynamic memory, well clear of the image at 0x400000. */
#define TEP_HEAP_BASE 0x10000000UL
#define TEP_HEAP_SIZE 0x10000000UL

/* One page in the root task, used to fill frames destined for other VSpaces. */
#define TEP_SCRATCH_VADDR (TEP_HEAP_BASE + TEP_HEAP_SIZE)

int tep_vspace_init(void);

/*
 * Map a frame into any VSpace, creating page tables as needed with alloc
 * (their caps stay in the root CNode). Returns 0 on success.
 */
int tep_map_frame(seL4_CPtr vspace, seL4_CPtr frame, seL4_Word vaddr,
                  seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,
                  tep_alloc_fn alloc, void *ctx);

/*
 * Map npages zeroed, read/write, non-executable pages and return their base
 * address, or NULL. Pages stay mapped for the life of the root task.
 */
void *tep_pages_alloc(seL4_Word npages);

seL4_Word tep_pages_mapped(void);
