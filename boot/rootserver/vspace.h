/*
 * tepOS root task virtual memory: maps fresh frames into a reserved window of
 * the root task's own address space.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

/* Window for root task dynamic memory, well clear of the image at 0x400000. */
#define TEP_HEAP_BASE 0x10000000UL
#define TEP_HEAP_SIZE 0x10000000UL

int tep_vspace_init(void);

/*
 * Map npages zeroed, read/write, non-executable pages and return their base
 * address, or NULL. Pages stay mapped for the life of the root task.
 */
void *tep_pages_alloc(seL4_Word npages);

seL4_Word tep_pages_mapped(void);
