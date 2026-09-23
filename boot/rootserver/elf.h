/*
 * Load a service ELF image into a fresh VSpace.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

#include "untyped.h"

/* Service images must lie entirely inside this window. */
#define TEP_SVC_IMAGE_BASE 0x400000UL
#define TEP_SVC_IMAGE_TOP  0x10000000UL

/*
 * Validate the image and map each PT_LOAD segment into vspace with its own
 * permissions (W^X enforced). Frames and page tables come from alloc.
 * Returns NULL and sets *entry on success, otherwise a static string
 * describing the problem.
 */
const char *tep_elf_load(const void *image, seL4_Word size, seL4_CPtr vspace,
                         tep_alloc_fn alloc, void *ctx, seL4_Word *entry);
