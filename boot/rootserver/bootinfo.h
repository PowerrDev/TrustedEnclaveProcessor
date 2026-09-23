/*
 * seL4 BootInfo validation for the tepOS root task.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

/*
 * Check that the BootInfo frame handed over by the kernel is self-consistent
 * before anything relies on it. Returns NULL on success, otherwise a static
 * string describing the first problem found.
 */
const char *tep_bootinfo_validate(const seL4_BootInfo *bi);

/* Print a short summary of the resources the kernel gave us. */
void tep_bootinfo_report(const seL4_BootInfo *bi);
