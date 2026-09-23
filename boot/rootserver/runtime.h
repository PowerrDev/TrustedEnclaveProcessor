/*
 * tepOS root task runtime: thread-local storage and the seL4 IPC buffer.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

#include "console.h"

#define TEPOS_VERSION "0.1.0"

/*
 * Set up the initial thread's TLS block and IPC buffer. Must run before any
 * libsel4 call that touches message registers beyond the hardware ones.
 * Returns 0 on success.
 */
int tep_runtime_init(const seL4_BootInfo *bi);

/*
 * Stop this thread after an unrecoverable initialisation error. tepOS fails
 * closed: it suspends itself instead of continuing half-initialised.
 */
void __attribute__((noreturn)) tep_fatal(const char *msg);
