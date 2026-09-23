/*
 * tepOS root task runtime: debug console output, thread-local storage and
 * the seL4 IPC buffer.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <sel4/sel4.h>

#define TEPOS_VERSION "0.1.0"

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

/* Kernel debug console (CONFIG_PRINTING). */
void tep_puts(const char *s);
void tep_puthex(seL4_Word v);
void tep_putdec(seL4_Word v);

/* "tepOS: <msg>\n" */
void tep_log(const char *msg);

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
