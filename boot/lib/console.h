/*
 * tepOS debug console output over the seL4 kernel console (CONFIG_PRINTING).
 * Shared by the root task and services.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <sel4/sel4.h>

#ifndef BIT
#define BIT(n) (1UL << (n))
#endif

/* Defined once per program, e.g. "tepOS" or "tepOS/diag". */
extern const char tep_log_prefix[];

void tep_puts(const char *s);
void tep_puthex(seL4_Word v);
void tep_putdec(seL4_Word v);

/* "<prefix>: <msg>\n" */
void tep_log(const char *msg);

/* "<prefix>: " without a message, for lines built from several parts. */
void tep_log_start(void);
