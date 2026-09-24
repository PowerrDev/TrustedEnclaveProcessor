/*
 * __assert_fail for tepOS programs. libsel4's generated bitfield helpers
 * (seL4_MessageInfo_new, ...) assert their arguments fit. A failed assertion
 * is a bug: log it and fault, so the root task (or, for the root task
 * itself, the kernel) sees the program stop instead of it carrying on with a
 * truncated value.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "console.h"

void __assert_fail(const char *expr, const char *file, int line, const char *function);

void __assert_fail(const char *expr, const char *file, int line, const char *function)
{
    tep_log_start();
    tep_puts("assertion failed: ");
    tep_puts(expr);
    tep_puts(" (");
    tep_puts(function);
    tep_puts(", ");
    tep_puts(file);
    tep_puts(":");
    tep_putdec((seL4_Word)line);
    tep_puts(")\n");
    for (;;) {
        *(volatile seL4_Word *)0 = 0;
    }
}
