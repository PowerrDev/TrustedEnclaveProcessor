/*
 * tepOS debug console output.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "console.h"

void tep_puts(const char *s)
{
    for (; *s; s++) {
        seL4_DebugPutChar(*s);
    }
}

void tep_puthex(seL4_Word v)
{
    tep_puts("0x");
    for (int i = 60; i >= 0; i -= 4) {
        seL4_DebugPutChar("0123456789abcdef"[(v >> i) & 0xf]);
    }
}

void tep_putdec(seL4_Word v)
{
    char buf[21];
    int i = sizeof(buf) - 1;

    buf[i] = '\0';
    do {
        buf[--i] = '0' + v % 10;
        v /= 10;
    } while (v);
    tep_puts(&buf[i]);
}

void tep_log_start(void)
{
    tep_puts(tep_log_prefix);
    tep_puts(": ");
}

void tep_log(const char *msg)
{
    tep_log_start();
    tep_puts(msg);
    tep_puts("\n");
}
