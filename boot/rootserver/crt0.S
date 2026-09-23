/*
 * Root task entry. The kernel starts us with x0 = seL4_BootInfo pointer.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .text.start, "ax"
    .global _start
_start:
    ldr     x1, =stack_top
    mov     sp, x1
    bl      main
1:  b       1b

    .bss
    .balign 16
stack:
    .space  16384
stack_top:
