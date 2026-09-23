/*
 * Program entry for the root task and services. x0-x3 are passed to main():
 * the kernel starts the root task with x0 = seL4_BootInfo pointer; the root
 * task starts services with arguments of its choosing.
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
