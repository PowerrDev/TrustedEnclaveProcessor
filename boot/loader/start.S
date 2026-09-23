/*
 * Minimal AArch64 boot loader entry for seL4 on QEMU virt.
 *
 * QEMU enters here (at EL1, or EL2 with virtualization=on) with the MMU off.
 * We drop to EL1 if needed, set up a stack and call loader_main(), which
 * copies the kernel and root task into place and never returns.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define SCTLR_EL1_RES1  0x30d00800  /* RES1 bits, MMU/caches off, little endian */
#define HCR_EL2_RW      (1 << 31)   /* EL1 is AArch64 */
#define SPSR_EL1H_MASKED 0x3c5      /* EL1h, DAIF masked */

    .section .text.start, "ax"
    .global _start
_start:
    msr     daifset, #0xf

    /* Only the primary core boots; park any others. */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xff
    cbnz    x0, park

    mrs     x0, CurrentEL
    lsr     x0, x0, #2
    cmp     x0, #2
    b.ne    at_el1

    /* EL2 -> EL1 */
    ldr     x0, =HCR_EL2_RW
    msr     hcr_el2, x0
    mrs     x0, cnthctl_el2
    orr     x0, x0, #3              /* EL1 access to physical counter/timer */
    msr     cnthctl_el2, x0
    msr     cntvoff_el2, xzr
    ldr     x0, =SCTLR_EL1_RES1
    msr     sctlr_el1, x0
    mov     x0, #SPSR_EL1H_MASKED
    msr     spsr_el2, x0
    adr     x0, at_el1
    msr     elr_el2, x0
    isb
    eret

at_el1:
    ldr     x0, =SCTLR_EL1_RES1
    msr     sctlr_el1, x0
    isb

    ldr     x0, =loader_stack_top
    mov     sp, x0

    /* Clear .bss */
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
1:  cmp     x0, x1
    b.hs    2f
    str     xzr, [x0], #8
    b       1b
2:
    bl      loader_main

park:
    wfe
    b       park

/*
 * void enable_mmu_and_jump(u64 mair, u64 tcr, u64 ttbr0, u64 ttbr1,
 *                          u64 entry, u64 args[6])
 */
    .text
    .global enable_mmu_and_jump
enable_mmu_and_jump:
    mov     x19, x4
    mov     x20, x5

    msr     mair_el1, x0
    msr     tcr_el1, x1
    msr     ttbr0_el1, x2
    msr     ttbr1_el1, x3
    isb
    tlbi    vmalle1
    ic      iallu
    dsb     sy
    isb

    mrs     x0, sctlr_el1
    orr     x0, x0, #(1 << 0)       /* M */
    orr     x0, x0, #(1 << 2)       /* C */
    orr     x0, x0, #(1 << 12)      /* I */
    msr     sctlr_el1, x0
    isb

    ldp     x0, x1, [x20, #0]
    ldp     x2, x3, [x20, #16]
    ldp     x4, x5, [x20, #32]
    br      x19

    .bss
    .balign 16
loader_stack:
    .space  16384
loader_stack_top:
