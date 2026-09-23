/*
 * Embeds the service ELF images into the root task.
 * The files are found via the assembler include path (-Wa,-I<dir>).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
    .section .rodata.services, "a"
    .balign 8
    .global diag_elf_start, diag_elf_end
diag_elf_start:
    .incbin "diagsvc.elf"
diag_elf_end:
