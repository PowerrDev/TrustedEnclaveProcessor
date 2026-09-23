/*
 * Embeds the kernel and root task ELF images into the loader.
 * The files are found via the assembler include path (-Wa,-I<dir>).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

    .section .rodata.blobs, "a"

    .balign 8
    .global kernel_elf_start, kernel_elf_end
kernel_elf_start:
    .incbin "kernel.elf"
kernel_elf_end:

    .balign 8
    .global rootserver_elf_start, rootserver_elf_end
rootserver_elf_start:
    .incbin "rootserver.elf"
rootserver_elf_end:
