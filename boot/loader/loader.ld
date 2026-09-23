/* SPDX-License-Identifier: BSD-2-Clause */

ENTRY(_start)

SECTIONS
{
    /* Well clear of the kernel (start of RAM) and QEMU's DTB, which QEMU
     * places at the start of RAM for bare-metal ELF images. */
    . = 0x60000000;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    }
    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    }
    .data : ALIGN(8) {
        *(.data .data.*)
    }
    .bss (NOLOAD) : ALIGN(4096) {
        __bss_start = .;
        *(.bss .bss.* COMMON)
        . = ALIGN(8);
        __bss_end = .;
    }

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
