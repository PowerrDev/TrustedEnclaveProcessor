/* SPDX-License-Identifier: BSD-2-Clause */

ENTRY(_start)

SECTIONS
{
    . = 0x400000;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    }
    .rodata : ALIGN(8) {
        *(.rodata .rodata.*)
    }
    .data : ALIGN(4096) {
        *(.data .data.*)
    }
    /* TLS template for the initial thread; runtime.c copies it into place. */
    .tdata : ALIGN(16) {
        __tdata_start = .;
        *(.tdata .tdata.*)
        __tdata_end = .;
    }
    .tbss : ALIGN(16) {
        __tbss_start = .;
        *(.tbss .tbss.*)
        __tbss_end = .;
    }
    .bss : ALIGN(16) {
        *(.bss .bss.* COMMON)
    }

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
