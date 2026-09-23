/*
 * Link layout for tepOS programs (root task and services).
 *
 * Separate page-aligned segments keep code, read-only data and writable data
 * apart, so a loader can map them R-X, R-- and RW- (W^X).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

ENTRY(_start)

PHDRS
{
    text   PT_LOAD FLAGS(5);    /* R-X */
    rodata PT_LOAD FLAGS(4);    /* R-- */
    data   PT_LOAD FLAGS(6);    /* RW- */
    tls    PT_TLS  FLAGS(4);
}

SECTIONS
{
    . = 0x400000;

    .text : {
        KEEP(*(.text.start))
        *(.text .text.*)
    } :text

    . = ALIGN(4096);
    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(4096);
    /* TLS template for the initial thread; tls.c copies it into place. */
    .tdata : ALIGN(16) {
        __tdata_start = .;
        *(.tdata .tdata.*)
        __tdata_end = .;
    } :data :tls
    .tbss : ALIGN(16) {
        __tbss_start = .;
        *(.tbss .tbss.*)
        __tbss_end = .;
    } :data :tls
    .data : ALIGN(16) {
        *(.data .data.*)
    } :data
    .bss : ALIGN(16) {
        *(.bss .bss.* COMMON)
    } :data

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
