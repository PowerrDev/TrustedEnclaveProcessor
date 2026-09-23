/*
 * Thread-local storage for the initial thread of a tepOS program.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "tls.h"

/* Referenced by libsel4's seL4_GetIPCBuffer()/seL4_SetMR() etc. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

/* TLS image bounds, from program.ld. */
extern char __tdata_start[], __tdata_end[], __tbss_start[], __tbss_end[];

#define TLS_TCB_SIZE  16
#define TLS_AREA_SIZE 256

static char tls_area[TLS_AREA_SIZE] __attribute__((aligned(16)));

static seL4_Word read_tpidr_el0(void)
{
    seL4_Word v;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(v));
    return v;
}

seL4_Word tep_tls_init(void)
{
    seL4_Word tdata_size = __tdata_end - __tdata_start;
    seL4_Word image_size = __tbss_end - __tdata_start;
    seL4_Word tp = (seL4_Word)tls_area;

    /* .tbss must directly follow .tdata (see program.ld). */
    if ((seL4_Word)__tbss_start < (seL4_Word)__tdata_end || image_size > TLS_AREA_SIZE - TLS_TCB_SIZE) {
        return 0;
    }

    for (seL4_Word i = 0; i < TLS_AREA_SIZE; i++) {
        tls_area[i] = 0;
    }
    for (seL4_Word i = 0; i < tdata_size; i++) {
        tls_area[TLS_TCB_SIZE + i] = __tdata_start[i];
    }

    __asm__ volatile("msr tpidr_el0, %0" :: "r"(tp) : "memory");
    return read_tpidr_el0() == tp ? tp : 0;
}
