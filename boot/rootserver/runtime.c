/*
 * tepOS root task runtime.
 *
 * libsel4 is built with CONFIG_LIB_SEL4_USE_THREAD_LOCALS, so the IPC buffer
 * pointer is a __thread variable. The initial thread therefore needs a real
 * AArch64 TLS block (variant I: TPIDR_EL0 points at a 16-byte TCB, followed by
 * the .tdata/.tbss image) before libsel4 can use message registers that do
 * not fit in hardware registers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "runtime.h"

/* Referenced by libsel4's seL4_GetIPCBuffer()/seL4_SetMR() etc. */
__thread seL4_IPCBuffer *__sel4_ipc_buffer;

/* TLS image bounds, from program.ld. */
extern char __tdata_start[], __tdata_end[], __tbss_start[], __tbss_end[];

#define TLS_TCB_SIZE  16
#define TLS_AREA_SIZE 256

static char tls_area[TLS_AREA_SIZE] __attribute__((aligned(16)));

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

void tep_log(const char *msg)
{
    tep_puts("tepOS: ");
    tep_puts(msg);
    tep_puts("\n");
}

static seL4_Word read_tpidr_el0(void)
{
    seL4_Word v;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(v));
    return v;
}

static int tls_init(void)
{
    seL4_Word tdata_size = __tdata_end - __tdata_start;
    seL4_Word image_size = __tbss_end - __tdata_start;
    seL4_Word tp = (seL4_Word)tls_area;

    /* .tbss must directly follow .tdata (see program.ld). */
    if ((seL4_Word)__tbss_start < (seL4_Word)__tdata_end || image_size > TLS_AREA_SIZE - TLS_TCB_SIZE) {
        return -1;
    }

    for (seL4_Word i = 0; i < TLS_AREA_SIZE; i++) {
        tls_area[i] = 0;
    }
    for (seL4_Word i = 0; i < tdata_size; i++) {
        tls_area[TLS_TCB_SIZE + i] = __tdata_start[i];
    }

    __asm__ volatile("msr tpidr_el0, %0" :: "r"(tp) : "memory");
    return 0;
}

int tep_runtime_init(const seL4_BootInfo *bi)
{
    seL4_Word tp = (seL4_Word)tls_area;

    if (tls_init() != 0) {
        tep_log("runtime: TLS image does not fit");
        return -1;
    }
    seL4_SetIPCBuffer(bi->ipcBuffer);

    /*
     * Record the TLS base in our TCB as well, so the kernel restores it on
     * every return to this thread. Done after the IPC buffer is set because
     * the invocation stub spills to the IPC buffer on error.
     */
    seL4_Error err = seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);
    if (err != seL4_NoError) {
        tep_puts("tepOS: runtime: TCB_SetTLSBase failed, error ");
        tep_putdec(err);
        tep_puts("\n");
        return -1;
    }

    if (read_tpidr_el0() != tp || seL4_GetIPCBuffer() != bi->ipcBuffer) {
        tep_log("runtime: TLS/IPC buffer readback mismatch");
        return -1;
    }
    return 0;
}

void tep_fatal(const char *msg)
{
    tep_puts("tepOS: FATAL: ");
    tep_puts(msg);
    tep_puts("\n");
    tep_log("root task suspended; tepOS unavailable");

    for (;;) {
        seL4_TCB_Suspend(seL4_CapInitThreadTCB);
    }
}
