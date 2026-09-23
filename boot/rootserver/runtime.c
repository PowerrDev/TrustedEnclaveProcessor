/*
 * tepOS root task runtime.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "runtime.h"
#include "tls.h"

const char tep_log_prefix[] = "tepOS";

int tep_runtime_init(const seL4_BootInfo *bi)
{
    seL4_Word tp = tep_tls_init();

    if (tp == 0) {
        tep_log("runtime: TLS setup failed");
        return -1;
    }
    seL4_SetIPCBuffer(bi->ipcBuffer);

    /*
     * Record the TLS base in our TCB as well. Done after the IPC buffer is
     * set because the invocation stub spills to the IPC buffer on error.
     */
    seL4_Error err = seL4_TCB_SetTLSBase(seL4_CapInitThreadTCB, tp);
    if (err != seL4_NoError) {
        tep_log_start();
        tep_puts("runtime: TCB_SetTLSBase failed, error ");
        tep_putdec(err);
        tep_puts("\n");
        return -1;
    }

    if (seL4_GetIPCBuffer() != bi->ipcBuffer) {
        tep_log("runtime: IPC buffer readback mismatch");
        return -1;
    }
    return 0;
}

void tep_fatal(const char *msg)
{
    tep_log_start();
    tep_puts("FATAL: ");
    tep_puts(msg);
    tep_puts("\n");
    tep_log("root task suspended; tepOS unavailable");

    for (;;) {
        seL4_TCB_Suspend(seL4_CapInitThreadTCB);
    }
}
