/*
 * Thread-local storage for the initial thread of a tepOS program.
 *
 * libsel4 is built with CONFIG_LIB_SEL4_USE_THREAD_LOCALS, so the IPC buffer
 * pointer is a __thread variable. Each program's initial thread needs a real
 * AArch64 TLS block (variant I: TPIDR_EL0 points at a 16-byte TCB, followed
 * by the .tdata/.tbss image) before libsel4 can use message registers that do
 * not fit in hardware registers. The kernel saves and restores TPIDR_EL0 on
 * context switch, so setting it from EL0 is enough.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

/* Build the TLS block and point TPIDR_EL0 at it. Returns the TLS base or 0. */
seL4_Word tep_tls_init(void);
