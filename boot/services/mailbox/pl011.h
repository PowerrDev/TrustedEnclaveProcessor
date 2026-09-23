/*
 * PL011 UART, polled TX and interrupt-driven RX, for the mailbox link.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

/* Check the PrimeCell IDs and set up 8N1 with FIFOs and RX interrupts. */
int pl011_init(seL4_Word base);

/* Returns the next received byte, or -1 when the RX FIFO is empty. */
int pl011_getc(void);

void pl011_putc(unsigned char c);

/* Clear the UART's interrupt status; call before draining RX. */
void pl011_clear_irq(void);
