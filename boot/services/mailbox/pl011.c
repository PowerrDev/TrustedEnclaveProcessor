/*
 * PL011 UART (ARM DDI 0183).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "pl011.h"

#define UART_DR    0x000
#define UART_FR    0x018
#define UART_LCR_H 0x02c
#define UART_CR    0x030
#define UART_IMSC  0x038
#define UART_ICR   0x044
#define UART_PERIPHID0 0xfe0
#define UART_CELLID0   0xff0

#define FR_RXFE (1u << 4)
#define FR_TXFF (1u << 5)
#define LCR_H_FEN  (1u << 4)
#define LCR_H_WLEN8 (3u << 5)
#define CR_UARTEN (1u << 0)
#define CR_TXE    (1u << 8)
#define CR_RXE    (1u << 9)
#define IMSC_RXIM (1u << 4)
#define IMSC_RTIM (1u << 6)
#define ICR_ALL   0x7ffu

static volatile seL4_Uint32 *regs;

static seL4_Uint32 rd(seL4_Word off)
{
    return regs[off / 4];
}

static void wr(seL4_Word off, seL4_Uint32 v)
{
    regs[off / 4] = v;
}

int pl011_init(seL4_Word base)
{
    static const seL4_Uint32 cell_id[4] = { 0x0d, 0xf0, 0x05, 0xb1 };

    regs = (volatile seL4_Uint32 *)base;
    for (int i = 0; i < 4; i++) {
        if ((rd(UART_CELLID0 + 4 * i) & 0xff) != cell_id[i]) {
            return -1;
        }
    }
    /* PeriphID: part number 0x011, designer ARM (0x41). */
    if ((rd(UART_PERIPHID0) & 0xff) != 0x11 || (rd(UART_PERIPHID0 + 4) & 0x0f) != 0x0 ||
        (rd(UART_PERIPHID0 + 8) & 0x0f) != 0x4) {
        return -1;
    }

    wr(UART_CR, 0);
    wr(UART_LCR_H, LCR_H_WLEN8 | LCR_H_FEN);
    wr(UART_ICR, ICR_ALL);
    wr(UART_IMSC, IMSC_RXIM | IMSC_RTIM);
    wr(UART_CR, CR_UARTEN | CR_TXE | CR_RXE);
    return 0;
}

int pl011_getc(void)
{
    if (rd(UART_FR) & FR_RXFE) {
        return -1;
    }
    return rd(UART_DR) & 0xff;
}

void pl011_putc(unsigned char c)
{
    while (rd(UART_FR) & FR_TXFF) {
    }
    wr(UART_DR, c);
}

void pl011_clear_irq(void)
{
    wr(UART_ICR, ICR_ALL);
}
