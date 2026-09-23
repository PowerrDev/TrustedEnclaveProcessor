/*
 * tepOS watchdog tick from the QEMU virt PL031 RTC.
 *
 * The kernel owns the ARM generic timer and does not export its counter to
 * user level in this configuration, so the root task uses the PL031's
 * one-second match interrupt as a coarse tick for service deadlines. It is
 * not a trusted time source.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/sel4.h>

/* QEMU virt: pl031@9010000, interrupts = <GIC_SPI 2 IRQ_TYPE_LEVEL_HIGH>. */
#define TEP_PL031_PADDR 0x9010000UL
#define TEP_PL031_IRQ   (32 + 2)

/* Root task virtual address for the PL031 registers. */
#define TEP_DEVICE_VADDR 0x30000000UL

/*
 * Map the RTC, claim its IRQ and deliver ticks as `badge` on the notification
 * `ntfn`. Returns NULL on success, otherwise a static string.
 */
const char *tep_timer_init(seL4_CPtr ntfn, seL4_Word badge);

/* Handle a tick: clear the interrupt, arm the next one, acknowledge the IRQ. */
void tep_timer_tick(void);

/* RTC seconds counter. */
seL4_Word tep_timer_seconds(void);
