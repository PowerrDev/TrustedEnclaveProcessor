/*
 * PL031 RTC watchdog tick.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "cspace.h"
#include "runtime.h"
#include "timer.h"
#include "untyped.h"
#include "vspace.h"

/* PL031 registers (ARM DDI 0224). */
#define RTC_DR   0x00   /* data: current seconds */
#define RTC_MR   0x04   /* match */
#define RTC_IMSC 0x10   /* interrupt mask set/clear */
#define RTC_ICR  0x1c   /* interrupt clear */

static volatile seL4_Uint32 *rtc;
static seL4_CPtr irq_handler;

static seL4_Uint32 rtc_read(seL4_Word reg)
{
    return rtc[reg / 4];
}

static void rtc_write(seL4_Word reg, seL4_Uint32 v)
{
    rtc[reg / 4] = v;
}

/* Arm a match one second from now, re-arming if the counter moved meanwhile. */
static void arm_next(void)
{
    seL4_Uint32 next;

    do {
        next = rtc_read(RTC_DR) + 1;
        rtc_write(RTC_MR, next);
    } while (rtc_read(RTC_DR) >= next);
}

const char *tep_timer_init(seL4_CPtr ntfn, seL4_Word badge)
{
    seL4_CPtr frame = tep_device_frame_alloc(TEP_PL031_PADDR);
    if (frame == seL4_CapNull) {
        return "no device untyped covers the RTC";
    }
    /* Not cacheable: mapped as device memory. */
    if (tep_map_frame(seL4_CapInitThreadVSpace, frame, TEP_DEVICE_VADDR, seL4_ReadWrite,
                      seL4_ARM_ExecuteNever, tep_object_alloc_fn, NULL) != 0) {
        return "mapping the RTC failed";
    }
    rtc = (volatile seL4_Uint32 *)TEP_DEVICE_VADDR;

    irq_handler = tep_cslot_alloc();
    seL4_CPtr tick_cap = tep_cslot_alloc();
    if (irq_handler == seL4_CapNull || tick_cap == seL4_CapNull) {
        return "out of cslots for the RTC";
    }
    if (seL4_IRQControl_Get(seL4_CapIRQControl, TEP_PL031_IRQ, seL4_CapInitThreadCNode,
                            irq_handler, seL4_WordBits) != seL4_NoError) {
        return "claiming the RTC IRQ failed";
    }
    if (seL4_CNode_Mint(seL4_CapInitThreadCNode, tick_cap, seL4_WordBits,
                        seL4_CapInitThreadCNode, ntfn, seL4_WordBits,
                        seL4_CanWrite, badge) != seL4_NoError ||
        seL4_IRQHandler_SetNotification(irq_handler, tick_cap) != seL4_NoError) {
        return "routing the RTC IRQ failed";
    }

    rtc_write(RTC_ICR, 1);
    arm_next();
    rtc_write(RTC_IMSC, 1);
    if (seL4_IRQHandler_Ack(irq_handler) != seL4_NoError) {
        return "enabling the RTC IRQ failed";
    }
    return NULL;
}

void tep_timer_tick(void)
{
    rtc_write(RTC_ICR, 1);
    arm_next();
    seL4_IRQHandler_Ack(irq_handler);
}

seL4_Word tep_timer_seconds(void)
{
    return rtc_read(RTC_DR);
}
