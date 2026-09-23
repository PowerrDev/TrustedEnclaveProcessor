/*
 * tepOS service protection domains.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <tep/ipc.h>

#include "cspace.h"
#include "elf.h"
#include "mem.h"
#include "runtime.h"
#include "service.h"
#include "untyped.h"
#include "vspace.h"

/* Copy a root CNode capability into slot `slot` of the service's CNode. */
static int give_cap(struct tep_service *svc, seL4_Word slot, seL4_CPtr src,
                    seL4_CapRights_t rights, seL4_Word badge)
{
    return seL4_CNode_Mint(svc->cnode, slot, TEP_SVC_CNODE_BITS,
                           seL4_CapInitThreadCNode, src, seL4_WordBits, rights, badge);
}

static const char *build(struct tep_service *svc, seL4_CPtr root_ep)
{
    const seL4_CapRights_t send = seL4_CapRights_new(1, 0, 0, 1);   /* Write + GrantReply */
    seL4_Word entry;
    const char *err;

    if (svc->id == 0 || svc->id > TEP_BADGE_ID_MASK) {
        return "bad service id";
    }

    /* Address space and image. */
    svc->vspace = tep_object_alloc(seL4_ARM_VSpaceObject, 0);
    if (svc->vspace == seL4_CapNull) {
        return "out of memory for VSpace";
    }
    if (seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, svc->vspace) != seL4_NoError) {
        return "ASID assignment failed";
    }
    err = tep_elf_load(svc->image, svc->image_size, svc->vspace, &entry);
    if (err != NULL) {
        return err;
    }

    seL4_CPtr ipc_frame = tep_object_alloc(seL4_ARM_SmallPageObject, 0);
    if (ipc_frame == seL4_CapNull ||
        tep_map_frame(svc->vspace, ipc_frame, TEP_SVC_IPC_BUFFER, seL4_ReadWrite,
                      seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever) != 0) {
        return "IPC buffer setup failed";
    }

    /* Capability space. */
    svc->cnode = tep_object_alloc(seL4_CapTableObject, TEP_SVC_CNODE_BITS);
    svc->notify = tep_object_alloc(seL4_NotificationObject, 0);
    svc->ping = tep_cslot_alloc();
    if (svc->cnode == seL4_CapNull || svc->notify == seL4_CapNull || svc->ping == seL4_CapNull) {
        return "out of memory for service caps";
    }
    if (give_cap(svc, TEP_SVC_SLOT_NOTIFY, svc->notify, seL4_CanRead, 0) != seL4_NoError ||
        give_cap(svc, TEP_SVC_SLOT_CONTROL, root_ep, send, TEP_SERVICE_BADGE(svc->id, 0)) != seL4_NoError ||
        give_cap(svc, TEP_SVC_SLOT_FAULT, root_ep, send, TEP_SERVICE_BADGE(svc->id, 1)) != seL4_NoError) {
        return "populating service CNode failed";
    }
    if (seL4_CNode_Mint(seL4_CapInitThreadCNode, svc->ping, seL4_WordBits,
                        seL4_CapInitThreadCNode, svc->notify, seL4_WordBits,
                        seL4_CanWrite, TEP_SVC_EVENT_PING) != seL4_NoError) {
        return "minting ping cap failed";
    }

    /* Thread. */
    svc->tcb = tep_object_alloc(seL4_TCBObject, 0);
    if (svc->tcb == seL4_CapNull) {
        return "out of memory for TCB";
    }
    seL4_Word guard = seL4_CNode_CapData_new(0, seL4_WordBits - TEP_SVC_CNODE_BITS).words[0];
    if (seL4_TCB_Configure(svc->tcb, TEP_SVC_SLOT_FAULT, svc->cnode, guard, svc->vspace, 0,
                           TEP_SVC_IPC_BUFFER, ipc_frame) != seL4_NoError) {
        return "TCB configure failed";
    }
    if (seL4_TCB_SetPriority(svc->tcb, seL4_CapInitThreadTCB, svc->priority) != seL4_NoError) {
        return "TCB priority failed";
    }

    seL4_UserContext regs;
    memset(&regs, 0, sizeof(regs));
    regs.pc = entry;
    regs.x0 = TEP_SVC_IPC_BUFFER;
    regs.x1 = svc->id;
    /* pc, sp, spsr, x0, x1: crt0 sets up its own stack. */
    if (seL4_TCB_WriteRegisters(svc->tcb, 1, 0, 5, &regs) != seL4_NoError) {
        return "starting service thread failed";
    }
    return NULL;
}

const char *tep_service_start(struct tep_service *svc, seL4_CPtr root_ep)
{
    const char *err = build(svc, root_ep);

    if (err != NULL) {
        tep_service_fail(svc, err);
        return err;
    }
    svc->state = TEP_SVC_STARTING;
    return NULL;
}

void tep_service_fail(struct tep_service *svc, const char *why)
{
    if (svc->tcb != seL4_CapNull) {
        seL4_TCB_Suspend(svc->tcb);
    }
    svc->state = TEP_SVC_FAILED;
    tep_log_start();
    tep_puts(svc->name);
    tep_puts(": failed: ");
    tep_puts(why);
    tep_puts("\n");
}

void tep_service_ping(struct tep_service *svc)
{
    svc->pings_sent++;
    seL4_Signal(svc->ping);
}
