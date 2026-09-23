/*
 * tepOS capability slot allocator: one bit per root CNode slot, set = free.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "cspace.h"
#include "runtime.h"

#define NSLOTS    (1UL << CONFIG_ROOT_CNODE_SIZE_BITS)
#define WORD_BITS (sizeof(seL4_Word) * 8)

static seL4_Word free_map[NSLOTS / WORD_BITS];
static seL4_Word nfree;
static seL4_Word hint;      /* word index to start searching from */

int tep_cspace_init(const seL4_BootInfo *bi)
{
    if (BIT(bi->initThreadCNodeSizeBits) > NSLOTS || bi->empty.end > NSLOTS) {
        return -1;
    }
    for (seL4_Word s = bi->empty.start; s < bi->empty.end; s++) {
        free_map[s / WORD_BITS] |= 1UL << (s % WORD_BITS);
    }
    nfree = bi->empty.end - bi->empty.start;
    hint = bi->empty.start / WORD_BITS;
    return 0;
}

seL4_CPtr tep_cslot_alloc(void)
{
    const seL4_Word nwords = NSLOTS / WORD_BITS;

    for (seL4_Word n = 0; n < nwords; n++) {
        seL4_Word w = (hint + n) % nwords;
        if (free_map[w] == 0) {
            continue;
        }
        seL4_Word bit = __builtin_ctzl(free_map[w]);
        free_map[w] &= ~(1UL << bit);
        nfree--;
        hint = w;
        return w * WORD_BITS + bit;
    }
    return seL4_CapNull;
}

void tep_cslot_free(seL4_CPtr slot)
{
    if (slot == seL4_CapNull || slot >= NSLOTS ||
        (free_map[slot / WORD_BITS] & (1UL << (slot % WORD_BITS)))) {
        return;
    }
    seL4_CNode_Delete(seL4_CapInitThreadCNode, slot, seL4_WordBits);
    free_map[slot / WORD_BITS] |= 1UL << (slot % WORD_BITS);
    nfree++;
}

seL4_Word tep_cslots_free_count(void)
{
    return nfree;
}
