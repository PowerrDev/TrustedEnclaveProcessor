/*
 * KeyStore persistence: the key table sealed onto a virtio-blk disk.
 *
 * NOT a protection boundary: the sealing key (KEK) is a file on the host
 * (QEMU fw_cfg "opt/org.tepos/kek"), so anyone who can read the host's
 * files can open the store. It keeps keys across tepOS reboots and detects
 * tampering and corruption; it cannot keep them secret from the host, and
 * it cannot stop a rollback to an older sealed copy (that would need a
 * hardware monotonic counter). A hardware root of trust is future work.
 *
 * Layout: two regions, A at sector 0 and B at sector 16, each a 512-byte
 * header followed by the sealed table. Saves go to the region not holding
 * the newest copy, with generation + 1; loads take the newest region that
 * authenticates.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <tep/services.h>

struct key {
    int in_use;
    uint32_t handle;
    seL4_Word owner;                /* client badge */
    uint8_t secret[64];             /* Monocypher Ed25519 secret key (seed || public) */
    uint8_t public[TEP_KS_PUBLIC_KEY_SIZE];
};

#define STORE_NONCE_SIZE 24

/*
 * Set up the disk (virtio-blk) and read the KEK from fw_cfg. Returns NULL or
 * a static string saying what is missing.
 */
const char *store_init(uintptr_t blk_regs, void *dma, uint64_t dma_pa, uintptr_t fw_cfg);

/*
 * Load the newest sealed table into keys[]. Returns NULL (with *count keys
 * loaded; 0 for a blank disk) or a static string: a store that exists but
 * does not authenticate is an error, never silently replaced.
 */
const char *store_load(struct key *keys, int max, int *count);

/* Seal keys[] into the other region under a fresh nonce. Returns 0 or -1. */
int store_save(const struct key *keys, int max, const uint8_t nonce[STORE_NONCE_SIZE]);
