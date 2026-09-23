/*
 * Minimal virtio-mmio (version 2, "modern") driver core for tepOS services.
 *
 * One split virtqueue (queue 0) of VIRTIO_QUEUE_SIZE entries, laid out at the
 * start of the service's DMA page; the rest of the page, from
 * VIRTIO_DMA_BUFFERS, holds the request buffers. Completion is polled.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#define VIRTIO_ID_BLOCK   2
#define VIRTIO_ID_ENTROPY 4

#define VIRTIO_QUEUE_SIZE  8
#define VIRTIO_DMA_SIZE    4096
#define VIRTIO_DMA_BUFFERS 0x400    /* first byte callers may use for buffers */

enum virtio_error {
    VIRTIO_OK = 0,
    VIRTIO_NOT_VIRTIO = -1,         /* bad magic or not version 2 */
    VIRTIO_WRONG_DEVICE = -2,       /* no device, or another type */
    VIRTIO_FEATURES = -3,           /* VIRTIO_F_VERSION_1 not accepted */
    VIRTIO_QUEUE = -4,              /* queue 0 missing or too small */
    VIRTIO_TIMEOUT = -5,
    VIRTIO_BAD_BUFFER = -6,
};

struct virtio_dev {
    volatile uint32_t *regs;
    uint8_t *dma;                   /* service virtual address of the DMA page */
    uint64_t dma_pa;                /* its physical address, for the device */
    uint16_t avail_idx;
    uint16_t used_idx;
};

struct virtio_buf {
    uint32_t offset;                /* in the DMA page, >= VIRTIO_DMA_BUFFERS */
    uint32_t len;
    int device_writes;
};

/* Reset, negotiate VIRTIO_F_VERSION_1 only, set up queue 0, go live. */
int virtio_mmio_init(struct virtio_dev *v, void *regs, void *dma, uint64_t dma_pa,
                     uint32_t device_id);

/*
 * Submit one descriptor chain and poll for its completion, calling wait()
 * between polls (e.g. seL4_Yield). Returns the number of bytes the device
 * wrote, or a negative virtio_error.
 */
long virtio_mmio_transfer(struct virtio_dev *v, const struct virtio_buf *bufs, int n,
                          void (*wait)(void), unsigned long max_polls);

uint32_t virtio_mmio_config32(struct virtio_dev *v, uint32_t offset);
