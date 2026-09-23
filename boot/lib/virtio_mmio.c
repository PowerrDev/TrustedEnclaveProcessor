/*
 * Minimal virtio-mmio (version 2) driver core. Register layout and
 * initialisation sequence from the Virtual I/O Device specification 1.2,
 * sections 4.2.2 and 3.1.1; split virtqueues from section 2.7.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "virtio_mmio.h"

#define REG_MAGIC           0x000
#define REG_VERSION         0x004
#define REG_DEVICE_ID       0x008
#define REG_DEVICE_FEATURES 0x010
#define REG_DEVICE_FEATURES_SEL 0x014
#define REG_DRIVER_FEATURES 0x020
#define REG_DRIVER_FEATURES_SEL 0x024
#define REG_QUEUE_SEL       0x030
#define REG_QUEUE_NUM_MAX   0x034
#define REG_QUEUE_NUM       0x038
#define REG_QUEUE_READY     0x044
#define REG_QUEUE_NOTIFY    0x050
#define REG_INTERRUPT_STATUS 0x060
#define REG_INTERRUPT_ACK   0x064
#define REG_STATUS          0x070
#define REG_QUEUE_DESC_LOW  0x080
#define REG_QUEUE_DESC_HIGH 0x084
#define REG_QUEUE_DRIVER_LOW  0x090
#define REG_QUEUE_DRIVER_HIGH 0x094
#define REG_QUEUE_DEVICE_LOW  0x0a0
#define REG_QUEUE_DEVICE_HIGH 0x0a4
#define REG_CONFIG          0x100

#define MAGIC 0x74726976u           /* "virt" */

#define STATUS_ACKNOWLEDGE  1u
#define STATUS_DRIVER       2u
#define STATUS_DRIVER_OK    4u
#define STATUS_FEATURES_OK  8u
#define STATUS_FAILED       128u

#define FEATURE_VERSION_1_HIGH (1u << 0)   /* bit 32 */

#define DESC_F_NEXT  1u
#define DESC_F_WRITE 2u

/* Queue layout in the DMA page. */
#define DESC_OFFSET  0x000
#define AVAIL_OFFSET 0x100
#define USED_OFFSET  0x200

struct vq_desc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};

struct vq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VIRTIO_QUEUE_SIZE];
    uint16_t used_event;
};

struct vq_used_elem {
    uint32_t id;
    uint32_t len;
};

struct vq_used {
    uint16_t flags;
    uint16_t idx;
    struct vq_used_elem ring[VIRTIO_QUEUE_SIZE];
    uint16_t avail_event;
};

_Static_assert(sizeof(struct vq_desc) * VIRTIO_QUEUE_SIZE <= AVAIL_OFFSET - DESC_OFFSET, "desc table");
_Static_assert(sizeof(struct vq_avail) <= USED_OFFSET - AVAIL_OFFSET, "avail ring");
_Static_assert(sizeof(struct vq_used) <= VIRTIO_DMA_BUFFERS - USED_OFFSET, "used ring");

static void barrier(void)
{
    __asm__ volatile("dmb sy" ::: "memory");
}

static uint32_t rd(struct virtio_dev *v, uint32_t off)
{
    return v->regs[off / 4];
}

static void wr(struct virtio_dev *v, uint32_t off, uint32_t val)
{
    v->regs[off / 4] = val;
}

static volatile struct vq_desc *desc(struct virtio_dev *v)
{
    return (volatile struct vq_desc *)(v->dma + DESC_OFFSET);
}

static volatile struct vq_avail *avail(struct virtio_dev *v)
{
    return (volatile struct vq_avail *)(v->dma + AVAIL_OFFSET);
}

static volatile struct vq_used *used(struct virtio_dev *v)
{
    return (volatile struct vq_used *)(v->dma + USED_OFFSET);
}

int virtio_mmio_init(struct virtio_dev *v, void *regs, void *dma, uint64_t dma_pa,
                     uint32_t device_id)
{
    v->regs = regs;
    v->dma = dma;
    v->dma_pa = dma_pa;
    v->avail_idx = 0;
    v->used_idx = 0;

    if (rd(v, REG_MAGIC) != MAGIC || rd(v, REG_VERSION) != 2) {
        return VIRTIO_NOT_VIRTIO;
    }
    if (rd(v, REG_DEVICE_ID) != device_id) {
        return VIRTIO_WRONG_DEVICE;
    }

    wr(v, REG_STATUS, 0);
    wr(v, REG_STATUS, STATUS_ACKNOWLEDGE);
    wr(v, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    /* Accept VIRTIO_F_VERSION_1 and nothing else. */
    wr(v, REG_DEVICE_FEATURES_SEL, 1);
    if (!(rd(v, REG_DEVICE_FEATURES) & FEATURE_VERSION_1_HIGH)) {
        wr(v, REG_STATUS, STATUS_FAILED);
        return VIRTIO_FEATURES;
    }
    wr(v, REG_DRIVER_FEATURES_SEL, 0);
    wr(v, REG_DRIVER_FEATURES, 0);
    wr(v, REG_DRIVER_FEATURES_SEL, 1);
    wr(v, REG_DRIVER_FEATURES, FEATURE_VERSION_1_HIGH);
    wr(v, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
    if (!(rd(v, REG_STATUS) & STATUS_FEATURES_OK)) {
        wr(v, REG_STATUS, STATUS_FAILED);
        return VIRTIO_FEATURES;
    }

    wr(v, REG_QUEUE_SEL, 0);
    if (rd(v, REG_QUEUE_READY) != 0 || rd(v, REG_QUEUE_NUM_MAX) < VIRTIO_QUEUE_SIZE) {
        wr(v, REG_STATUS, STATUS_FAILED);
        return VIRTIO_QUEUE;
    }
    for (uint32_t i = 0; i < VIRTIO_DMA_BUFFERS; i++) {
        v->dma[i] = 0;
    }
    wr(v, REG_QUEUE_NUM, VIRTIO_QUEUE_SIZE);
    wr(v, REG_QUEUE_DESC_LOW, (uint32_t)(dma_pa + DESC_OFFSET));
    wr(v, REG_QUEUE_DESC_HIGH, (uint32_t)((dma_pa + DESC_OFFSET) >> 32));
    wr(v, REG_QUEUE_DRIVER_LOW, (uint32_t)(dma_pa + AVAIL_OFFSET));
    wr(v, REG_QUEUE_DRIVER_HIGH, (uint32_t)((dma_pa + AVAIL_OFFSET) >> 32));
    wr(v, REG_QUEUE_DEVICE_LOW, (uint32_t)(dma_pa + USED_OFFSET));
    wr(v, REG_QUEUE_DEVICE_HIGH, (uint32_t)((dma_pa + USED_OFFSET) >> 32));
    wr(v, REG_QUEUE_READY, 1);

    wr(v, REG_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    return VIRTIO_OK;
}

long virtio_mmio_transfer(struct virtio_dev *v, const struct virtio_buf *bufs, int n,
                          void (*wait)(void), unsigned long max_polls)
{
    if (n < 1 || n > VIRTIO_QUEUE_SIZE) {
        return VIRTIO_BAD_BUFFER;
    }
    for (int i = 0; i < n; i++) {
        if (bufs[i].offset < VIRTIO_DMA_BUFFERS || bufs[i].len == 0 ||
            bufs[i].len > VIRTIO_DMA_SIZE - bufs[i].offset) {
            return VIRTIO_BAD_BUFFER;
        }
        desc(v)[i].addr = v->dma_pa + bufs[i].offset;
        desc(v)[i].len = bufs[i].len;
        desc(v)[i].flags = (bufs[i].device_writes ? DESC_F_WRITE : 0) | (i + 1 < n ? DESC_F_NEXT : 0);
        desc(v)[i].next = (uint16_t)(i + 1 < n ? i + 1 : 0);
    }

    /* One chain in flight: its head is always descriptor 0. */
    avail(v)->ring[v->avail_idx % VIRTIO_QUEUE_SIZE] = 0;
    barrier();
    avail(v)->idx = ++v->avail_idx;
    barrier();
    wr(v, REG_QUEUE_NOTIFY, 0);

    for (unsigned long polls = 0; polls < max_polls; polls++) {
        barrier();
        if (used(v)->idx != v->used_idx) {
            barrier();
            uint32_t len = used(v)->ring[v->used_idx % VIRTIO_QUEUE_SIZE].len;
            v->used_idx++;
            wr(v, REG_INTERRUPT_ACK, rd(v, REG_INTERRUPT_STATUS));
            return len;
        }
        if (wait) {
            wait();
        }
    }
    return VIRTIO_TIMEOUT;
}

uint32_t virtio_mmio_config32(struct virtio_dev *v, uint32_t offset)
{
    return rd(v, REG_CONFIG + offset);
}
