/*
 * Minimal seL4 loader for AArch64 QEMU virt (non-hypervisor kernel config).
 *
 * Does the job of seL4_tools' elfloader for this one platform:
 *   1. copy QEMU's DTB out of the way (it sits where the kernel goes),
 *   2. load the kernel ELF at its physical addresses,
 *   3. load the root task ELF into physical memory right after the DTB,
 *   4. build boot page tables (identity map in TTBR0, kernel window in TTBR1),
 *      program MAIR/TCR the way the kernel expects, enable the MMU and jump
 *      to the kernel with the arguments init_kernel() expects in x0-x5.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define UART_BASE   0x09000000UL    /* PL011 on QEMU virt */
#define RAM_BASE    0x40000000UL    /* QEMU puts the DTB here for bare-metal ELFs */
#define PAGE_SIZE   0x1000UL
#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))

/* Must match enum mair_types in src/arch/arm/64/kernel/vspace.c */
#define MT_DEVICE_nGnRnE 0
#define MT_NORMAL        4
#define MAIR_VALUE ((0x00UL << 0) | (0x04UL << 8) | (0x0cUL << 16) | \
                    (0x44UL << 24) | (0xffUL << 32) | (0xaaUL << 40))

/* 48-bit VA, 4K granule, WBWA inner-shareable walks, 40-bit PA, 16-bit ASIDs
 * (the kernel checks TCR_EL1.AS in check16BitASID()). */
#define TCR_VALUE ((16UL << 0) | (1UL << 8) | (1UL << 10) | (3UL << 12) | (0UL << 14) | \
                   (16UL << 16) | (1UL << 24) | (1UL << 26) | (3UL << 28) | (2UL << 30) | \
                   (2UL << 32) | (1UL << 36))

#define PTE_VALID   (1UL << 0)
#define PTE_TABLE   (1UL << 1)
#define PTE_AF      (1UL << 10)
#define PTE_SH_INNER (3UL << 8)
#define PTE_PXN     (1UL << 53)
#define PTE_UXN     (1UL << 54)
#define PTE_ATTR(i) ((u64)(i) << 2)

#define BLOCK_NORMAL (PTE_VALID | PTE_AF | PTE_SH_INNER | PTE_ATTR(MT_NORMAL))
#define BLOCK_DEVICE (PTE_VALID | PTE_AF | PTE_ATTR(MT_DEVICE_nGnRnE) | PTE_PXN | PTE_UXN)

#define L0_INDEX(va) (((va) >> 39) & 0x1ff)
#define L1_INDEX(va) (((va) >> 30) & 0x1ff)
#define L2_INDEX(va) (((va) >> 21) & 0x1ff)

static u64 pgd_lo[512] __attribute__((aligned(4096)));
static u64 pud_lo[512] __attribute__((aligned(4096)));
static u64 pgd_hi[512] __attribute__((aligned(4096)));
static u64 pud_hi[512] __attribute__((aligned(4096)));
static u64 pmd_hi[512] __attribute__((aligned(4096)));

extern const u8 kernel_elf_start[], kernel_elf_end[];
extern const u8 rootserver_elf_start[], rootserver_elf_end[];

void enable_mmu_and_jump(u64 mair, u64 tcr, u64 ttbr0, u64 ttbr1, u64 entry, u64 *args)
__attribute__((noreturn));

/* ---- console ---------------------------------------------------------- */

static void putc(char c)
{
    volatile u32 *uart = (volatile u32 *)UART_BASE;
    while (uart[0x18 / 4] & (1 << 5)); /* TXFF */
    uart[0] = (u32)c;
}

static void puts(const char *s)
{
    for (; *s; s++) {
        if (*s == '\n') {
            putc('\r');
        }
        putc(*s);
    }
}

static void puthex(u64 v)
{
    puts("0x");
    for (int i = 60; i >= 0; i -= 4) {
        putc("0123456789abcdef"[(v >> i) & 0xf]);
    }
}

static void __attribute__((noreturn)) fail(const char *msg)
{
    puts("loader: ERROR: ");
    puts(msg);
    puts("\n");
    for (;;) {
        __asm__ volatile("wfe");
    }
}

/* ---- memory helpers (MMU is off: keep accesses simple and aligned) ---- */

static void copy(u8 *dst, const u8 *src, u64 n)
{
    while (n--) {
        *dst++ = *src++;
    }
}

static void zero(u8 *dst, u64 n)
{
    while (n--) {
        *dst++ = 0;
    }
}

/* ELF headers are embedded with 8-byte alignment, so field reads are aligned. */
typedef struct {
    u8  e_ident[16];
    u16 e_type, e_machine;
    u32 e_version;
    u64 e_entry, e_phoff, e_shoff;
    u32 e_flags;
    u16 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    u32 p_type, p_flags;
    u64 p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;

#define PT_LOAD 1
#define EM_AARCH64 183

static const Elf64_Ehdr *check_elf(const u8 *img, const char *name)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)img;
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' ||
        eh->e_ident[3] != 'F' || eh->e_ident[4] != 2 || eh->e_machine != EM_AARCH64) {
        fail(name);
    }
    return eh;
}

static const Elf64_Phdr *phdr(const u8 *img, int i)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)img;
    return (const Elf64_Phdr *)(img + eh->e_phoff + (u64)i * eh->e_phentsize);
}

/* Range covered by PT_LOAD segments, by virtual (use_paddr=0) or physical address. */
static void elf_range(const u8 *img, int use_paddr, u64 *lo, u64 *hi)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)img;
    *lo = ~0UL;
    *hi = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = phdr(img, i);
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0) {
            continue;
        }
        u64 base = use_paddr ? ph->p_paddr : ph->p_vaddr;
        if (base < *lo) {
            *lo = base;
        }
        if (base + ph->p_memsz > *hi) {
            *hi = base + ph->p_memsz;
        }
    }
}

/* Copy each PT_LOAD segment to (vaddr + v_to_p), zero-filling .bss. */
static void elf_load(const u8 *img, int use_paddr, u64 v_to_p)
{
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)img;
    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = phdr(img, i);
        if (ph->p_type != PT_LOAD) {
            continue;
        }
        u8 *dst = (u8 *)((use_paddr ? ph->p_paddr : ph->p_vaddr) + v_to_p);
        copy(dst, img + ph->p_offset, ph->p_filesz);
        zero(dst + ph->p_filesz, ph->p_memsz - ph->p_filesz);
    }
}

static u32 be32(const u8 *p)
{
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | p[3];
}

/* ---- main ------------------------------------------------------------- */

void __attribute__((noreturn)) loader_main(void)
{
    puts("\nTEP loader: booting seL4\n");

    const u8 *kimg = kernel_elf_start;
    const u8 *uimg = rootserver_elf_start;
    const Elf64_Ehdr *keh = check_elf(kimg, "kernel image is not an AArch64 ELF");
    const Elf64_Ehdr *ueh = check_elf(uimg, "root task image is not an AArch64 ELF");

    u64 k_p_lo, k_p_hi, k_v_lo, k_v_hi;
    elf_range(kimg, 1, &k_p_lo, &k_p_hi);
    elf_range(kimg, 0, &k_v_lo, &k_v_hi);
    if ((k_p_lo & 0x1fffff) || (k_v_lo & 0x1fffff) ||
        L0_INDEX(k_v_lo) != 511 || L1_INDEX(k_v_lo) != 511) {
        fail("kernel must be 2 MiB aligned and linked in the top 1 GiB of VA");
    }

    /* 1. Move the DTB out of the kernel's way. */
    u64 next = ALIGN_UP(k_p_hi, PAGE_SIZE);
    u64 dtb_p = 0, dtb_size = 0;
    const u8 *qemu_dtb = (const u8 *)RAM_BASE;
    if (be32(qemu_dtb) == 0xd00dfeed) {
        dtb_size = be32(qemu_dtb + 4);
        dtb_p = next;
        if (dtb_p < RAM_BASE + dtb_size) {
            fail("DTB would overlap itself");
        }
        copy((u8 *)dtb_p, qemu_dtb, dtb_size);
        next = ALIGN_UP(dtb_p + dtb_size, PAGE_SIZE);
    } else {
        puts("TEP loader: no DTB found, continuing without one\n");
    }

    /* 2. Kernel at its physical load address. */
    elf_load(kimg, 1, 0);

    /* 3. Root task right after the DTB. */
    u64 u_v_lo, u_v_hi;
    elf_range(uimg, 0, &u_v_lo, &u_v_hi);
    u_v_lo &= ~(PAGE_SIZE - 1);
    u_v_hi = ALIGN_UP(u_v_hi, PAGE_SIZE);
    u64 u_p_lo = next;
    u64 u_p_hi = u_p_lo + (u_v_hi - u_v_lo);
    u64 pv_offset = u_p_lo - u_v_lo;
    if (u_p_hi > (u64)kernel_elf_start) {
        fail("root task collides with the loader");
    }
    zero((u8 *)u_p_lo, u_p_hi - u_p_lo);
    elf_load(uimg, 0, pv_offset);

    puts("  kernel    ");
    puthex(k_p_lo);
    puts(" - ");
    puthex(k_p_hi);
    puts("\n  dtb       ");
    puthex(dtb_p);
    puts(" (");
    puthex(dtb_size);
    puts(" bytes)\n  root task ");
    puthex(u_p_lo);
    puts(" - ");
    puthex(u_p_hi);
    puts(" @ vaddr ");
    puthex(u_v_lo);
    puts("\n");

    /* 4. Boot page tables.
     * TTBR0: identity map of the low 4 GiB (devices in the first GiB) so this
     *        code keeps running once the MMU is on.
     * TTBR1: kernel window, 2 MiB blocks from the kernel's vaddr to the top. */
    pgd_lo[0] = (u64)pud_lo | PTE_VALID | PTE_TABLE;
    pud_lo[0] = 0x00000000UL | BLOCK_DEVICE;
    for (u64 i = 1; i < 4; i++) {
        pud_lo[i] = (i << 30) | BLOCK_NORMAL;
    }

    pgd_hi[511] = (u64)pud_hi | PTE_VALID | PTE_TABLE;
    pud_hi[511] = (u64)pmd_hi | PTE_VALID | PTE_TABLE;
    u64 pa = k_p_lo;
    for (u64 i = L2_INDEX(k_v_lo); i < 512; i++, pa += 0x200000) {
        pmd_hi[i] = pa | BLOCK_NORMAL;
    }

    u64 args[6] = { u_p_lo, u_p_hi, pv_offset, ueh->e_entry, dtb_p, dtb_size };

    puts("TEP loader: jumping to kernel at ");
    puthex(keh->e_entry);
    puts("\n\n");

    enable_mmu_and_jump(MAIR_VALUE, TCR_VALUE, (u64)pgd_lo, (u64)pgd_hi,
                        keh->e_entry, args);
}
