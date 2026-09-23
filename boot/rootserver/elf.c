/*
 * Service ELF loader.
 *
 * Every page gets a fresh frame, filled through the root task's scratch page
 * and then mapped into the target VSpace only. The root task keeps the frame
 * capabilities but no mapping of service memory.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "mem.h"

#include "elf.h"
#include "runtime.h"
#include "untyped.h"
#include "vspace.h"

#define PAGE_SIZE BIT(seL4_PageBits)
#define PAGE_MASK (PAGE_SIZE - 1)
#define MAX_PHDRS 16

typedef struct {
    unsigned char e_ident[16];
    seL4_Uint16 e_type, e_machine;
    seL4_Uint32 e_version;
    seL4_Uint64 e_entry, e_phoff, e_shoff;
    seL4_Uint32 e_flags;
    seL4_Uint16 e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    seL4_Uint32 p_type, p_flags;
    seL4_Uint64 p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Elf64_Phdr;

#define ET_EXEC    2
#define EM_AARCH64 183
#define PT_LOAD    1
#define PF_X       1
#define PF_W       2
#define PF_R       4

static const char *check_segment(const Elf64_Phdr *ph, seL4_Word size)
{
    if (ph->p_memsz == 0 || ph->p_filesz > ph->p_memsz) {
        return "bad segment size";
    }
    if (ph->p_offset > size || ph->p_filesz > size - ph->p_offset) {
        return "segment outside image";
    }
    if (ph->p_vaddr & PAGE_MASK) {
        return "segment not page aligned";
    }
    if (ph->p_vaddr < TEP_SVC_IMAGE_BASE || ph->p_vaddr >= TEP_SVC_IMAGE_TOP ||
        ph->p_memsz > TEP_SVC_IMAGE_TOP - ph->p_vaddr) {
        return "segment outside service window";
    }
    if (!(ph->p_flags & PF_R) || (ph->p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) {
        return "segment permissions not allowed (need R, no W+X)";
    }
    return NULL;
}

static seL4_Word seg_end(const Elf64_Phdr *ph)
{
    return (ph->p_vaddr + ph->p_memsz + PAGE_MASK) & ~PAGE_MASK;
}

static const char *load_segment(const unsigned char *img, const Elf64_Phdr *ph, seL4_CPtr vspace)
{
    seL4_CapRights_t rights = (ph->p_flags & PF_W) ? seL4_ReadWrite : seL4_CanRead;
    seL4_ARM_VMAttributes attr = seL4_ARM_Default_VMAttributes;

    if (!(ph->p_flags & PF_X)) {
        attr |= seL4_ARM_ExecuteNever;
    }

    for (seL4_Word va = ph->p_vaddr; va < seg_end(ph); va += PAGE_SIZE) {
        seL4_CPtr frame = tep_object_alloc(seL4_ARM_SmallPageObject, 0);
        if (frame == seL4_CapNull) {
            return "out of memory for service frame";
        }

        /* Fresh frames are zeroed by the kernel; copy the file-backed part. */
        seL4_Word off = va - ph->p_vaddr;
        if (off < ph->p_filesz) {
            seL4_Word n = ph->p_filesz - off;
            if (n > PAGE_SIZE) {
                n = PAGE_SIZE;
            }
            if (tep_map_frame(seL4_CapInitThreadVSpace, frame, TEP_SCRATCH_VADDR, seL4_ReadWrite,
                              seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever) != 0) {
                return "scratch map failed";
            }
            memcpy((void *)TEP_SCRATCH_VADDR, img + ph->p_offset + off, n);
            if ((ph->p_flags & PF_X) &&
                seL4_ARM_Page_Unify_Instruction(frame, 0, PAGE_SIZE) != seL4_NoError) {
                return "instruction cache maintenance failed";
            }
            if (seL4_ARM_Page_Unmap(frame) != seL4_NoError) {
                return "scratch unmap failed";
            }
        }

        if (tep_map_frame(vspace, frame, va, rights, attr) != 0) {
            return "service map failed";
        }
    }
    return NULL;
}

const char *tep_elf_load(const void *image, seL4_Word size, seL4_CPtr vspace, seL4_Word *entry)
{
    const unsigned char *img = image;
    const Elf64_Ehdr *eh = image;
    const Elf64_Phdr *load[MAX_PHDRS];
    int nload = 0;
    int entry_ok = 0;
    const char *err;

    if (((seL4_Word)image & 7) || size < sizeof(*eh)) {
        return "image too small or misaligned";
    }
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E' || eh->e_ident[2] != 'L' ||
        eh->e_ident[3] != 'F' || eh->e_ident[4] != 2 || eh->e_ident[5] != 1 ||
        eh->e_type != ET_EXEC || eh->e_machine != EM_AARCH64) {
        return "not an AArch64 ELF64 executable";
    }
    if (eh->e_phentsize != sizeof(Elf64_Phdr) || eh->e_phnum == 0 || eh->e_phnum > MAX_PHDRS ||
        (eh->e_phoff & 7) || eh->e_phoff > size ||
        (seL4_Word)eh->e_phnum * sizeof(Elf64_Phdr) > size - eh->e_phoff) {
        return "bad program header table";
    }

    for (int i = 0; i < eh->e_phnum; i++) {
        const Elf64_Phdr *ph = (const Elf64_Phdr *)(img + eh->e_phoff) + i;
        if (ph->p_type != PT_LOAD) {
            continue;
        }
        err = check_segment(ph, size);
        if (err != NULL) {
            return err;
        }
        for (int j = 0; j < nload; j++) {
            if (ph->p_vaddr < seg_end(load[j]) && load[j]->p_vaddr < seg_end(ph)) {
                return "overlapping segments";
            }
        }
        if ((ph->p_flags & PF_X) && eh->e_entry >= ph->p_vaddr &&
            eh->e_entry < ph->p_vaddr + ph->p_memsz) {
            entry_ok = 1;
        }
        load[nload++] = ph;
    }
    if (!entry_ok) {
        return "entry point not in an executable segment";
    }

    for (int i = 0; i < nload; i++) {
        err = load_segment(img, load[i], vspace);
        if (err != NULL) {
            return err;
        }
    }
    *entry = eh->e_entry;
    return NULL;
}
