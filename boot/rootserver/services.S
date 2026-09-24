/*
 * Embeds the service ELF images into the root task.
 * The files are found via the assembler include path (-Wa,-I<dir>).
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
    .section .rodata.services, "a"
    .balign 8
    .global diag_elf_start, diag_elf_end
diag_elf_start:
    .incbin "diagsvc.elf"
diag_elf_end:
    .balign 8
    .global mailbox_elf_start, mailbox_elf_end
mailbox_elf_start:
    .incbin "mailboxsvc.elf"
mailbox_elf_end:
    .balign 8
    .global crypto_elf_start, crypto_elf_end
crypto_elf_start:
    .incbin "cryptosvc.elf"
crypto_elf_end:
    .balign 8
    .global keystore_elf_start, keystore_elf_end
keystore_elf_start:
    .incbin "keystoresvc.elf"
keystore_elf_end:
    .balign 8
    .global auth_elf_start, auth_elf_end
auth_elf_start:
    .incbin "authsvc.elf"
auth_elf_end:
    .balign 8
    .global bootpolicy_elf_start, bootpolicy_elf_end
bootpolicy_elf_start:
    .incbin "bootpolicysvc.elf"
bootpolicy_elf_end:
