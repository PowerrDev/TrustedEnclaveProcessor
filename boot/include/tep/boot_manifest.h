/*
 * Signed boot manifests for NXU images (tepOS BootPolicyService).
 *
 * A manifest names one image by its SHA-256, size, a short name and a
 * version, and is signed with Ed25519 by the host's boot-signing key
 * (tools/boot_sign). tepOS holds only the public key. All fields little
 * endian:
 *
 *   off  size  field
 *     0     8  magic            TEP_BOOT_MAGIC ("TEPBOOT1")
 *     8     4  format version   TEP_BOOT_FORMAT_VERSION
 *    12     4  image version    anti-rollback: never below the highest accepted
 *    16     8  image size       bytes
 *    24    16  name             NUL-padded, e.g. "bootd"
 *    40    32  image SHA-256
 *    72    64  Ed25519 signature over bytes 0 .. 71
 *
 * Verifying a manifest only says the image NXU measured is the one the key
 * holder signed. Nothing enforces it yet: NXU reports the verdict, it does
 * not stop booting on it, and the measurement is NXU's own.
 */

#pragma once

#define TEP_BOOT_MAGIC "TEPBOOT1"
#define TEP_BOOT_FORMAT_VERSION 1u
#define TEP_BOOT_NAME_SIZE 16
#define TEP_BOOT_SIGNED_SIZE 72
#define TEP_BOOT_MANIFEST_SIZE (TEP_BOOT_SIGNED_SIZE + 64)
