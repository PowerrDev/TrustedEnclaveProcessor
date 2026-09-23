#
# Convenience targets for building and booting seL4 on QEMU (AArch64 virt).
#
#   make run     build kernel + root task + loader, boot in QEMU (Ctrl-A X quits)
#   make debug   same, but QEMU waits for gdb on :1234
#   make image   just build build/boot/sel4-image.elf
#
# SPDX-License-Identifier: BSD-2-Clause
#

CROSS   ?= aarch64-elf-
CC      := $(CROSS)gcc
QEMU    ?= qemu-system-aarch64

BUILD_DIR := build
BOOT_DIR  := $(BUILD_DIR)/boot
KERNEL    := $(BUILD_DIR)/kernel.elf
ROOTSRV   := $(BOOT_DIR)/rootserver.elf
IMAGE     := $(BOOT_DIR)/sel4-image.elf

# Must match the kernel's compile-time memory map and platform config
# (see build/kernel.dts): 1 GiB at 0x40000000, GICv2, Cortex-A53.
QEMU_MACHINE ?= virt,secure=off,virtualization=off,gic-version=2
QEMU_CPU     ?= cortex-a53
QEMU_MEM     ?= 1024
# serial0 is the console; serial1 is the NXU mailbox link: a Unix socket this
# QEMU listens on. NXU's QEMU listens on its own socket, and
# tools/mailbox_link.py joins the two like a serial cable, reconnecting when
# either machine restarts (see boot/include/tep/mailbox.h). Neither QEMU is a
# socket client: QEMU 11.1 aborts a reconnecting socket client whenever a
# connection attempt fails.
TEP_MAILBOX_SOCK ?= /tmp/tepos-mailbox.sock

# tepOS's devices beyond the serial ports, each on a fixed virtio-mmio slot so
# a service's device page (8 slots of 0x200 bytes) holds only its own device:
# slot 0 (0x0a000000) virtio-rng for the CryptoService. Tools that boot tepOS
# themselves (NXU's tools/with_tepos.sh) read this with `make -s qemu-devices`.
TEP_QEMU_DEVICES := -global virtio-mmio.force-legacy=false \
                    -device virtio-rng-device,bus=virtio-mmio-bus.0

QEMU_FLAGS   := -machine $(QEMU_MACHINE) -cpu $(QEMU_CPU) -m $(QEMU_MEM) \
                -nographic -serial mon:stdio \
                -serial unix:$(TEP_MAILBOX_SOCK),server=on,wait=off \
                $(TEP_QEMU_DEVICES) -kernel $(IMAGE) $(QEMU_EXTRA)

KERNEL_CMAKE_FLAGS := -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE=gcc.cmake \
    -DCROSS_COMPILER_PREFIX=$(CROSS) \
    -DKernelPlatform=qemu-arm-virt \
    -DKernelSel4Arch=aarch64 \
    -DKernelArmHypervisorSupport=OFF \
    -DKernelDebugBuild=ON \
    -DKernelPrinting=ON

BARE_CFLAGS := -ffreestanding -fno-builtin -nostdlib -nostartfiles -static \
               -mgeneral-regs-only -mstrict-align -fno-pic -fno-stack-protector \
               -O2 -Wall -Wextra -Wno-builtin-declaration-mismatch -g \
               -Wl,--no-warn-rwx-segments

# seL4 generates libsel4 headers with Python/jinja2; use the project venv
# (python3 -m venv .venv && .venv/bin/pip install jinja2) when present.
ifneq ($(wildcard .venv/bin/python3),)
export PATH := $(CURDIR)/.venv/bin:$(PATH)
endif

# libsel4 is header-only for the root task (inline invocations).
SEL4_INCLUDES := -Ilibsel4/include -Ilibsel4/arch_include/arm \
    -Ilibsel4/sel4_arch_include/aarch64 -Ilibsel4/sel4_plat_include/qemu-arm-virt \
    -Ilibsel4/mode_include/64 \
    -I$(BUILD_DIR)/libsel4/include -I$(BUILD_DIR)/libsel4/arch_include/arm \
    -I$(BUILD_DIR)/libsel4/sel4_arch_include/aarch64 \
    -I$(BUILD_DIR)/libsel4/autoconf -I$(BUILD_DIR)/libsel4/gen_config \
    -I$(BUILD_DIR)/gen_config

TEP_INCLUDES := -Iboot/include -Iboot/lib
TEP_LIB_SRCS := boot/lib/crt0.S boot/lib/console.c boot/lib/tls.c boot/lib/string.c
TEP_LIB_HDRS := boot/lib/console.h boot/lib/tls.h boot/lib/mem.h boot/lib/program.ld

# Services: one ELF each, embedded into the root task (boot/rootserver/services.S).
DIAG_SVC := $(BOOT_DIR)/diagsvc.elf

$(DIAG_SVC): libsel4-headers $(TEP_LIB_SRCS) $(TEP_LIB_HDRS) boot/include/tep/ipc.h \
             boot/services/diag/main.c
	@mkdir -p $(BOOT_DIR)
	$(CC) $(BARE_CFLAGS) $(SEL4_INCLUDES) $(TEP_INCLUDES) -T boot/lib/program.ld \
	    $(TEP_LIB_SRCS) boot/services/diag/main.c -o $@

MAILBOX_SVC := $(BOOT_DIR)/mailboxsvc.elf
MAILBOX_SRCS := boot/services/mailbox/main.c boot/services/mailbox/frame.c \
    boot/services/mailbox/pl011.c

$(MAILBOX_SVC): libsel4-headers $(TEP_LIB_SRCS) $(TEP_LIB_HDRS) boot/include/tep/ipc.h \
                boot/include/tep/mailbox.h $(MAILBOX_SRCS) \
                boot/services/mailbox/frame.h boot/services/mailbox/pl011.h
	@mkdir -p $(BOOT_DIR)
	$(CC) $(BARE_CFLAGS) $(SEL4_INCLUDES) $(TEP_INCLUDES) -T boot/lib/program.ld \
	    $(TEP_LIB_SRCS) $(MAILBOX_SRCS) -o $@

CRYPTO_SVC := $(BOOT_DIR)/cryptosvc.elf
CRYPTO_SVC_SRCS := boot/services/crypto/main.c boot/lib/sha256.c boot/lib/hmac_drbg.c \
    boot/lib/virtio_mmio.c

$(CRYPTO_SVC): libsel4-headers $(TEP_LIB_SRCS) $(TEP_LIB_HDRS) boot/include/tep/ipc.h \
               $(CRYPTO_SVC_SRCS) boot/lib/sha256.h boot/lib/hmac_drbg.h boot/lib/virtio_mmio.h
	@mkdir -p $(BOOT_DIR)
	$(CC) $(BARE_CFLAGS) $(SEL4_INCLUDES) $(TEP_INCLUDES) -T boot/lib/program.ld \
	    $(TEP_LIB_SRCS) $(CRYPTO_SVC_SRCS) -o $@

ROOTSRV_SRCS := $(TEP_LIB_SRCS) boot/rootserver/main.c \
    boot/rootserver/runtime.c boot/rootserver/bootinfo.c \
    boot/rootserver/cspace.c boot/rootserver/untyped.c boot/rootserver/vspace.c \
    boot/rootserver/elf.c boot/rootserver/service.c boot/rootserver/services.S \
    boot/rootserver/timer.c boot/rootserver/manager.c
ROOTSRV_HDRS := boot/rootserver/runtime.h boot/rootserver/bootinfo.h \
    boot/rootserver/cspace.h boot/rootserver/untyped.h boot/rootserver/vspace.h \
    boot/rootserver/elf.h boot/rootserver/service.h boot/include/tep/ipc.h \
    boot/rootserver/timer.h boot/rootserver/manager.h

.PHONY: all kernel libsel4-headers image run debug clean-boot test-crypto qemu-devices

all: image

$(BUILD_DIR)/build.ninja:
	cmake $(KERNEL_CMAKE_FLAGS) -S . -B $(BUILD_DIR)

# Always defer to ninja so kernel source changes are picked up.
kernel: $(BUILD_DIR)/build.ninja
	cmake --build $(BUILD_DIR) --target kernel.elf

$(KERNEL): kernel

# Generated libsel4 API headers (syscall.h, invocation.h, sel4_client.h, ...).
libsel4-headers: $(BUILD_DIR)/build.ninja
	cmake --build $(BUILD_DIR) --target sel4_generated

$(ROOTSRV): libsel4-headers $(ROOTSRV_SRCS) $(ROOTSRV_HDRS) $(TEP_LIB_HDRS) $(DIAG_SVC) \
            $(MAILBOX_SVC) $(CRYPTO_SVC) boot/include/tep/mailbox.h
	@mkdir -p $(BOOT_DIR)
	$(CC) $(BARE_CFLAGS) $(SEL4_INCLUDES) $(TEP_INCLUDES) -Wa,-I$(BOOT_DIR) \
	    -T boot/lib/program.ld $(ROOTSRV_SRCS) -o $@

$(IMAGE): kernel $(ROOTSRV) boot/loader/start.S boot/loader/loader.c \
          boot/loader/blobs.S boot/loader/loader.ld
	@mkdir -p $(BOOT_DIR)
	cp $(KERNEL) $(BOOT_DIR)/kernel.elf
	$(CC) $(BARE_CFLAGS) -Wa,-I$(BOOT_DIR) -T boot/loader/loader.ld \
	    boot/loader/start.S boot/loader/loader.c boot/loader/blobs.S -o $@

image: $(IMAGE)

run: $(IMAGE)
	@echo "Booting seL4 in QEMU (Ctrl-A X to quit)"
	$(QEMU) $(QEMU_FLAGS)

debug: $(IMAGE)
	@echo "QEMU waiting for gdb: $(CROSS)gdb $(KERNEL) -ex 'target remote :1234'"
	$(QEMU) $(QEMU_FLAGS) -S -s

# Host check of the crypto primitives: boot/lib/sha256.c against the FIPS 180-4
# and RFC 4231 vectors, boot/lib/hmac_drbg.c against NIST CAVP vectors,
# vendored Monocypher's Ed25519 (RFC 8032) and AEAD.
HOST_CC ?= cc
CRYPTO_SRCS := tools/crypto_test.c boot/lib/sha256.c boot/lib/hmac_drbg.c \
    boot/third_party/monocypher/monocypher.c boot/third_party/monocypher/monocypher-ed25519.c

test-crypto: $(CRYPTO_SRCS) boot/lib/sha256.h boot/lib/hmac_drbg.h
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) -std=c11 -O2 -Wall -Wextra -fsanitize=address,undefined \
	    -Iboot/lib -Iboot/third_party/monocypher $(CRYPTO_SRCS) -o $(BUILD_DIR)/crypto_test
	$(BUILD_DIR)/crypto_test

qemu-devices:
	@echo $(TEP_QEMU_DEVICES)

clean-boot:
	rm -rf $(BOOT_DIR)
