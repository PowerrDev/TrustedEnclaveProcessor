/*
 * QEMU fw_cfg (MMIO interface, "qemu,fw-cfg-mmio"): read a named file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/*
 * Copy up to `max` bytes of fw_cfg file `name` (e.g. "opt/org.tepos/kek") to
 * out. Returns the file's size (which may exceed max), or -1 if the device is
 * not there or has no such file.
 */
long fw_cfg_read_file(uintptr_t base, const char *name, void *out, size_t max);
