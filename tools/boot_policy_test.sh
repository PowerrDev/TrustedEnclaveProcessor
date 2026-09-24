#!/usr/bin/env bash
#
# tools/boot_policy_test.sh -- the BootPolicyService's manifest checks.
#
# Signs manifests with the host boot-signing key (build/boot-signing.key)
# and asks tepOS, on a scratch key store, to check them against measured
# image digests: right image, another image, a tampered manifest, another
# signing key, a bad magic, an older version (rollback), and that the
# minimum version survives a reboot. Run with `make test-boot-policy`.

set -u
cd "$(dirname "$0")/.." || exit 1

SCRATCH=$(mktemp -d /tmp/tepos-boot.XXXXXX) || exit 1
IMG=$SCRATCH/keystore.img
KEK=$SCRATCH/kek.bin
SOCK=$SCRATCH/mb.sock
qpid=
failures=0
trap '[ -n "$qpid" ] && kill $qpid 2>/dev/null; wait 2>/dev/null; rm -rf "$SCRATCH"' EXIT

dd if=/dev/zero of="$IMG" bs=1024 count=1024 2>/dev/null
head -c 32 /dev/urandom >"$KEK"
DEVICES=$(make -s qemu-devices TEP_KEYSTORE_IMG="$IMG" TEP_KEK="$KEK")
SIGN=build/boot_sign
KEY=build/boot-signing.key

# Two stand-in "images".
head -c 20000 /dev/urandom >"$SCRATCH/bootd"
head -c 20000 /dev/urandom >"$SCRATCH/other"
$SIGN sign $KEY "$SCRATCH/bootd" bootd 2 "$SCRATCH/v2.manifest"
$SIGN sign $KEY "$SCRATCH/bootd" bootd 1 "$SCRATCH/v1.manifest"
$SIGN sign $KEY "$SCRATCH/bootd" bootd 3 "$SCRATCH/v3.manifest"
$SIGN keygen "$SCRATCH/other.key" "$SCRATCH/other_pub.h"
$SIGN sign "$SCRATCH/other.key" "$SCRATCH/bootd" bootd 9 "$SCRATCH/foreign.manifest"
python3 - "$SCRATCH" <<'PY'
import sys
d = sys.argv[1]
m = bytearray(open(d + "/v2.manifest", "rb").read())
m[20] ^= 1                                  # inside the signed bytes (image size)
open(d + "/tampered.manifest", "wb").write(m)
m = bytearray(open(d + "/v2.manifest", "rb").read())
m[0] = ord("X")                             # magic
open(d + "/badmagic.manifest", "wb").write(m)
PY

boot() {
	rm -f "$SOCK"
	qemu-system-aarch64 -machine virt,secure=off,virtualization=off,gic-version=2 -cpu cortex-a53 -m 1024 \
		-nographic -serial file:"$SCRATCH/console.$1.log" -serial unix:"$SOCK",server=on,wait=off \
		$DEVICES -monitor none -kernel build/boot/sel4-image.elf >"$SCRATCH/qemu.$1.log" 2>&1 </dev/null &
	qpid=$!
	sleep 6
}

halt() {
	kill $qpid 2>/dev/null
	wait $qpid 2>/dev/null
	qpid=
}

check() {
	local got
	got=$(python3 tools/mailbox_client.py --socket "$SOCK" --timeout 10 boot-verify "$2" "$3")
	if [ "$got" = "$4" ]; then
		printf '%-58s ok\n' "$1"
	else
		printf '%-58s FAIL (%s)\n' "$1" "$got"
		failures=$((failures + 1))
	fi
}

boot 1
check "signed manifest, matching image" "$SCRATCH/v2.manifest" "$SCRATCH/bootd" "OK 2"
check "signed manifest, another image" "$SCRATCH/v2.manifest" "$SCRATCH/other" "DENIED wrong image"
check "tampered manifest" "$SCRATCH/tampered.manifest" "$SCRATCH/bootd" "DENIED bad signature"
check "manifest signed by another key" "$SCRATCH/foreign.manifest" "$SCRATCH/bootd" "DENIED bad signature"
check "not a manifest" "$SCRATCH/badmagic.manifest" "$SCRATCH/bootd" "DENIED bad format"
check "older version after v2 -> rollback" "$SCRATCH/v1.manifest" "$SCRATCH/bootd" "ROLLBACK 2"
check "newer version accepted" "$SCRATCH/v3.manifest" "$SCRATCH/bootd" "OK 3"
check "v2 now refused" "$SCRATCH/v2.manifest" "$SCRATCH/bootd" "ROLLBACK 3"
halt

boot 2
check "after a reboot the minimum is still 3" "$SCRATCH/v2.manifest" "$SCRATCH/bootd" "ROLLBACK 3"
check "and v3 still verifies" "$SCRATCH/v3.manifest" "$SCRATCH/bootd" "OK 3"
halt

echo "boot_policy_test: $([ $failures = 0 ] && echo passed || echo "$failures failure(s)")"
[ $failures = 0 ]
