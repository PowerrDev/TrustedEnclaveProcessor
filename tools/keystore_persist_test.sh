#!/usr/bin/env bash
#
# tools/keystore_persist_test.sh -- the KeyStore's sealed store across reboots.
#
# Boots tepOS four times on a scratch copy of the key store disk and sealing
# key (your build/tepos-keystore.img and build/tepos-kek.bin are not used):
#
#   1. generate a key and note its handle and public key;
#   2. reboot: the same handle must give the same public key and sign
#      (verified on the host with build/ed25519_check);
#   3. reboot with a byte of the sealed data flipped: the KeyStore must refuse
#      to start and tepOS report itself failed;
#   4. reboot with the intact disk but a different sealing key: the same.
#
# Run with `make test-keystore`.

set -u
cd "$(dirname "$0")/.." || exit 1

SCRATCH=$(mktemp -d /tmp/tepos-ks.XXXXXX) || exit 1
IMG=$SCRATCH/keystore.img
KEK=$SCRATCH/kek.bin
SOCK=$SCRATCH/mb.sock
qpid=
failures=0
trap '[ -n "$qpid" ] && kill $qpid 2>/dev/null; wait 2>/dev/null; rm -rf "$SCRATCH"' EXIT

dd if=/dev/zero of="$IMG" bs=1024 count=1024 2>/dev/null
head -c 32 /dev/urandom >"$KEK"
DEVICES=$(make -s qemu-devices TEP_KEYSTORE_IMG="$IMG" TEP_KEK="$KEK")

boot() {
	rm -f "$SOCK"
	qemu-system-aarch64 -machine virt,secure=off,virtualization=off,gic-version=2 -cpu cortex-a53 -m 1024 \
		-nographic -serial file:"$SCRATCH/console.$1.log" -serial unix:"$SOCK",server=on,wait=off \
		$DEVICES -monitor none -kernel build/boot/sel4-image.elf >"$SCRATCH/qemu.$1.log" 2>&1 </dev/null &
	qpid=$!
	sleep "${2:-6}"
}

halt() {
	kill $qpid 2>/dev/null
	wait $qpid 2>/dev/null
	qpid=
}

result() {
	printf '%-58s %s\n' "$1" "$2"
	[ "$2" = ok ] || failures=$((failures + 1))
}

boot 1
read -r HANDLE PUBLIC < <(python3 tools/mailbox_client.py --socket "$SOCK" key-new)
halt
[ -n "${PUBLIC:-}" ] && result "boot 1: key generated (handle $HANDLE)" ok || result "boot 1: key generated" FAIL

boot 2
python3 tools/mailbox_client.py --socket "$SOCK" key-check "$HANDLE" "$PUBLIC" >/dev/null &&
	result "boot 2: same key after reboot, signature verifies" ok || result "boot 2: same key after reboot" FAIL
halt

cp "$IMG" "$SCRATCH/good.img"
# Flip one byte of the sealed table in both regions (sectors 1 and 17).
python3 - "$IMG" <<'PY'
import sys
with open(sys.argv[1], "r+b") as f:
    for sector in (1, 17):
        f.seek(sector * 512 + 40)
        b = f.read(1)
        f.seek(sector * 512 + 40)
        f.write(bytes([b[0] ^ 0x01]) if b else b"\x01")
PY
boot 3 10
H=$(python3 tools/mailbox_client.py --socket "$SOCK" health)
halt
case "$H" in
*"health=failed"*"[svc 4 disabled"*) result "boot 3: tampered store refused, tepOS health failed" ok ;;
*) result "boot 3: tampered store refused ($H)" FAIL ;;
esac
grep -a -m1 "keystore: FATAL" "$SCRATCH/console.3.log" | tr -d '\r' | sed 's/^/    /'

cp "$SCRATCH/good.img" "$IMG"
head -c 32 /dev/urandom >"$KEK"
boot 4 10
H=$(python3 tools/mailbox_client.py --socket "$SOCK" health)
halt
case "$H" in
*"health=failed"*"[svc 4 disabled"*) result "boot 4: other sealing key refused, tepOS health failed" ok ;;
*) result "boot 4: other sealing key refused ($H)" FAIL ;;
esac

echo "keystore_persist_test: $([ $failures = 0 ] && echo passed || echo "$failures failure(s)")"
[ $failures = 0 ]
