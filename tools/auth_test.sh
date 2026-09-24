#!/usr/bin/env bash
#
# tools/auth_test.sh -- the AuthenticationService's passcode and attempt limits.
#
# Runs on a scratch key store (your build/tepos-keystore.img is not used) and
# moves tepOS's clock with QEMU's -rtc base= between boots, which also shows
# the failure counter survives reboots:
#
#   boot 1  no passcode yet; set one; right and wrong attempts; a right one
#           resets the counter; five wrong ones in a row -> RETRY_LATER ~60 s
#   boot 2  +2 min: the counter is still 5; a wrong attempt -> wait ~300 s
#   boot 3..5  further wrong attempts after each wait: 900 s, 3600 s, 3600 s
#   boot 6  the tenth failure -> LOCKED, even for the right passcode
#   boot 7  with fw_cfg opt/org.tepos/auth-reset: the passcode is cleared and
#           a new one can be set
#
# Run with `make test-auth`.

set -u
cd "$(dirname "$0")/.." || exit 1

SCRATCH=$(mktemp -d /tmp/tepos-auth.XXXXXX) || exit 1
IMG=$SCRATCH/keystore.img
KEK=$SCRATCH/kek.bin
SOCK=$SCRATCH/mb.sock
qpid=
failures=0
trap '[ -n "$qpid" ] && kill $qpid 2>/dev/null; wait 2>/dev/null; rm -rf "$SCRATCH"' EXIT

dd if=/dev/zero of="$IMG" bs=1024 count=1024 2>/dev/null
head -c 32 /dev/urandom >"$KEK"
printf 1 >"$SCRATCH/reset"
DEVICES=$(make -s qemu-devices TEP_KEYSTORE_IMG="$IMG" TEP_KEK="$KEK")
T0=$(date -u +%s)

# boot <n> <seconds after T0> [extra QEMU arguments]
boot() {
	local base
	base=$(python3 -c 'import sys, datetime; print(datetime.datetime.fromtimestamp(int(sys.argv[1]), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"))' $((T0 + $2)))
	rm -f "$SOCK"
	qemu-system-aarch64 -machine virt,secure=off,virtualization=off,gic-version=2 -cpu cortex-a53 -m 1024 \
		-nographic -serial file:"$SCRATCH/console.$1.log" -serial unix:"$SOCK",server=on,wait=off \
		$DEVICES -rtc base="$base" ${3:-} -monitor none -kernel build/boot/sel4-image.elf \
		>"$SCRATCH/qemu.$1.log" 2>&1 </dev/null &
	qpid=$!
	sleep 6
}

halt() {
	kill $qpid 2>/dev/null
	wait $qpid 2>/dev/null
	qpid=
}

mb() {
	python3 tools/mailbox_client.py --socket "$SOCK" --timeout 20 "$@"
}

# expect <label> <pattern> <actual>
expect() {
	case "$3" in
	$2) printf '%-60s ok\n' "$1" ;;
	*) printf '%-60s FAIL (%s)\n' "$1" "$3"; failures=$((failures + 1)) ;;
	esac
}

# expect_wait <label> <seconds> <actual>: RETRY_LATER within 15 s below <seconds>.
expect_wait() {
	local n=${3#RETRY_LATER }
	if [ "${3%% *}" = RETRY_LATER ] && [ "$n" -le "$2" ] && [ "$n" -ge $(($2 - 15)) ]; then
		printf '%-60s ok\n' "$1"
	else
		printf '%-60s FAIL (%s)\n' "$1" "$3"
		failures=$((failures + 1))
	fi
}

boot 1 0
expect "boot 1: no passcode yet" "set=0 failures=0*" "$(mb auth-status)"
expect "boot 1: verify without a passcode -> NOT_FOUND" "NOT_FOUND" "$(mb auth-verify 1234)"
expect "boot 1: set a passcode" "OK" "$(mb auth-set - 1234)"
expect "boot 1: setting again without the old one -> DENIED" "DENIED" "$(mb auth-set - 5678)"
expect "boot 1: right passcode -> OK" "OK" "$(mb auth-verify 1234)"
for i in 1 2 3; do mb auth-verify 0000 >/dev/null; done
expect "boot 1: right passcode after 3 wrong -> OK" "OK" "$(mb auth-verify 1234)"
expect "boot 1: the counter was reset" "set=1 failures=0 locked=0*" "$(mb auth-status)"
for i in 1 2 3 4; do mb auth-verify 0000 >/dev/null; done
expect "boot 1: fifth wrong passcode -> DENIED" "DENIED" "$(mb auth-verify 0000)"
expect_wait "boot 1: then even the right one must wait ~60 s" 60 "$(mb auth-verify 1234)"
halt

boot 2 120
expect "boot 2 (+2 min): counter kept across the reboot" "set=1 failures=5 locked=0 wait=0" "$(mb auth-status)"
expect "boot 2: wrong passcode -> DENIED" "DENIED" "$(mb auth-verify 0000)"
expect_wait "boot 2: then a wait of ~300 s" 300 "$(mb auth-verify 1234)"
halt

boot 3 500
expect "boot 3 (+5 min later): wrong -> DENIED, then ~900 s" "DENIED" "$(mb auth-verify 0000)"
expect_wait "boot 3: wait ~900 s" 900 "$(mb auth-verify 1234)"
halt

boot 4 1500
expect "boot 4: wrong -> DENIED, then ~3600 s" "DENIED" "$(mb auth-verify 0000)"
expect_wait "boot 4: wait ~3600 s" 3600 "$(mb auth-verify 1234)"
halt

boot 5 5200
expect "boot 5: ninth wrong -> DENIED, then ~3600 s" "DENIED" "$(mb auth-verify 0000)"
expect_wait "boot 5: wait ~3600 s" 3600 "$(mb auth-verify 1234)"
halt

boot 6 8900
expect "boot 6: tenth wrong passcode -> LOCKED" "LOCKED" "$(mb auth-verify 0000)"
expect "boot 6: the right passcode is refused too" "LOCKED" "$(mb auth-verify 1234)"
expect "boot 6: status" "set=1 failures=10 locked=1*" "$(mb auth-status)"
halt

boot 7 9000 "-fw_cfg name=opt/org.tepos/auth-reset,file=$SCRATCH/reset"
expect "boot 7 (recovery reset): passcode cleared" "set=0 failures=0 locked=0*" "$(mb auth-status)"
expect "boot 7: a new passcode can be set" "OK" "$(mb auth-set - 2468)"
expect "boot 7: and verifies" "OK" "$(mb auth-verify 2468)"
grep -a -m1 "recovery reset" "$SCRATCH/console.7.log" | tr -d '\r' | sed 's/^/    /'
halt

echo "auth_test: $([ $failures = 0 ] && echo passed || echo "$failures failure(s)")"
[ $failures = 0 ]
