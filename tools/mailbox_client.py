#!/usr/bin/env python3
#
# Host-side client for the NXU <-> tepOS mailbox (boot/include/tep/mailbox.h).
# Stands in for NXU: connects to the Unix socket behind tepOS's serial1, as
# tools/mailbox_link.py does (stop the link first; one peer at a time).
#
#   tools/mailbox_client.py hello|health     one request, print the response
#   tools/mailbox_client.py --selftest       protocol conformance checks
#
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import hashlib
import os
import subprocess
import socket
import struct
import sys
import time
import zlib

MAGIC = 0x5054
VERSION = 1
REQUEST, RESPONSE = 1, 2
HELLO, GET_HEALTH = 0x0001, 0x0002
SHA256, RANDOM = 0x0010, 0x0011
KEY_GENERATE, KEY_PUBLIC, KEY_SIGN, KEY_DELETE = 0x0020, 0x0021, 0x0022, 0x0023
ALG_ED25519 = 1
FEATURE_CRYPTO = 1
ED25519_CHECK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "ed25519_check")
STATUS = {0: "OK", 1: "BAD_VERSION", 2: "BAD_COMMAND", 3: "BAD_LENGTH",
          4: "UNAVAILABLE", 5: "INTERNAL", 6: "NOT_FOUND", 7: "FULL"}
HEALTH = {0: "starting", 1: "ok", 2: "degraded", 3: "failed"}
STATE = {0: "stopped", 1: "starting", 2: "ready", 3: "failed", 4: "disabled"}
HEADER = struct.Struct("<HBBHHIHH")


def frame(command, request_id, payload=b"", version=VERSION, ftype=REQUEST,
          length=None, corrupt_crc=False):
    body = HEADER.pack(MAGIC, version, ftype, command, 0, request_id,
                       len(payload) if length is None else length, 0) + payload
    crc = zlib.crc32(body) & 0xffffffff
    if corrupt_crc:
        crc ^= 1
    return body + struct.pack("<I", crc)


class Link:
    def __init__(self, path, timeout):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.timeout = timeout
        self.buf = b""

    def send(self, data):
        self.sock.sendall(data)

    def recv_frame(self):
        """Next well-formed response frame, or None on timeout."""
        deadline = time.monotonic() + self.timeout
        while True:
            while len(self.buf) >= 2 and self.buf[:2] != b"TP":
                self.buf = self.buf[1:]
            if len(self.buf) >= HEADER.size:
                magic, ver, ftype, cmd, status, rid, plen, _ = HEADER.unpack_from(self.buf)
                total = HEADER.size + plen + 4
                if len(self.buf) >= total:
                    body, crc = self.buf[:total - 4], self.buf[total - 4:total]
                    self.buf = self.buf[total:]
                    if zlib.crc32(body) & 0xffffffff != struct.unpack("<I", crc)[0]:
                        raise AssertionError("response with bad CRC")
                    return dict(version=ver, type=ftype, command=cmd, status=status,
                                request_id=rid, payload=body[HEADER.size:])
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                raise ConnectionError("tepOS closed the link")
            self.buf += chunk

    def request(self, command, request_id, **kw):
        self.send(frame(command, request_id, **kw))
        return self.recv_frame()


def show(resp):
    if resp is None:
        return "no response"
    out = "id=%d %s" % (resp["request_id"], STATUS.get(resp["status"], resp["status"]))
    p = resp["payload"]
    if resp["status"] == 0 and resp["command"] == HELLO and len(p) == 12:
        proto, _, ver, boot = struct.unpack("<HHII", p)
        out += " protocol=%d tepOS=%d.%d.%d boot_id=%d" % (
            proto, ver >> 16, (ver >> 8) & 0xff, ver & 0xff, boot)
    elif resp["status"] == 0 and resp["command"] == GET_HEALTH and len(p) >= 4:
        n = p[1]
        out += " health=%s" % HEALTH.get(p[0], p[0])
        for i in range(n):
            sid, st, rs, _ = p[4 + 4 * i:8 + 4 * i]
            out += " [svc %d %s restarts=%d]" % (sid, STATE.get(st, st), rs)
    return out


def ed25519_valid(public, signature, message):
    """Verify with build/ed25519_check (make ed25519-check), independently of tepOS."""
    if not os.path.exists(ED25519_CHECK):
        raise SystemExit("mailbox_client: run `make ed25519-check` first")
    return subprocess.run([ED25519_CHECK, public.hex(), signature.hex(), message.hex()]).returncode == 0


def crypto_selftest(link, check):
    """The TEP_MB_FEATURE_CRYPTO commands. Returns the number of failures."""
    before = [0]

    def c(name, cond, detail=""):
        before[0] += not cond
        check(name, cond, detail)

    rid = [1000]

    def req(cmd, payload=b""):
        rid[0] += 1
        r = link.request(cmd, rid[0], payload=payload)
        if r is None or r["request_id"] != rid[0]:
            raise AssertionError("no response to command 0x%x" % cmd)
        return r

    r = link.request(HELLO, 999)
    c("HELLO advertises crypto", r and struct.unpack_from("<H", r["payload"], 2)[0] & FEATURE_CRYPTO)

    for msg in (b"abc", bytes(range(240))):
        r = req(SHA256, msg)
        c("SHA256 of %d bytes matches hashlib" % len(msg), r["status"] == 0 and r["payload"] == hashlib.sha256(msg).digest(),
          "status %s" % STATUS.get(r["status"], r["status"]))
    rid[0] += 1
    c("SHA256 over 240 bytes: frame dropped", link.request(SHA256, rid[0], payload=bytes(241)) is None)
    c("SHA256 of nothing refused", req(SHA256, b"")["status"] == 3)

    a, b = req(RANDOM, struct.pack("<H", 32)), req(RANDOM, struct.pack("<H", 32))
    c("RANDOM 32 bytes twice, different", a["status"] == 0 and len(a["payload"]) == 32 and a["payload"] != b["payload"])
    c("RANDOM 65 bytes refused", req(RANDOM, struct.pack("<H", 65))["status"] == 3)

    r = req(KEY_GENERATE, bytes([ALG_ED25519]))
    c("KEY_GENERATE Ed25519", r["status"] == 0 and len(r["payload"]) == 4)
    handle = r["payload"]
    pub = req(KEY_PUBLIC, handle)
    c("KEY_PUBLIC returns 32 bytes", pub["status"] == 0 and len(pub["payload"]) == 32)
    message = b"NXU boot image digest " + hashlib.sha256(b"kernel").digest()
    sig = req(KEY_SIGN, handle + message)
    c("KEY_SIGN returns 64 bytes", sig["status"] == 0 and len(sig["payload"]) == 64)
    c("signature verifies on the host", ed25519_valid(pub["payload"], sig["payload"], message))
    c("signature fails for another message", not ed25519_valid(pub["payload"], sig["payload"], message + b"!"))
    c("KEY_SIGN of 225 bytes refused", req(KEY_SIGN, handle + bytes(225))["status"] == 3)
    c("unknown key algorithm refused", req(KEY_GENERATE, bytes([99]))["status"] == 2)
    c("unknown handle: NOT_FOUND", req(KEY_PUBLIC, struct.pack("<I", 0))["status"] == 6)
    c("KEY_DELETE", req(KEY_DELETE, handle)["status"] == 0)
    c("deleted key: NOT_FOUND", req(KEY_SIGN, handle + b"x")["status"] == 6)

    handles = []
    for _ in range(40):
        r = req(KEY_GENERATE, bytes([ALG_ED25519]))
        if r["status"] != 0:
            break
        handles.append(r["payload"])
    c("key table fills at 32 keys, then FULL", len(handles) == 32 and r["status"] == 7)
    c("handles are unique", len(set(handles)) == len(handles))
    for h in handles:
        req(KEY_DELETE, h)
    return before[0]


def selftest(link):
    failures = 0

    def check(name, cond, detail=""):
        nonlocal failures
        print("%-40s %s %s" % (name, "ok" if cond else "FAIL", detail))
        failures += not cond

    r = link.request(HELLO, 1)
    check("HELLO", r and r["status"] == 0 and r["request_id"] == 1 and len(r["payload"]) == 12, show(r))
    r = link.request(GET_HEALTH, 2)
    ok = r and r["status"] == 0 and len(r["payload"]) >= 4 and len(r["payload"]) == 4 + 4 * r["payload"][1]
    check("GET_HEALTH", ok, show(r))

    link.send(b"\x00garbage\xffTX" * 5)
    r = link.request(HELLO, 3)
    check("resync after garbage", r and r["status"] == 0 and r["request_id"] == 3, show(r))

    r = link.request(HELLO, 4, corrupt_crc=True)
    check("bad CRC is dropped", r is None, show(r))
    r = link.request(HELLO, 5)
    check("valid request after bad CRC", r and r["status"] == 0 and r["request_id"] == 5, show(r))

    r = link.request(HELLO, 6, version=9)
    check("bad version", r and r["status"] == 1 and r["request_id"] == 6 and not r["payload"], show(r))
    r = link.request(0x7777, 7)
    check("unknown command", r and r["status"] == 2 and r["request_id"] == 7, show(r))
    r = link.request(GET_HEALTH, 8, payload=b"\x01\x02")
    check("payload length mismatch", r and r["status"] == 3 and r["request_id"] == 8, show(r))

    link.send(frame(HELLO, 9, length=0xffff))
    r = link.request(HELLO, 10)
    check("oversized length resyncs", r and r["status"] == 0 and r["request_id"] == 10, show(r))

    r = link.request(HELLO, 11, ftype=RESPONSE)
    check("response-type frame ignored", r is None, show(r))

    ids = []
    for i in range(20):
        r = link.request(GET_HEALTH, 100 + i)
        ids.append(r["request_id"] if r else None)
    check("20 back-to-back requests", ids == list(range(100, 120)))

    failures += crypto_selftest(link, check)
    print("selftest: %s" % ("passed" if failures == 0 else "%d failure(s)" % failures))
    return failures == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", nargs="?", choices=["hello", "health", "key-new", "key-check"], default="hello")
    ap.add_argument("args", nargs="*", help="key-check: <handle hex> <public key hex>")
    ap.add_argument("--socket", default="/tmp/tepos-mailbox.sock")
    ap.add_argument("--timeout", type=float, default=2.0, help="seconds to wait for each response")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    link = Link(args.socket, args.timeout)
    if args.command == "key-new":
        # Prints "<handle hex> <public key hex>" of a new Ed25519 key.
        r = link.request(KEY_GENERATE, 1, payload=bytes([ALG_ED25519]))
        if not r or r["status"] != 0:
            sys.exit("key-new: %s" % show(r))
        p = link.request(KEY_PUBLIC, 2, payload=r["payload"])
        print(r["payload"].hex(), p["payload"].hex())
        sys.exit(0)
    if args.command == "key-check":
        # The key must still exist with the same public key and sign verifiably.
        handle, public = bytes.fromhex(args.args[0]), bytes.fromhex(args.args[1])
        p = link.request(KEY_PUBLIC, 1, payload=handle)
        msg = b"tepOS persistence check"
        sig = link.request(KEY_SIGN, 2, payload=handle + msg)
        ok = (p and p["status"] == 0 and p["payload"] == public and sig and sig["status"] == 0
              and ed25519_valid(public, sig["payload"], msg))
        print("key-check: %s" % ("ok" if ok else "FAIL (%s / %s)" % (show(p), show(sig))))
        sys.exit(0 if ok else 1)
    if args.selftest:
        sys.exit(0 if selftest(link) else 1)
    r = link.request(HELLO if args.command == "hello" else GET_HEALTH, 1)
    print(show(r))
    sys.exit(0 if r and r["status"] == 0 else 1)


if __name__ == "__main__":
    main()
