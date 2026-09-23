#!/usr/bin/env python3
#
# Host-side client for the NXU <-> tepOS mailbox (boot/include/tep/mailbox.h).
# Connects to the Unix socket behind tepOS's serial1, like NXU's QEMU does.
#
#   tools/mailbox_client.py hello|health     one request, print the response
#   tools/mailbox_client.py --selftest       protocol conformance checks
#
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import socket
import struct
import sys
import time
import zlib

MAGIC = 0x5054
VERSION = 1
REQUEST, RESPONSE = 1, 2
HELLO, GET_HEALTH = 0x0001, 0x0002
STATUS = {0: "OK", 1: "BAD_VERSION", 2: "BAD_COMMAND", 3: "BAD_LENGTH",
          4: "UNAVAILABLE", 5: "INTERNAL"}
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

    print("selftest: %s" % ("passed" if failures == 0 else "%d failure(s)" % failures))
    return failures == 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", nargs="?", choices=["hello", "health"], default="hello")
    ap.add_argument("--socket", default="/tmp/tepos-mailbox.sock")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    link = Link(args.socket, args.timeout)
    if args.selftest:
        sys.exit(0 if selftest(link) else 1)
    r = link.request(HELLO if args.command == "hello" else GET_HEALTH, 1)
    print(show(r))
    sys.exit(0 if r and r["status"] == 0 else 1)


if __name__ == "__main__":
    main()
