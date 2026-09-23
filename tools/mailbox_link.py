#!/usr/bin/env python3
#
# The serial cable between NXU and tepOS (boot/include/tep/mailbox.h).
#
# Both QEMUs expose their mailbox UART as a listening Unix socket
# (tepOS: `make run`, serial1; NXU: TEP_SERIAL1 in its makedefs/tests.mk).
# This relay connects to both and copies bytes in each direction. When either
# machine goes away it drops both connections and waits for both sockets
# again, so either side can restart; bytes in flight at that moment are lost,
# as on an unplugged cable, and NXU's request times out.
#
# QEMU itself is never the connecting side because QEMU 11.1 aborts a
# reconnecting socket client whenever a connection attempt fails.
#
#   tools/mailbox_link.py [--nxu /tmp/nxu-mailbox.sock] [--tepos /tmp/tepos-mailbox.sock]
#
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import select
import socket
import sys
import time


def log(msg):
    print("mailbox_link: " + msg, file=sys.stderr, flush=True)


def connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(path)
    except OSError:
        s.close()
        return None
    return s


def recv(s):
    try:
        return s.recv(4096)
    except OSError:
        return b""


def relay(a, b):
    """Copy bytes both ways until one side closes; return that side."""
    peer = {a: b, b: a}
    while True:
        readable, _, _ = select.select([a, b], [], [])
        for s in readable:
            data = recv(s)
            if not data:
                return s
            try:
                peer[s].sendall(data)
            except OSError:
                return peer[s]


def main():
    ap = argparse.ArgumentParser(description="NXU <-> tepOS mailbox relay")
    ap.add_argument("--nxu", default="/tmp/nxu-mailbox.sock")
    ap.add_argument("--tepos", default="/tmp/tepos-mailbox.sock")
    args = ap.parse_args()

    ends = {"NXU": [args.nxu, None], "tepOS": [args.tepos, None]}
    while True:
        for name, end in ends.items():
            if end[1] is None:
                end[1] = connect(end[0])
                if end[1]:
                    log("%s connected" % name)

        nxu, tep = ends["NXU"][1], ends["tepOS"][1]
        if nxu and tep:
            log("linked")
            gone = relay(nxu, tep)
            name = "NXU" if gone is nxu else "tepOS"
            gone.close()
            ends[name][1] = None
            log("%s went away; waiting for it" % name)
            continue

        # One side only: discard what it sends (nobody can answer it) and notice if it goes.
        held = [s for s in (nxu, tep) if s]
        if not held:
            time.sleep(0.2)
            continue
        readable, _, _ = select.select(held, [], [], 0.2)
        for s in readable:
            if not recv(s):
                name = "NXU" if s is nxu else "tepOS"
                s.close()
                ends[name][1] = None
                log("%s went away" % name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
