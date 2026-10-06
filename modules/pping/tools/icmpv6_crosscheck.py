#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-check for the SELF-DERIVED ICMPv6 echo packets in ../src/echo_kat.zig.

The kernel this module's captures were taken on has no IPv6, so
`capture_icmp_echo.sh` could not record a real `ping -6` run. Instead this
script builds the IPv6 packets the KAT uses (fd00::1 <-> fd00::2, Echo
Request 128 / Echo Reply 129, RFC 4443 checksum over the RFC 8200 §8.1
pseudo-header), prints each as hex (the KAT pastes these), writes them to a
LINKTYPE_IPV6 pcap and lets an independent dissector -- `tcpdump -vv` --
decode them. The anchor is tcpdump agreeing on type, id, seq and checksum,
not a real stack having sent them.

Usage: tools/icmpv6_crosscheck.py OUTDIR
"""
import os
import struct
import subprocess
import sys

SRC = bytes.fromhex("fd000000000000000000000000000001")
DST = bytes.fromhex("fd000000000000000000000000000002")
PAYLOAD = b"pping-v6"


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def packet(src: bytes, dst: bytes, typ: int, ident: int, seq: int) -> bytes:
    icmp = struct.pack("!BBHHH", typ, 0, 0, ident, seq) + PAYLOAD
    pseudo = src + dst + struct.pack("!I3xB", len(icmp), 58)
    icmp = icmp[:2] + struct.pack("!H", csum(pseudo + icmp)) + icmp[4:]
    ip6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, 64) + src + dst
    return ip6 + icmp


# (name, src, dst, type, id, seq): the order the KAT feeds them.
FRAMES = [
    ("req_1", SRC, DST, 128, 0x5A5A, 1),
    ("rep_1", DST, SRC, 129, 0x5A5A, 1),
    ("req_ffff", SRC, DST, 128, 0x5A5A, 0xFFFF),
    ("rep_ffff", DST, SRC, 129, 0x5A5A, 0xFFFF),
    ("req_0", SRC, DST, 128, 0x5A5A, 0),
    ("rep_0", DST, SRC, 129, 0x5A5A, 0),
]


def main() -> None:
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "v6_selfderived.pcap")
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 229))
        for i, (name, src, dst, typ, ident, seq) in enumerate(FRAMES):
            p = packet(src, dst, typ, ident, seq)
            print(name, p.hex())
            f.write(struct.pack("<IIII", 1, i, len(p), len(p)) + p)
    subprocess.run(["tcpdump", "-r", path, "-n", "-vv"], check=True)


if __name__ == "__main__":
    main()
