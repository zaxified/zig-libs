#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Generate src/tcpdump_fixtures.zig: ICMP error messages the loopback
capture cannot produce (redirect, source quench, time exceeded, parameter
problem, packet too big, ...), each decoded by tcpdump as a black-box oracle.

The packets are built here from RFC 792 / RFC 4443; what makes them an
EXTERNAL anchor is that every expected value written into the fixture file --
the error kind and code, the quoted echo request's identifier and sequence,
the quoted addresses -- is read back out of tcpdump's own decoding of the
packet, not taken from the builder. A packet tcpdump decodes differently
from what the builder meant aborts the run.

For ICMPv6 errors tcpdump decodes the outer message but not the quoted
invoking packet, so the quoted packet is also handed to tcpdump on its own
and its identifier/sequence are taken from that decoding. The quoted
packet's position (byte 8 of the error message) is anchored separately by
the real kernel capture in echo.zig (`v6_dest_unreach_icmp`).

Needs tcpdump (4.99 used; reading a pcap file needs no privilege).
Usage (from modules/icmp): python3 tools/gen_tcpdump_fixtures.py > src/tcpdump_fixtures.zig
"""
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip4(src, dst, proto, payload, ttl=64):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, ttl, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + payload


def icmp4(t, c, rest, data):
    b = struct.pack("!BBH", t, c, 0) + rest + data
    return b[:2] + struct.pack("!H", csum(b)) + b[4:]


def ip6(src, dst, nh, payload, hl=64):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nh, hl,
                       socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, dst)) + payload


def icmp6(src, dst, t, c, rest, data):
    b = struct.pack("!BBH", t, c, 0) + rest + data
    ph = (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
          + struct.pack("!I3xB", len(b), 58))
    return b[:2] + struct.pack("!H", csum(ph + b)) + b[4:]


# (family, type, code, rest-of-header, quoted ident, quoted seq,
#  regex tcpdump must print for the outer message, kind it means)
V4_CASES = [
    (3, 1, b"\0" * 4, 0x1234, 77, r"ICMP host 198\.51\.100\.7 unreachable", "dest_unreachable"),
    (4, 0, b"\0" * 4, 0x1235, 78, r"ICMP source quench", "other"),
    (5, 1, socket.inet_aton("192.0.2.254"), 0x1236, 79, r"ICMP redirect 198\.51\.100\.7 to host 192\.0\.2\.254", "redirect"),
    (11, 0, b"\0" * 4, 0x1237, 80, r"ICMP time exceeded in-transit", "time_exceeded"),
    (11, 1, b"\0" * 4, 0x1238, 81, r"ICMP ip reassembly time exceeded", "time_exceeded"),
    (12, 0, bytes([20, 0, 0, 0]), 0x1239, 82, r"ICMP parameter problem - octet 20", "param_problem"),
]
V6_CASES = [
    (1, 4, b"\0" * 4, 0xBEEF, 513, r"ICMP6, destination unreachable, unreachable port", "dest_unreachable"),
    (1, 0, b"\0" * 4, 0xBEF0, 514, r"ICMP6, destination unreachable, unreachable route", "dest_unreachable"),
    (2, 0, struct.pack("!I", 1280), 0xBEF1, 515, r"ICMP6, packet too big, mtu 1280", "packet_too_big"),
    (3, 0, b"\0" * 4, 0xBEF2, 516, r"ICMP6, time exceeded in-transit", "time_exceeded"),
    (4, 0, struct.pack("!I", 6), 0xBEF3, 517, r"ICMP6, parameter problem, erroneous - octet 6", "param_problem"),
]
V6_CODE = {  # tcpdump phrase -> RFC 4443 code, read from tcpdump's wording
    "unreachable port": 4, "unreachable route": 0, "packet too big": 0,
    "time exceeded in-transit": 0, "erroneous": 0,
}


def build():
    packets = []  # (family, outer bytes for the pcap, icmp bytes, quoted bytes, case)
    for case in V4_CASES:
        t, c, rest, ident, seq = case[:5]
        echo = icmp4(8, 0, struct.pack("!HH", ident, seq), b"")
        quoted = ip4("192.0.2.1", "198.51.100.7", 1, echo, ttl=1)
        icmp = icmp4(t, c, rest, quoted)
        packets.append(("v4", ip4("192.0.2.9", "192.0.2.1", 1, icmp), icmp, None, case))
    for case in V6_CASES:
        t, c, rest, ident, seq = case[:5]
        echo = icmp6("2001:db8::1", "2001:db8:1::7", 128, 0, struct.pack("!HH", ident, seq), b"")
        quoted = ip6("2001:db8::1", "2001:db8:1::7", 58, echo, hl=1)
        icmp = icmp6("2001:db8::9", "2001:db8::1", t, c, rest, quoted)
        packets.append(("v6", ip6("2001:db8::9", "2001:db8::1", 58, icmp), icmp, quoted, case))
    return packets


def tcpdump(frames):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "f.pcap")
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))  # LINKTYPE_RAW
            for i, p in enumerate(frames):
                f.write(struct.pack("<IIII", i, 0, len(p), len(p)) + p)
        out = subprocess.run(["tcpdump", "-nn", "-vv", "-r", path], check=True,
                             capture_output=True, text=True).stdout
    # One record per packet: a line starting with the timestamp opens it.
    records = []
    for line in out.splitlines():
        if re.match(r"^\d\d:\d\d:\d\d\.\d+ ", line):
            records.append(line)
        else:
            records[-1] += "\n" + line
    if len(records) != len(frames):
        sys.exit(f"tcpdump printed {len(records)} records for {len(frames)} packets")
    return records


def zig_bytes(b):
    rows = []
    for i in range(0, len(b), 16):
        rows.append("            " + " ".join("0x%02x," % x for x in b[i:i + 16]))
    return "&[_]u8{\n" + "\n".join(rows) + "\n    }"


def main():
    packets = build()
    outer = tcpdump([p[1] for p in packets])
    quoted6 = tcpdump([p[3] for p in packets if p[0] == "v6"])
    q6 = iter(quoted6)
    out = sys.stdout
    out.write("// SPDX-License-Identifier: MIT\n")
    out.write("//! GENERATED by tools/gen_tcpdump_fixtures.py -- do not edit by hand.\n")
    out.write("//!\n")
    out.write("//! ICMP error messages the loopback capture cannot produce, with every\n")
    out.write("//! expected value read from tcpdump's decoding of the packet (tcpdump used\n")
    out.write("//! as a black-box oracle; its output line is kept in `tcpdump`).\n\n")
    out.write("pub const Case = struct {\n")
    out.write("    family: enum { v4, v6 },\n    icmp: []const u8,\n    ip: []const u8,\n")
    out.write("    kind: []const u8,\n    code: u8,\n    ident: u16,\n    seq: u16,\n")
    out.write("    quoted_src: []const u8,\n    quoted_dst: []const u8,\n    tcpdump: []const u8,\n};\n\n")
    out.write("pub const cases = [_]Case{\n")
    for (fam, frame, icmp, quoted, case), rec in zip(packets, outer):
        t, c, rest, ident, seq, pattern, kind = case
        if not re.search(pattern, rec):
            sys.exit(f"tcpdump decoded type {t} code {c} as:\n{rec}\nexpected /{pattern}/")
        if fam == "v4":
            if "wrong icmp cksum" in rec:
                sys.exit(f"tcpdump: bad checksum\n{rec}")
            m = re.search(r"(\S+) > (\S+): ICMP echo request, id (\d+), seq (\d+)", rec)
            if not m:
                sys.exit(f"tcpdump did not decode the quoted echo request:\n{rec}")
            src, dst, got_id, got_seq = m.group(1), m.group(2), int(m.group(3)), int(m.group(4))
            code = c  # tcpdump's v4 wording names the code; the pattern pinned which one
            src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
        else:
            if "[icmp6 sum ok]" not in rec:
                sys.exit(f"tcpdump: ICMPv6 checksum not ok\n{rec}")
            qrec = next(q6)
            m = re.search(r"\[icmp6 sum ok\] ICMP6, echo request, id (\d+), seq (\d+)", qrec)
            a = re.search(r"\) (\S+) > (\S+): ", qrec)
            if not m or not a:
                sys.exit(f"tcpdump did not decode the quoted echo request:\n{qrec}")
            got_id, got_seq = int(m.group(1)), int(m.group(2))
            src, dst = a.group(1), a.group(2)
            phrase = next(k for k in V6_CODE if k in rec)
            code = V6_CODE[phrase]
            src_b = socket.inet_pton(socket.AF_INET6, src)
            dst_b = socket.inet_pton(socket.AF_INET6, dst)
        line = " ".join(rec.split())
        out.write("    .{\n")
        out.write(f"        .family = .{fam},\n")
        out.write(f"        .icmp = {zig_bytes(icmp)},\n".replace("\n    }", "\n        }"))
        out.write(f"        .ip = {zig_bytes(frame)},\n".replace("\n    }", "\n        }"))
        out.write(f'        .kind = "{kind}",\n        .code = {code},\n')
        out.write(f"        .ident = {got_id},\n        .seq = {got_seq},\n")
        out.write(f"        .quoted_src = {zig_bytes(src_b)},\n".replace("\n    }", "\n        }"))
        out.write(f"        .quoted_dst = {zig_bytes(dst_b)},\n".replace("\n    }", "\n        }"))
        out.write('        .tcpdump = "' + line.replace("\\", "\\\\").replace('"', '\\"') + '",\n')
        out.write("    },\n")
    out.write("};\n")


if __name__ == "__main__":
    main()
