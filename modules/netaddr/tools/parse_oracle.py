#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Parse/format/prefix oracle for netaddr: glibc's inet_pton/inet_ntop and
Python's ipaddress, both black boxes, through Python's own socket module.

Writes `src/parse_vectors.zig`, replayed by `src/parse_oracle_test.zig` with
no Python at test time:

    python3 modules/netaddr/tools/parse_oracle.py > modules/netaddr/src/parse_vectors.zig
    python3 modules/netaddr/tools/parse_oracle.py --check   # re-take, compare with the committed file

Literals: a crafted table of hostile shapes plus generated ones (every way of
writing a random address with zero runs, uppercase, leading zeros, an IPv4
tail, and single-character mutations of all of those). For each: what glibc's
inet_pton makes of it as IPv4 and as IPv6 (the bytes, or a refusal), whether
Python's ipaddress accepts it, and the text glibc's inet_ntop and Python print
for it. Prefixes: Python's ip_network(strict=False) verdict and network.
Ranges and prefix sets: Python's summarize_address_range and
collapse_addresses. glibc and Python are black boxes -- only their answers
are recorded.
"""
import ipaddress
import os
import platform
import random
import socket
import sys

SEED = 5952

CRAFTED = [
    "", " ", "1.2.3.4", "0.0.0.0", "255.255.255.255", "256.1.1.1", "1.2.3", "1.2.3.4.5", "1.2.3.", ".1.2.3",
    "01.2.3.4", "1.02.3.4", "1.2.3.04", "00.0.0.0", "0x1.2.3.4", "1.2.3.4 ", " 1.2.3.4", "1..3.4", "1.2.3.-4",
    "+1.2.3.4", "1.2.3.4\x00", "1.2.3.0255", "4294967295", "127.1", "1.2.3.4/32", "1,2,3,4", "１.2.3.4",
    "::", "::1", "1::", "1::1", ":::", "::::", "1:::1", ":1::", "::1:", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9",
    "1:2:3:4:5:6:7", "1:2:3:4:5:6:7::", "::2:3:4:5:6:7:8", "1::3:4:5:6:7:8", "1:2:3:4:5:6::8",
    "1:2:3:4:5:6:7:8::", "::1:2:3:4:5:6:7:8", "1::2::3", "12345::", "1:00000::", "1:0000::", "0001::",
    "ABCD::EF", "abcd::ef", "AbCd::eF", "g::", "::g", "fe80::1%eth0", "fe80::1%", "fe80::1%1", "[::1]",
    "::ffff:1.2.3.4", "::FFFF:1.2.3.4", "::1.2.3.4", "::ffff:0:1.2.3.4", "64:ff9b::1.2.3.4",
    "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "1:2:3:4:5:1.2.3.4", "::1.2.3", "::1.2.3.4.5",
    "::01.2.3.4", "::256.2.3.4", "::1.2.3.4:5", "1.2.3.4::", "::ffff:1.2.3.4:5", "::ffff:1.2.3.04",
    "2001:db8::", "2001:DB8::1", "2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1", "2001:0db8:0000:0000:0000:0000:0000:0001",
    "2001:db8:0:1:1:1:1:1", "2001:db8::0:1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0",
    "0:0:1:0:0:0:0:1", "1:0:0:1:0:0:0:1", "1:0:0:0:1:0:0:0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    "::ffff:0.0.0.0", "::0.0.0.0", "::0.0.0.1", "::0:1.2.3.4", "0:0:0:0:0:ffff:1.2.3.4", "::ffff:255.255.255.255",
    "1::ffff:1.2.3.4", "::1:ffff:1.2.3.4", "::-1", "::+1", "::1 ", " ::1", ":: 1", "::\t1", "::0x1",
]

PREFIX_CRAFTED = [
    "1.2.3.4/0", "1.2.3.4/8", "1.2.3.4/24", "1.2.3.4/32", "1.2.3.4/33", "1.2.3.4/", "1.2.3.4", "/24",
    "1.2.3.4/08", "1.2.3.4/-1", "1.2.3.4/+8", "1.2.3.4/ 8", "1.2.3.4/255.255.255.0", "1.2.3.4/0.0.0.255",
    "1.2.3.4//8", "1.2.3.4/8/8", "1.2.3.4/1e1", "::/0", "::1/128", "::1/129", "2001:db8::1/32", "2001:db8::/64",
    "2001:db8::/064", "::ffff:1.2.3.4/96", "::ffff:1.2.3.4/120", "fe80::1%eth0/64", "1.2.3.4/4294967304",
    "1.2.3.4/00", "::/00", "01.2.3.4/8", "1.2.3.4 /8",
]


def rand_v6(rnd):
    b = bytearray(rnd.getrandbits(8) for _ in range(16))
    # zero runs, so compression has something to choose between
    for _ in range(rnd.randint(0, 3)):
        start = rnd.randrange(8)
        length = rnd.randint(1, 8 - start)
        for g in range(start, start + length):
            b[2 * g] = b[2 * g + 1] = 0
    if rnd.random() < 0.15:
        b[:12] = bytes(10) + b"\xff\xff"
    elif rnd.random() < 0.05:
        b[:12] = bytes(12)
    return bytes(b)


def spellings(rnd, b):
    """Several ways a person or a program writes the same IPv6 address."""
    groups = [int.from_bytes(b[i:i + 2], "big") for i in range(0, 16, 2)]
    out = [":".join(f"{g:x}" for g in groups), ":".join(f"{g:04x}" for g in groups), str(ipaddress.IPv6Address(b))]
    # compress a random zero run (not necessarily the longest)
    runs = []
    i = 0
    while i < 8:
        if groups[i] == 0:
            j = i
            while j < 8 and groups[j] == 0:
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    if runs:
        s, e = rnd.choice(runs)
        left = ":".join(f"{g:x}" for g in groups[:s])
        right = ":".join(f"{g:x}" for g in groups[e:])
        out.append(f"{left}::{right}")
    t = rnd.choice(out)
    out.append(t.upper())
    v4 = ".".join(str(x) for x in b[12:])
    head = ":".join(f"{g:x}" for g in groups[:6])
    out.append(f"{head}:{v4}")
    return out


def mutate(rnd, t):
    alphabet = "0123456789abcdefABCDEF:.%/ gx"
    if not t:
        return rnd.choice(alphabet)
    i = rnd.randrange(len(t) + 1)
    op = rnd.randrange(3)
    if op == 0:
        return t[:i] + rnd.choice(alphabet) + t[i:]
    if op == 1 and i < len(t):
        return t[:i] + t[i + 1:]
    if i < len(t):
        return t[:i] + rnd.choice(alphabet) + t[i + 1:]
    return t + rnd.choice(alphabet)


def literals(rnd):
    seen = []
    pool = list(CRAFTED)
    for _ in range(220):
        pool += spellings(rnd, rand_v6(rnd))
    for _ in range(80):
        q = [rnd.randrange(256) for _ in range(4)]
        pool.append(".".join(map(str, q)))
        pool.append(".".join(rnd.choice([str(x), f"0{x}", str(x)]) for x in q))
    base = list(pool)
    for _ in range(900):
        pool.append(mutate(rnd, rnd.choice(base)))
    for t in pool:
        if t not in seen:
            seen.append(t)
    return seen


def pton(fam, t):
    try:
        return socket.inet_pton(fam, t)
    except (OSError, ValueError, UnicodeEncodeError):
        return None


def py_accepts(t):
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


def zstr(s):
    out = ['"']
    for ch in s.encode("utf-8"):
        c = chr(ch)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif 0x20 <= ch < 0x7f:
            out.append(c)
        else:
            out.append(f"\\x{ch:02x}")
    out.append('"')
    return "".join(out)


def zlist(items):
    """A Zig `&.{...}` literal laid out the way `zig fmt` lays it out."""
    items = list(items)
    if not items:
        return "&.{}"
    if len(items) == 1:
        return "&.{" + items[0] + "}"
    return "&.{ " + ", ".join(items) + " }"


def opt(s):
    return "null" if s is None else zstr(s)


def generate(w):
    rnd = random.Random(SEED)
    libc = platform.libc_ver()
    w("// SPDX-License-Identifier: MIT\n")
    w(f"// GENERATED by modules/netaddr/tools/parse_oracle.py ({libc[0]} {libc[1]}, Python {platform.python_version()}) -- do not hand-edit.\n")
    w("//! glibc inet_pton/inet_ntop and Python ipaddress verdicts, replayed by\n")
    w("//! `parse_oracle_test.zig`. Regenerate with the command in the script's docstring.\n\n")
    w(f"pub const glibc_version = \"{libc[1]}\";\n")
    w(f"pub const python_version = \"{platform.python_version()}\";\n\n")
    w("/// `v4`/`v6`: the bytes glibc's inet_pton gave (hex), or null when it refused the\n")
    w("/// text for that family. `ntop`: glibc's inet_ntop of those bytes; `py`: Python's\n")
    w("/// str() of its parse, null when ipaddress refused the text.\n")
    w("pub const Literal = struct { text: []const u8, v4: ?[]const u8, v6: ?[]const u8, ntop: ?[]const u8, py: ?[]const u8 };\n")
    w("/// Python's ip_network(text, strict=False): the network in CIDR text, or null.\n")
    w("pub const PrefixCase = struct { text: []const u8, py: ?[]const u8 };\n")
    w("/// summarize_address_range(from, to) / collapse_addresses(in), as CIDR texts.\n")
    w("pub const RangeCase = struct { from: []const u8, to: []const u8, out: []const []const u8 };\n")
    w("pub const MergeCase = struct { in: []const []const u8, out: []const []const u8 };\n\n")

    w("pub const literals = [_]Literal{\n")
    for t in literals(rnd):
        b4 = pton(socket.AF_INET, t)
        b6 = pton(socket.AF_INET6, t)
        ntop = None
        if b4 is not None:
            ntop = socket.inet_ntop(socket.AF_INET, b4)
        elif b6 is not None:
            ntop = socket.inet_ntop(socket.AF_INET6, b6)
        py = str(ipaddress.ip_address(t)) if py_accepts(t) else None
        w(f"    .{{ .text = {zstr(t)}, .v4 = {opt(b4.hex() if b4 else None)}, .v6 = {opt(b6.hex() if b6 else None)}, .ntop = {opt(ntop)}, .py = {opt(py)} }},\n")
    w("};\n\n")

    prefixes = list(PREFIX_CRAFTED)
    for _ in range(150):
        if rnd.random() < 0.5:
            a = ".".join(str(rnd.randrange(256)) for _ in range(4))
            prefixes.append(f"{a}/{rnd.randint(0, 32)}")
        else:
            a = str(ipaddress.IPv6Address(rand_v6(rnd)))
            prefixes.append(f"{a}/{rnd.randint(0, 128)}")
    for _ in range(60):
        prefixes.append(mutate(rnd, rnd.choice(prefixes)))
    w("pub const prefixes = [_]PrefixCase{\n")
    done = set()
    for t in prefixes:
        if t in done:
            continue
        done.add(t)
        try:
            py = str(ipaddress.ip_network(t, strict=False))
        except ValueError:
            py = None
        w(f"    .{{ .text = {zstr(t)}, .py = {opt(py)} }},\n")
    w("};\n\n")

    w("pub const ranges = [_]RangeCase{\n")
    for _ in range(200):
        if rnd.random() < 0.5:
            bits, mk = 32, ipaddress.IPv4Address
        else:
            bits, mk = 128, ipaddress.IPv6Address
        x = rnd.getrandbits(bits)
        span = rnd.getrandbits(rnd.choice([0, 1, 4, 8, 16, 24, bits // 2, bits - 1]))
        y = min(x + span, (1 << bits) - 1)
        if rnd.random() < 0.2:  # aligned starts and ends, the common real case
            m = rnd.randint(1, bits // 2)
            x &= ~((1 << m) - 1)
            y = min(y | ((1 << m) - 1), (1 << bits) - 1)
        out = [str(n) for n in ipaddress.summarize_address_range(mk(x), mk(y))]
        w(f"    .{{ .from = {zstr(str(mk(x)))}, .to = {zstr(str(mk(y)))}, .out = {zlist(zstr(o) for o in out)} }},\n")
    w("};\n\n")

    w("pub const merges = [_]MergeCase{\n")
    for _ in range(200):
        fam4 = rnd.random() < 0.5
        bits = 32 if fam4 else 128
        base = rnd.getrandbits(bits)
        nets = []
        texts = []  # unmasked, as a caller would hand them over
        for _ in range(rnd.randint(1, 12)):
            plen = rnd.randint(max(0, bits - 12), bits) if rnd.random() < 0.8 else rnd.randint(0, bits)
            a = (base ^ rnd.getrandbits(12)) & ((1 << bits) - 1)
            addr = ipaddress.IPv4Address(a) if fam4 else ipaddress.IPv6Address(a)
            texts.append(f"{addr}/{plen}")
            nets.append(ipaddress.ip_network(texts[-1], strict=False))
        out = [str(n) for n in ipaddress.collapse_addresses(nets)]
        w(f"    .{{ .in = {zlist(zstr(t) for t in texts)}, .out = {zlist(zstr(o) for o in out)} }},\n")
    w("};\n")


def body(text):
    """The vectors without their `// GENERATED ... (versions)` line: the
    versions are provenance, the verdicts are the anchor. A runner with
    another kernel or Python build passes as long as every verdict agrees."""
    return "".join(l for l in text.splitlines(True) if not l.startswith("// GENERATED by "))


def main():
    if "--check" in sys.argv:
        parts = []
        generate(parts.append)
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "parse_vectors.zig")
        with open(path) as f:
            if body(f.read()) != body("".join(parts)):
                sys.exit("parse_vectors.zig is stale: glibc, Python or the case tables moved -- regenerate and re-judge the divergences")
        print("parse_vectors.zig is fresh")
        return
    generate(sys.stdout.write)


if __name__ == "__main__":
    main()
