#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RFC 6724 oracle for netaddr: glibc's getaddrinfo (destination ordering) and
the Linux kernel (IPv6 source selection), both black boxes, neither modelled by
this module's code (which follows Go's addrselect.go).

Writes `src/rfc6724_vectors.zig`, replayed by `src/rfc6724_oracle_test.zig`
with no namespace, no glibc and no socket:

    python3 modules/netaddr/tools/rfc6724_oracle.py > modules/netaddr/src/rfc6724_vectors.zig
    python3 modules/netaddr/tools/rfc6724_oracle.py --check   # re-take, compare with the committed file

Needs `unshare` (user + net + mount namespaces), `ip` and `mount`; no root, no
network. The script re-executes itself inside `unshare -rnm`, where it owns a
dummy interface, the routing tables, /etc/hosts and /etc/gai.conf.

Destination ordering (`sortDestinationsWithSources`). A "world" gives every
destination of a fixed pool a source: a host route `dst/128 dev d0 src S`
(or `unreachable dst`) pins what connect() -- and so glibc -- will pick. The
source glibc saw is then read back the same way glibc gets it (UDP connect +
getsockname), never assumed. /etc/gai.conf holds exactly the RFC 6724 §2.1
policy table, so glibc's own (RFC 3484-era) default table plays no part. For
every ordered pair of destinations a hosts name lists the two in that order;
glibc's answer order says whether the pair was swapped. Longer lists check the
sort itself.

Source selection (`selectSource`, IPv6 only -- the kernel's IPv4 choice is not
RFC 6724). A subset of candidate addresses is put on the dummy interface (the
only one with addresses: ::1 is removed from lo, so the kernel's rule 5,
"prefer outgoing interface", never decides), each /64 so that the kernel's
prefix-length cap on rule 8 equals the 64-bit cap of RFC 6724 §2.2, and every
destination is asked. A tie is detected by adding the same subset in reverse
order: if the kernel's choice moves, both are acceptable.
"""
import ipaddress
import os
import platform
import random
import socket
import subprocess
import sys
import tempfile

# RFC 6724 §2.1, verbatim.
GAI_CONF = """\
precedence ::1/128 50
precedence ::/0 40
precedence ::ffff:0:0/96 35
precedence 2002::/16 30
precedence 2001::/32 5
precedence fc00::/7 3
precedence ::/96 1
precedence fec0::/10 1
precedence 3ffe::/16 1
label ::1/128 0
label ::/0 1
label ::ffff:0:0/96 4
label 2002::/16 2
label 2001::/32 5
label fc00::/7 13
label ::/96 3
label fec0::/10 11
label 3ffe::/16 12
"""

# Sources living on d0. IPv6 ones are /64 (rule 8 cap, see the docstring).
SRC6 = [
    "2001:db8:9::1",        # global, same /64 as the 2001:db8:9:: destinations
    "2001:db8:1::1",        # global, shares 2001:db8::/32 only
    "2001:0:5ef5:79fd::2",  # Teredo
    "2002:c000:204::2",     # 6to4
    "fd12:3456::2",         # ULA
    "fec0::2",              # deprecated site-local
    "3ffe::2",              # 6bone
    "fe80::2",              # link-local
]
SRC4 = ["10.0.0.1", "192.0.2.1", "169.254.0.1", "100.64.0.1"]

# Destinations: (text, kind). kind picks the source pool; "natural" gets no
# route of ours (loopback and friends resolve however the kernel resolves them).
DSTS = [
    ("2001:db8:9::a", "v6"),
    ("2001:db8:9:0:8000::b", "v6"),
    ("2001:db8:7::c", "v6"),
    ("2001:0:5ef5:79fd::9", "v6"),
    ("2002:c000:204::9", "v6"),
    ("fd12:3456::9", "v6"),
    ("fd99::9", "v6"),
    ("fec0::9", "v6"),
    ("3ffe::9", "v6"),
    ("::c000:209", "v6"),          # IPv4-compatible (deprecated), label 3
    ("fe80::9", "natural"),         # no zone, as DNS gives it: connect() refuses -> unusable
    ("ff0e::9", "v6"),
    ("ff05::9", "v6"),
    ("ff08::9", "v6"),
    ("ff02::9", "natural"),         # likewise
    ("::1", "natural"),
    ("192.0.2.9", "v4"),
    ("10.1.2.3", "v4"),
    ("100.64.0.9", "v4"),
    ("169.254.0.9", "v4"),
    ("127.0.0.2", "natural"),
    ("::ffff:192.0.2.77", "m4"),
    ("::ffff:10.9.9.9", "m4"),
    ("::ffff:169.254.7.7", "m4"),
    ("::ffff:127.0.0.3", "natural"),
]

# Kernel phase.
CAND6 = SRC6 + ["2001:db8:9::2", "fd99::2", "2001:db8:9:1::1"]
KDSTS = [d for d, k in DSTS if k == "v6"] + ["fe80::9%d0", "ff02::9%d0", "::1", "2001:db8:9::1", "fd12:3456::2", "ff0e::1", "ff01::9%d0", "ff04::9", "fe80::2%d0"]

WORLDS = 10
LISTS_PER_WORLD = 24
SRC_SETS = 160
SEED = 6724


def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)


def ip_batch(lines):
    r = subprocess.run(["ip", "-batch", "-"], input="\n".join(lines) + "\n", text=True, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"ip -batch failed: {r.stderr.strip()}")


def zlist(items):
    """A Zig `&.{...}` literal laid out the way `zig fmt` lays it out."""
    items = list(items)
    if not items:
        return "&.{}"
    if len(items) == 1:
        return "&.{" + items[0] + "}"
    return "&.{ " + ", ".join(items) + " }"


def split_zone(text):
    if "%" in text:
        a, z = text.split("%", 1)
        return a, socket.if_nametoindex(z)
    return text, 0


def probe(text):
    """The source connect() picks for `text`, or None -- what glibc does."""
    addr, scope = split_zone(text)
    v6 = ":" in addr
    s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 9, 0, scope) if v6 else (addr, 9))
        return s.getsockname()[0].split("%")[0]
    except OSError:
        return None
    finally:
        s.close()


def route_for(dst, kind, src):
    addr = dst.split("%")[0]
    if kind == "m4":
        addr = str(ipaddress.IPv6Address(addr).ipv4_mapped)
        kind = "v4"
    plen = 128 if kind == "v6" else 32
    if src is None:
        return f"route replace unreachable {addr}/{plen}"
    return f"route replace {addr}/{plen} dev d0 src {src}"


def sockaddr_key(sa, fam):
    if fam == socket.AF_INET6:
        return sa[0].split("%")[0]
    return sa[0]


def norm(text):
    return str(ipaddress.ip_address(text.split("%")[0]))


def inside(out):
    rnd = random.Random(SEED)
    tmp = tempfile.mkdtemp(prefix="rfc6724-")
    hosts = os.path.join(tmp, "hosts")
    gai = os.path.join(tmp, "gai.conf")
    with open(hosts, "w") as f:
        f.write("")
    with open(gai, "w") as f:
        f.write(GAI_CONF)
    sh(f"mount --bind {hosts} /etc/hosts")
    sh(f"mount --bind {gai} /etc/gai.conf")
    ip_batch([
        "link set lo up",
        "link add d0 type dummy",
        "link set d0 addrgenmode none",
        "link set d0 up",
    ] + [f"addr add {a}/64 dev d0 nodad" for a in SRC6] + [f"addr add {a}/32 dev d0" for a in SRC4])

    glibc = platform.libc_ver()
    w = out.write
    w("// SPDX-License-Identifier: MIT\n")
    w(f"// GENERATED by modules/netaddr/tools/rfc6724_oracle.py ({glibc[0]} {glibc[1]}, Linux {platform.release()}) -- do not hand-edit.\n")
    w("//! glibc getaddrinfo destination order and Linux kernel IPv6 source choice, replayed\n")
    w("//! by `rfc6724_oracle_test.zig`. Regenerate with the command in the script's docstring.\n\n")
    w(f"pub const glibc_version = \"{glibc[1]}\";\n")
    w(f"pub const kernel_release = \"{platform.release()}\";\n\n")
    w("/// A destination with the source connect() gave it (null: unusable).\n")
    w("pub const Entry = struct { dst: []const u8, src: ?[]const u8 };\n")
    w("/// `in` and `out` are indices into the world's entries: glibc got `in`, answered `out`.\n")
    w("pub const List = struct { in: []const u8, out: []const u8 };\n")
    w("/// `pairs[k]` for the k-th ordered pair (i, j), i != j, row-major: '0' when glibc\n")
    w("/// answered i then j, '1' when it answered j then i.\n")
    w("pub const World = struct { entries: []const Entry, pairs: []const u8, lists: []const List };\n")
    w("/// `ok`: indices into the set's candidates the kernel may pick (several on a tie).\n")
    w("pub const Answer = struct { dst: []const u8, ok: []const u8 };\n")
    w("pub const SrcSet = struct { cands: []const []const u8, answers: []const Answer };\n\n")

    # ── destination ordering ──
    w("pub const worlds = [_]World{\n")
    for wi in range(WORLDS):
        routes = []
        for d, kind in DSTS:
            if kind == "natural":
                continue
            pool = SRC6 if kind == "v6" else SRC4
            src = None if rnd.random() < 0.15 else rnd.choice(pool)
            routes.append(route_for(d, kind, src))
        ip_batch(routes)
        entries = []
        for d, _ in DSTS:
            entries.append((d, probe(d)))
        n = len(entries)
        names = []
        lines = []
        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                name = f"p{i}x{j}"
                names.append((name, [i, j]))
                lines.append(f"{entries[i][0]} {name}\n{entries[j][0]} {name}\n")
        lists = []
        for li in range(LISTS_PER_WORLD):
            k = rnd.randint(3, 9)
            idx = rnd.sample(range(n), k)
            name = f"l{li}"
            lists.append((name, idx))
            lines.append("".join(f"{entries[i][0]} {name}\n" for i in idx))
        with open(hosts, "w") as f:
            f.write("".join(lines))

        by_addr = {norm(d): i for i, (d, _) in enumerate(entries)}

        def ask(name, idx):
            res = socket.getaddrinfo(name, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
            got = [by_addr[norm(sockaddr_key(r[4], r[0]))] for r in res]
            if sorted(got) != sorted(idx):
                raise SystemExit(f"world {wi} {name}: glibc answered {got} for {idx}")
            return got

        pairs = []
        for name, idx in names:
            got = ask(name, idx)
            pairs.append("0" if got == idx else "1")
        w("    .{\n        .entries = &.{\n")
        for d, s in entries:
            src = "null" if s is None else f"\"{s}\""
            w(f"            .{{ .dst = \"{d.split('%')[0]}\", .src = {src} }},\n")
        w("        },\n")
        w(f"        .pairs = \"{''.join(pairs)}\",\n")
        w("        .lists = &.{\n")
        for name, idx in lists:
            got = ask(name, idx)
            w(f"            .{{ .in = {zlist(map(str, idx))}, .out = {zlist(map(str, got))} }},\n")
        w("        },\n    },\n")
    w("};\n\n")

    # ── IPv6 source selection ──
    sh("ip -6 addr flush dev d0")
    ip_batch(["addr del ::1/128 dev lo", "route add ::/0 dev d0"])
    w("pub const src_sets = [_]SrcSet{\n")
    for _ in range(SRC_SETS):
        k = rnd.randint(2, 6)
        cands = rnd.sample(CAND6, k)

        def ask_all(order):
            sh("ip -6 addr flush dev d0")
            ip_batch([f"addr add {a}/64 dev d0 nodad" for a in order])
            return {d: probe(d) for d in KDSTS}

        fwd = ask_all(cands)
        rev = ask_all(list(reversed(cands)))
        w(f"    .{{ .cands = {zlist(f'\"{c}\"' for c in cands)}, .answers = &.{{\n")
        for d in KDSTS:
            ok = sorted({cands.index(x) for x in (fwd[d], rev[d]) if x is not None and x in cands})
            if fwd[d] is not None and fwd[d] not in cands:
                raise SystemExit(f"kernel chose {fwd[d]} for {d}, not a candidate of {cands}")
            if not ok:
                continue  # no route, no source: nothing to compare
            w(f"        .{{ .dst = \"{d.split('%')[0]}\", .ok = {zlist(map(str, ok))} }},\n")
        w("    } },\n")
    w("};\n")


def main():
    if "--inside" in sys.argv:
        inside(sys.stdout)
        return
    cmd = ["unshare", "-rnm", "--propagation", "private", sys.executable, os.path.abspath(__file__), "--inside"]
    if "--check" not in sys.argv:
        sys.exit(subprocess.run(cmd).returncode)
    fresh = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    committed_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "rfc6724_vectors.zig")
    with open(committed_path) as f:
        committed = f.read()
    if fresh != committed:
        sys.exit("rfc6724_vectors.zig is stale: glibc, the kernel or the case tables moved -- regenerate and re-judge the divergences")
    print("rfc6724_vectors.zig is fresh")


if __name__ == "__main__":
    main()
