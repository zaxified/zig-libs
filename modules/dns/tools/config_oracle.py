#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/testdata/config_oracle.zig`: what the system's glibc does
with resolv.conf and hosts files, as a black box. Replayed by
`src/config_oracle_test.zig`.

    python3 modules/dns/tools/config_oracle.py | zig fmt --stdin > modules/dns/src/testdata/config_oracle.zig

Runs itself again under `unshare -rmn` (a user, mount and network namespace:
nothing on the host is touched). Inside, for each fixture it bind-mounts the
text over /etc/resolv.conf or /etc/hosts and an nsswitch.conf naming only
`dns` or only `files`, and asks glibc through Python's `socket` module (which
is glibc's getaddrinfo / gethostbyaddr) in a FRESH process, so no state is
carried between fixtures. A fake DNS server on 127.0.0.1-4 and ::1, port 53,
records every query glibc sends:

  - the search-list candidates: the names glibc queries, in order, for a
    lookup that never succeeds (every answer NXDOMAIN);
  - the nameservers and attempts: the servers glibc tries, in order, for a
    rooted name when every server answers SERVFAIL;
  - hosts: the addresses getaddrinfo returns per family, and the name
    gethostbyaddr returns.

Nothing of glibc is read or copied; the expectations are its observed
behaviour.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

SERVERS = [("127.0.0.1", socket.AF_INET), ("127.0.0.2", socket.AF_INET), ("127.0.0.3", socket.AF_INET),
           ("127.0.0.4", socket.AF_INET), ("::1", socket.AF_INET6)]

# (name, resolv.conf text, names to look up)
RESOLV = [
    ("basic", "nameserver 127.0.0.1\nsearch a.example b.example\n", ["www", "www.x", "www.x.", "a.b.c"]),
    ("ndots3", "nameserver 127.0.0.1\nsearch a.example\noptions ndots:3\n", ["a.b", "a.b.c", "a.b.c.d"]),
    ("ndots0", "nameserver 127.0.0.1\nsearch a.example\noptions ndots:0\n", ["www"]),
    ("domain_after_search", "nameserver 127.0.0.1\nsearch s1.example s2.example\ndomain d.example\n", ["h"]),
    ("search_after_domain", "nameserver 127.0.0.1\ndomain d.example\nsearch s1.example\n", ["h"]),
    ("eight_domains", "nameserver 127.0.0.1\nsearch d1.example d2.example d3.example d4.example d5.example "
                      "d6.example d7.example d8.example\n", ["h"]),
    ("inline_comment", "nameserver 127.0.0.1 # the local one\nsearch a.example # not a domain\n", ["h"]),
    ("trailing_dot_domain", "nameserver 127.0.0.1\nsearch a.example. b.example\n", ["h"]),
    ("ndots_junk", "nameserver 127.0.0.1\nsearch a.example\noptions ndots:junk\n", ["h", "h.x"]),
    ("ndots_capped", "nameserver 127.0.0.1\nsearch a.example\noptions ndots:20\n",
     ["a.b.c.d.e.f.g.h.i.j.k.l.m.n.o", "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p"]),
    ("tabs_and_semicolon", "nameserver\t127.0.0.1\n; a comment line\nsearch\ta.example\tb.example\n", ["h"]),
    ("search_dot", "nameserver 127.0.0.1\nsearch .\n", ["h"]),
    ("no_search", "nameserver 127.0.0.1\n", ["h", "h.x"]),
    ("ndots_digits_then_junk", "nameserver 127.0.0.1\nsearch a.example\noptions ndots:2x\n", ["h.x", "h.x.y"]),
    ("indented_hash", "nameserver 127.0.0.1\n  # search not.this\nsearch a.example\n", ["h"]),
    ("semicolon_in_search", "nameserver 127.0.0.1\nsearch a.example ;b.example\n", ["h"]),
    ("semicolon_line", "nameserver 127.0.0.1\n;search not.this\nsearch a.example\n", ["h"]),
]
# (name, resolv.conf text): servers and attempts, observed with SERVFAIL everywhere.
SERVERS_FIXTURES = [
    ("three_servers", "nameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\n"),
    ("four_servers", "nameserver 127.0.0.1\nnameserver 127.0.0.2\nnameserver 127.0.0.3\nnameserver 127.0.0.4\n"),
    ("attempts3", "nameserver 127.0.0.2\nnameserver 127.0.0.1\noptions attempts:3 timeout:1\n"),
    ("attempts_capped", "nameserver 127.0.0.1\noptions attempts:9\n"),
    ("bad_server_skipped", "nameserver not-an-ip\nnameserver 127.0.0.3\nnameserver 999.1.1.1\nnameserver 127.0.0.1\n"),
    ("ipv6_server", "nameserver ::1\nnameserver 127.0.0.1\n"),
    ("attempts_junk", "nameserver 127.0.0.1\noptions attempts:junk\n"),
    ("attempts_zero", "nameserver 127.0.0.1\noptions attempts:0\n"),
    ("attempts_digits_then_junk", "nameserver 127.0.0.1\noptions attempts:3x\n"),
    ("no_nameserver", "search a.example\n"),
    ("semicolon_hash_after_server", "nameserver 127.0.0.2;x\nnameserver 127.0.0.1#y\nnameserver 127.0.0.3 # z\n"),
]
HOSTS = ("127.0.0.1 localhost\n"
         "192.0.2.1 a.example a # first\n"
         "192.0.2.2\ta.example\n"
         "2001:db8::1 a.example\n"
         "192.0.2.3 B.Example\n"
         "# 192.0.2.9 commented.example\n"
         "192.0.2.4 c.example\tc-alias   c-other\n")
HOSTS_NAMES = ["a.example", "a", "A.EXAMPLE", "b.example", "c-other", "commented.example", "localhost", "#", "first"]
HOSTS_ADDRS = ["192.0.2.1", "192.0.2.2", "192.0.2.4", "2001:db8::1", "192.0.2.9", "::ffff:192.0.2.3"]


# ── the fake DNS server ─────────────────────────────────────────────────────

class Dns:
    def __init__(self):
        self.log, self.rcode, self.socks = [], 3, []
        for addr, fam in SERVERS:
            s = socket.socket(fam, socket.SOCK_DGRAM)
            s.bind((addr, 53))
            self.socks.append((addr, s))
            threading.Thread(target=self.serve, args=(addr, s), daemon=True).start()

    def serve(self, addr, s):
        while True:
            q, peer = s.recvfrom(4096)
            off, labels = 12, []
            while q[off]:
                labels.append(q[off + 1:off + 1 + q[off]].decode())
                off += 1 + q[off]
            qtype = struct.unpack(">H", q[off + 1:off + 3])[0]
            self.log.append((addr, ".".join(labels), qtype))
            flags = 0x8180 | self.rcode
            s.sendto(q[:2] + struct.pack(">HHHHH", flags, 1, 0, 0, 0) + q[12:off + 5], peer)


def bind(path, text):
    f = tempfile.NamedTemporaryFile("w", delete=False, dir="/tmp")
    f.write(text)
    f.close()
    subprocess.run(["mount", "--bind", f.name, path], check=True)
    return f.name


def unbind(path, tmp):
    subprocess.run(["umount", path], check=True)
    os.unlink(tmp)


def fresh(code):
    """Run `code` in a new Python (fresh glibc state); its stdout as JSON."""
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=120)
    return json.loads(r.stdout)


LOOKUP = """
import json, socket, sys
for n in json.loads(sys.argv[1] if len(sys.argv) > 1 else '[]'):
    pass
"""


def lookups(names, family):
    code = (
        "import json, socket\n"
        f"out = {{}}\nfor n in {names!r}:\n"
        "    try:\n"
        f"        out[n] = [a[4][0] for a in socket.getaddrinfo(n, None, {int(family)}, socket.SOCK_STREAM)]\n"
        "    except socket.gaierror as e:\n"
        "        out[n] = None\n"
        "print(json.dumps(out))\n"
    )
    return fresh(code)


def reverse(addrs):
    code = (
        "import json, socket\nout = {}\n"
        f"for a in {addrs!r}:\n"
        "    try:\n"
        "        out[a] = socket.gethostbyaddr(a)[0]\n"
        "    except (socket.herror, socket.gaierror):\n"
        "        out[a] = None\n"
        "print(json.dumps(out))\n"
    )
    return fresh(code)


def inner():
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "127.0.0.2/8", "dev", "lo"], capture_output=True)
    time.sleep(0.5)  # IPv6 ::1 on lo
    dns = Dns()
    ns = bind("/etc/nsswitch.conf", "hosts: dns\n")
    empty_hosts = bind("/etc/hosts", "")
    out = {"resolv": [], "servers": [], "hosts": {}}

    for name, text, names in RESOLV:
        rc = bind("/etc/resolv.conf", text)
        res = {}
        for n in names:
            dns.log.clear()
            dns.rcode = 3  # NXDOMAIN
            lookups([n], socket.AF_INET)
            res[n] = [q for _, q, t in dns.log if t == 1]
        out["resolv"].append({"name": name, "text": text, "queries": res})
        unbind("/etc/resolv.conf", rc)

    for name, text in SERVERS_FIXTURES:
        rc = bind("/etc/resolv.conf", text)
        dns.log.clear()
        dns.rcode = 2  # SERVFAIL: glibc moves to the next server, then the next attempt
        lookups(["probe.example."], socket.AF_INET)
        out["servers"].append({"name": name, "text": text, "tried": [a for a, _, t in dns.log if t == 1]})
        unbind("/etc/resolv.conf", rc)

    unbind("/etc/nsswitch.conf", ns)
    unbind("/etc/hosts", empty_hosts)
    ns = bind("/etc/nsswitch.conf", "hosts: files\n")
    hs = bind("/etc/hosts", HOSTS)
    out["hosts"] = {
        "text": HOSTS,
        "v4": lookups(HOSTS_NAMES, socket.AF_INET),
        "v6": lookups(HOSTS_NAMES, socket.AF_INET6),
        "reverse": reverse(HOSTS_ADDRS),
    }
    unbind("/etc/hosts", hs)
    unbind("/etc/nsswitch.conf", ns)
    print(json.dumps(out))


def zstr(s):
    return json.dumps(s)  # a JSON string literal is a valid Zig string literal for this ASCII text


def main():
    r = subprocess.run(["unshare", "-rmn", sys.executable, "-I", os.path.abspath(__file__), "--inner"],
                       capture_output=True, text=True, timeout=600)
    if r.returncode:
        sys.exit(r.stderr)
    data = json.loads(r.stdout)
    glibc = subprocess.run(["ldd", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    o = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by modules/dns/tools/config_oracle.py: what the system glibc did with these",
        f"// resolv.conf and hosts files ({glibc}). Replayed by src/config_oracle_test.zig.",
        "// Do not edit by hand.",
        "",
        "pub const Lookup = struct { name: []const u8, queries: []const []const u8 };",
        "pub const Resolv = struct { name: []const u8, text: []const u8, lookups: []const Lookup };",
        "pub const Servers = struct { name: []const u8, text: []const u8, tried: []const []const u8 };",
        "pub const Answer = struct { name: []const u8, addrs: ?[]const []const u8 };",
        "pub const Reverse = struct { addr: []const u8, name: ?[]const u8 };",
        "",
        "pub const resolv = [_]Resolv{",
    ]
    for r_ in data["resolv"]:
        lk = ", ".join(f".{{ .name = {zstr(n)}, .queries = &.{{{', '.join(zstr(q) for q in qs)}}} }}" for n, qs in r_["queries"].items())
        o.append(f"    .{{ .name = {zstr(r_['name'])}, .text = {zstr(r_['text'])}, .lookups = &.{{{lk}}} }},")
    o.append("};")
    o.append("")
    o.append("pub const servers = [_]Servers{")
    for s in data["servers"]:
        o.append(f"    .{{ .name = {zstr(s['name'])}, .text = {zstr(s['text'])}, .tried = &.{{{', '.join(zstr(a) for a in s['tried'])}}} }},")
    o.append("};")
    h = data["hosts"]
    o.append("")
    o.append(f"pub const hosts_text = {zstr(h['text'])};")
    for fam in ("v4", "v6"):
        rows = []
        for n, addrs in h[fam].items():
            a = "null" if addrs is None else "&.{" + ", ".join(zstr(x) for x in addrs) + "}"
            rows.append(f".{{ .name = {zstr(n)}, .addrs = {a} }}")
        o.append(f"pub const hosts_{fam} = [_]Answer{{{', '.join(rows)}}};")
    rev = ", ".join(f".{{ .addr = {zstr(a)}, .name = {'null' if n is None else zstr(n)} }}" for a, n in h["reverse"].items())
    o.append(f"pub const hosts_reverse = [_]Reverse{{{rev}}};")
    sys.stdout.write("\n".join(o) + "\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["--inner"]:
        inner()
    else:
        main()
