#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mutation probe for `http`: weaken or delete one shipped guard at a time in a
FRESH copy of ../src and see whether the module's own suite notices.

  RED    = at least one test failed  -> the guard is pinned by the suite
  GREEN  = the suite still passes    -> the guard is NOT pinned (a finding)
  NOLAND = the edit did not apply    -> reported as a failure, never silently as
           GREEN. A runner that fails open prints GREEN for a mutation that
           never happened, which reads as "the suite has a hole" when the truth
           is "nothing was tested".

WHY THIS EXISTS. Most of what makes this module safe to expose directly is a
CONSTANT or a single refusal: the redirect cap, the response-head cap, the
multipart part/header caps, `crossOrigin`, the Proxy-* strip, the strong
If-Match comparison, the q>1 rejection, the CR/LF refusal in SSE fields. Every
one of them is invisible to a functional test that fetches a URL and gets the
right bytes back — the test passes just as well with the limit at 2^40. So the
question this answers is not "does it work" but "would anyone notice if it
stopped".

⚠ AN ANCHOR THAT MATCHES MORE THAN ONCE IS REFUSED, not applied to the first
hit. A half-applied mutation is neither the original nor the intended edit, and
its verdict describes neither.

⚠ IT COPIES FROM ../src AT RUN TIME. The audit kept an `orig/` snapshot beside
this runner; by 2026-09-16 that snapshot was 661 lines behind `Client.zig`, 1221
behind `h2_server.zig` and 331 behind `Server.zig`, so it mutated code that no
longer existed and reported verdicts about a module nobody ships. The tracked
tree is never touched: everything happens under `.zig-cache/`, droppable by
contract.

⚠ TWO ANCHORS WERE RE-DERIVED on 2026-09-16 (M10, M10b). They named a
two-clause credential strip; the shipped guard has THREE clauses since
`b9943521` added `proxy-authorization`, so the old text no longer occurred at
all. The fix is to re-read the function and name the current site — never to
loosen the match until something sticks.

WHAT IT NEEDS. A `zig` on PATH. `netaddr`, `datefmt`, `testkit`, `workerpool`
and `lockfree` are taken from THIS repository, not from any copy.

    python3 mutate.py              # all of them
    python3 mutate.py M4 M13       # only these

WHAT IT PRODUCES. A verdict line per mutation, a tally, and the list of guards
the suite does not pin. Exit 1 if a POSITIVE CONTROL misbehaved — `PC-ok` must
stay GREEN and `PC-bad` must go RED; if either is wrong the runner is broken and
no other row means anything.
"""
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE.parent / "src"
REPO = HERE.parent.parent.parent
WORK = REPO / ".zig-cache" / "http-mutate"
MOD = WORK / "modsrc"

M = REPO / "modules"
TIMEOUT_S = 1800


def restore():
    """A FRESH copy of the live sources for every mutation."""
    if MOD.exists():
        for f in sorted(MOD.rglob("*"), reverse=True):
            f.unlink() if f.is_file() else f.rmdir()
        MOD.rmdir()
    MOD.parent.mkdir(parents=True, exist_ok=True)
    # ⚠ `src/` can hold a nested `.zig-cache/` (a stray build tree left by a
    # hand-run `zig` inside the module). Copying it would duplicate a build
    # tree on EVERY mutation and put a second cache under the one this runner
    # already writes.
    shutil.copytree(SRC, MOD, ignore=shutil.ignore_patterns(".zig-cache", "__pycache__"))


def run_suite():
    cmd = [
        "zig", "test", "-OReleaseSafe",
        "--dep", "netaddr", "--dep", "datefmt", "--dep", "testkit", "--dep", "workerpool",
        "-Mroot=" + str(MOD / "root.zig"),
        "-Mnetaddr=" + str(M / "netaddr" / "src" / "root.zig"),
        "-Mdatefmt=" + str(M / "datefmt" / "src" / "root.zig"),
        "--dep", "lockfree",
        "-Mworkerpool=" + str(M / "workerpool" / "src" / "root.zig"),
        "-Mlockfree=" + str(M / "lockfree" / "src" / "root.zig"),
        "-Mtestkit=" + str(M / "testkit" / "src" / "root.zig"),
        "--cache-dir", str(WORK / "zc"),
    ]
    capped = REPO / "scripts" / "capped"
    if capped.exists():
        cmd = [str(capped)] + cmd
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S)
    return r.returncode, (r.stdout + r.stderr)


# (id, file, old, new, what it disarms, verdict the 2026-09-04 audit recorded)
MUTATIONS = [
    ("M1", "sse.zig",
     '    if (ev.event) |name| {\n'
     '        if (std.mem.indexOfAny(u8, name, "\\r\\n") != null) return error.InvalidField;\n'
     '    }\n'
     '    if (ev.id) |id| {\n'
     '        if (std.mem.indexOfAny(u8, id, "\\r\\n\\x00") != null) return error.InvalidField;\n'
     '    }\n',
     "",
     "SSE event/id fields stop rejecting CR/LF (and NUL)", None),

    ("M2", "range.zig",
     "    if (last < first) return error.InvalidRange;\n", "",
     "a byte range whose end precedes its start is accepted", None),

    ("M3", "range.zig",
     "pub const default_max_ranges: usize = 16;",
     "pub const default_max_ranges: usize = 100000;",
     "the shipped cap on ranges per request", None),

    ("M4", "Client.zig",
     "    return !(a.scheme == b.scheme and a.port == b.port and std.ascii.eqlIgnoreCase(a.host, b.host));",
     "    return !std.ascii.eqlIgnoreCase(a.host, b.host);",
     "crossOrigin degraded to host-only (the CVE-2018-18074 shape)", None),

    ("M5", "Client.zig",
     "    max_redirects: u8 = 10,", "    max_redirects: u8 = 255,",
     "the shipped redirect cap", None),

    ("M6", "conneg.zig",
     "    if (milli > q_max) return null;\n", "",
     "a q-value above 1.000 is accepted", None),

    ("M7", "multipart.zig",
     "    max_parts: usize = 1000,", "    max_parts: usize = 100000000,",
     "the shipped cap on multipart parts", "GREEN"),

    ("M7b", "multipart.zig",
     "    max_header_bytes: usize = 16 * 1024,", "    max_header_bytes: usize = 1 << 40,",
     "the shipped cap on a multipart part's header block", None),

    ("M9", "bufpool.zig",
     "        if (slab.len != p.slab_size) {\n            p.gpa.free(slab);\n            return;\n        }\n",
     "",
     "a foreign-sized slab is taken into the pool instead of freed", None),

    # ⚠ RE-DERIVED 2026-09-16. The audit's anchor named two clauses; the shipped
    # guard has three since `proxy-authorization` was added, so the old text
    # matched nothing at all and the row read NOLAND.
    ("M10", "Client.zig",
     '        if (strip_sensitive and (std.ascii.eqlIgnoreCase(hd.name, "authorization") or\n'
     '            std.ascii.eqlIgnoreCase(hd.name, "cookie") or\n'
     '            std.ascii.eqlIgnoreCase(hd.name, "proxy-authorization"))) continue;',
     '        if (strip_sensitive and false and (std.ascii.eqlIgnoreCase(hd.name, "authorization") or\n'
     '            std.ascii.eqlIgnoreCase(hd.name, "cookie") or\n'
     '            std.ascii.eqlIgnoreCase(hd.name, "proxy-authorization"))) continue;',
     "credentials are no longer stripped on a cross-origin redirect hop",
     "RED"),
    # `strip_sensitive` is KEPT in the expression on purpose: deleting the line
    # outright makes the parameter unused, and a mutation that fails to COMPILE
    # is not a red test -- it is no test. The audit hit exactly that (M10 rc=1,
    # "unused function parameter") and had to add this second form.

    ("M11", "gzip.zig",
     "    const value = accept_encoding orelse return false;",
     "    const value = accept_encoding orelse return true;",
     "an ABSENT Accept-Encoding starts compressing", "RED"),

    ("M12", "Client.zig",
     "    max_head_bytes: usize = 16 * 1024,", "    max_head_bytes: usize = 1 << 24,",
     "the shipped response-head cap, 16 KiB -> 16 MiB", "RED"),
    # Deliberately NOT 1 GiB: a per-connection 1 GiB head buffer makes the
    # loopback tests thrash, which is a hazard, not a result.

    ("M13", "conditional.zig",
     "        if (!listMatches(list, v.etag, false)) return .precondition_failed;",
     "        if (!listMatches(list, v.etag, true)) return .precondition_failed;",
     "If-Match evaluated weakly (RFC 9110 requires strong)", "RED"),

    ("M14", "proxy.zig",
     '    if (std.ascii.startsWithIgnoreCase(name, "proxy-")) return true;\n', "",
     "Proxy-* request/response headers stop being stripped", "RED"),
]

# A control is not decoration: it is the row that says whether any other row is
# evidence. PC-ok proves a mutated tree still builds and passes (so a RED
# elsewhere is the guard, not the harness); PC-bad proves the suite can fail at
# all (so a GREEN elsewhere is a gap, not a suite that never ran).
CONTROLS = [
    ("PC-ok", "range.zig",
     "pub const default_max_ranges: usize = 16;",
     "// PC-ok: a semantically neutral edit -- the suite must stay GREEN\npub const default_max_ranges: usize = 16;",
     "a comment (no behaviour change at all)", "GREEN"),

    ("PC-bad", "Client.zig",
     '    try w.writeAll(" HTTP/1.1\\r\\nHost: ");',
     '    try w.writeAll(" HTTP/1.0\\r\\nHost: ");',
     "the request line claims HTTP/1.0 (golden byte tests must catch it)", "RED"),
]


def apply(fname, old, new):
    p = MOD / fname
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        return False, ("absent" if n == 0 else f"{n} sites")
    p.write_text(s.replace(old, new))
    return True, None


def one(mid, fname, old, new, what, expect):
    restore()
    ok, why = apply(fname, old, new)
    if not ok:
        print(f"  {mid:<8} {fname:<18} NOLAND  ({why}) -- a MISSING ROW, not a verdict")
        return "NOLAND"
    # diff-verify: the copy must now differ from the source in this very file
    if (MOD / fname).read_text() == (SRC / fname).read_text():
        print(f"  {mid:<8} {fname:<18} NOLAND  (file unchanged) -- a MISSING ROW")
        return "NOLAND"
    rc, out = run_suite()
    if rc != 0 and re.search(r"error: .*(unused|never used|not found|expected)", out):
        # A mutant that does not COMPILE is not a caught mutant.
        print(f"  {mid:<8} {fname:<18} NOBUILD (the mutant does not compile) -- not a verdict")
        return "NOBUILD"
    verdict = "GREEN" if rc == 0 else "RED"
    m = re.search(r"(\d+) passed; (\d+) skipped; (\d+) failed", out)
    tail = f"  [{m.group(0)}]" if m else ""
    flag = ""
    if expect and verdict != expect:
        flag = f"   <== 2026-09-04 recorded {expect}"
    print(f"  {mid:<8} {fname:<18} {verdict:<7}{tail}{flag}")
    print(f"           disarms: {what}")
    return verdict


def main(argv):
    want = set(argv[1:])
    rows = CONTROLS + MUTATIONS
    if want:
        rows = [r for r in rows if r[0] in want]
        if not rows:
            print("no mutation matched; ids are: " + ", ".join(r[0] for r in CONTROLS + MUTATIONS))
            return 2

    print("POSITIVE CONTROLS and MUTATIONS over a fresh copy of ../src\n")
    tally = {}
    control_bad = 0
    for mid, fname, old, new, what, expect in rows:
        v = one(mid, fname, old, new, what, expect)
        tally[v] = tally.get(v, 0) + 1
        if mid.startswith("PC-") and v != expect:
            control_bad += 1

    print("\n" + ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    if control_bad:
        print(f"\n⛔ {control_bad} positive control(s) misbehaved — the runner is broken and")
        print("   every row above is meaningless. Fix the runner before reading them.")
        return 1
    if tally.get("NOLAND") or tally.get("NOBUILD"):
        print("\n⚠ Rows that did not land are MISSING, not passing. Re-derive them against")
        print("  the current sources rather than loosening the match.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
