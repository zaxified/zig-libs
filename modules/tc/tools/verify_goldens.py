#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Re-capture every golden whose `tc` command line is recorded in goldens.zig
and compare it byte-for-byte with the pinned constant.

    modules/tc/tools/verify_goldens.py [name-substring]

`modules/tc/src/goldens.zig` is ~106 KB of byte-exact netlink datagrams taken
from a stock `tc` binary. Its header records the capture recipe in prose; this
is the executable half -- without it the constants can be read but not
re-derived, and a golden nobody can re-derive is a number, not evidence.

For each `test "golden: ..."` block it takes the `// tc ...` comment (joining
`\\` continuations) and the `expectGolden(g_x, ...)` constant, re-runs that
command inside an unprivileged `unshare -rn` netns under
`strace -e write=all`, and compares the bytes. `nlmsg_seq` (bytes 8..11) is
zeroed on both sides because it is per-run; everything else must match exactly.

Needs iproute2, strace and unprivileged user namespaces -- a foreign toolchain
`zig build test-tc` must never require, which is why this is in tools/
(CONVENTIONS.md §9).

⚠ The comparison is only as good as the host: these goldens were captured on
iproute2-6.19.0 with `/proc/net/psched = 000003e8 00000040 000f4240 3b9aca00`.
A different iproute2 may legitimately put different bytes on the wire, so a
MISS here means "this host disagrees", not automatically "the module is wrong"
-- check the version before believing it is a defect.
"""
import re, subprocess, sys, pathlib

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SRC = ROOT / "modules/tc/src/goldens.zig"
CAP = HERE / "capture.sh"
want_filter = sys.argv[1] if len(sys.argv) > 1 else ""

text = SRC.read_text()

# ── the pinned constants ────────────────────────────────────────────────────
goldens = {}
for m in re.finditer(r"^const (g_\w+) =\s*((?:\s*\"[0-9a-f]*\"\s*(?:\+\+)?)+);", text, re.M):
    goldens[m.group(1)] = "".join(re.findall(r'"([0-9a-f]*)"', m.group(2)))

# ── the command each test says it came from ─────────────────────────────────
cases = []  # (test name, command, golden name)
blocks = re.split(r"^test ", text, flags=re.M)[1:]
for b in blocks:
    tname = b.split('"')[1] if '"' in b else "?"
    if not tname.startswith("golden:"):
        continue
    body = b[: b.find("\n}\n") if "\n}\n" in b else len(b)]
    # leading comment block: // tc … with `\` continuations
    cmt = []
    for ln in body.splitlines():
        s = ln.strip()
        if not s.startswith("//"):
            if cmt:
                break
            continue
        piece = s[2:].strip()
        cont = piece.endswith("\\")
        cmt.append(piece[:-1].strip() if cont else piece)
        if not cont:
            break
    joined = " ".join(cmt)
    mm = re.search(r"\btc\s+(?:qdisc|class|filter|actions)\b.*", joined)
    if not mm:
        continue
    cmd = re.sub(r"\s*\(.*?\)\s*$", "", mm.group(0)).strip()
    cmd = re.sub(r"\s+", " ", cmd)
    g = re.search(r"expectGolden\((g_\w+)", body)
    if not g or g.group(1) not in goldens:
        continue
    cases.append((tname, cmd, g.group(1)))

# Three cake goldens carry a multi-line comment WITHOUT `\` continuations, so
# the extractor above truncates them; their full command line is taken from
# SPEC.md's coverage table instead. (Verified by hand: all three MATCH.)
MANUAL = {
    "g_cake_qdisc_add_full":
        "tc qdisc add dev lo root handle 8: cake bandwidth 1gbit diffserv4 dual-srchost nat wash "
        "ack-filter overhead 18 mpu 64 memlimit 4194304 split-gso fwmark 0xff",
    "g_cake_qdisc_add_mpu_rtt":
        "tc qdisc add dev lo root handle 8: cake bandwidth 50mbit overhead 10 mpu 84 rtt 100ms "
        "ingress split-gso",
    "g_cake_qdisc_add_unlimited":
        "tc qdisc add dev lo root handle 8: cake unlimited besteffort flowblind ptm no-ack-filter "
        "nowash nonat",
}

# ⚠ COVERAGE FLOOR. Every case above is DISCOVERED by parsing comments, so a
# change to how goldens.zig spells its `// tc` lines silently shrinks the run
# rather than breaking it -- and "reproduced 0 / 0 goldens" both reads like a
# success and exits 0. Measured 2026-09-16: 51 constants, 51 of them reachable
# through a recorded command line, 51 reproduced. So the discovery step owes a
# case for every constant, and losing one is a defect in THIS script.
missing = sorted(set(goldens) - {g for _, _, g in cases})
if missing and not want_filter:
    print(f"⛔ the extractor found {len(cases)} cases for {len(goldens)} constants; "
          f"{len(missing)} lost their command line:", file=sys.stderr)
    for g in missing:
        print(f"     {g}", file=sys.stderr)
    print("   Fix the extractor (or add the command to MANUAL) -- a golden that "
          "cannot be re-derived is not evidence.", file=sys.stderr)
    sys.exit(2)


def zero_seq(h):
    return h[:16] + "00000000" + h[24:]


ok = miss = 0
for tname, cmd, gname in cases:
    if want_filter and want_filter not in gname and want_filter not in tname:
        continue
    cmd = MANUAL.get(gname, cmd)
    setup = "true"
    if cmd.startswith("tc class") or cmd.startswith("tc filter"):
        setup = "tc qdisc add dev lo root handle 1: htb default 10"
    try:
        out = subprocess.run([str(CAP), cmd, setup], capture_output=True, text=True, timeout=90).stdout
    except subprocess.TimeoutExpired:
        print(f"  TMO  {gname}"); miss += 1; continue
    caps = [zero_seq(c) for c in out.split()]
    want = zero_seq(goldens[gname])
    if want in caps:
        ok += 1
        print(f"  OK   {gname:28s} {len(goldens[gname])//2:5d} B   {cmd}")
    else:
        miss += 1
        detail = ""
        for c in caps:
            if len(c) == len(want):
                d = next((k for k in range(0, len(c), 2) if c[k:k+2] != want[k:k+2]), None)
                detail = f" [same length, first diff at byte {d//2}]" if d is not None else ""
        if not caps:
            detail = " [no sendmsg captured — command failed?]"
        print(f"  MISS {gname:28s} {len(goldens[gname])//2:5d} B   {cmd}{detail}")

print(f"\nreproduced {ok} / {ok + miss} goldens whose command line is recorded")

# ⚠ And it EXITS on the result. Until 2026-09-16 this printed MISS lines, counted
# them, and returned 0 regardless -- the "cannot fail" shape that had already
# been found three times over in this collection's parked instruments. A runner
# nobody watches that always exits 0 is a green light nobody earned.
if ok + miss == 0:
    print("⛔ nothing ran -- the filter matched no case", file=sys.stderr)
    sys.exit(2)
if miss:
    print(f"⛔ {miss} golden(s) did not reproduce on this host "
          f"(iproute2: check `tc -V` against the provenance in goldens.zig)", file=sys.stderr)
    sys.exit(1)
