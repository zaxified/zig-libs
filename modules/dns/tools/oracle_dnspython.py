#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Differential: this module's decoder against dnspython over the same packets.

    modules/dns/tools/oracle_dnspython.py corpus.hex zig_out.txt

Compares the SECURITY-RELEVANT projection: accept/reject, plus -- for accepted
messages -- every owner name, type, class and every name carried in RDATA, in
the byte form `dns` produces (labels joined by '.', no trailing root dot, no
escaping), so the two renderings are directly comparable.

The full recipe, from the repository root:

    modules/dns/tools/gen_corpus.py 25000 1 > .zig-cache/dns-oracle/corpus.hex
    scripts/lib/capped zig build-exe --cache-dir .zig-cache \\
      -femit-bin=.zig-cache/dns-oracle/probe_dump \\
      --dep msg -Mroot=modules/dns/tools/probe_dump.zig \\
      --dep testkit -Mmsg=modules/dns/src/message.zig \\
      -Mtestkit=modules/testkit/src/root.zig
    .zig-cache/dns-oracle/probe_dump .zig-cache/dns-oracle/corpus.hex \\
      .zig-cache/dns-oracle/zig.txt
    modules/dns/tools/oracle_dnspython.py .zig-cache/dns-oracle/corpus.hex \\
      .zig-cache/dns-oracle/zig.txt

Needs dnspython -- a foreign toolchain `zig build test-dns` must never require,
which is why this lives in tools/ (CONVENTIONS.md §9).

Against the pinned corpus (see PINNED below) it compares every count with the
baseline and fails if any of them MOVED. Against any other corpus it reports
and exits 0, because a raw disagreement count is not a verdict -- see below.

⚠ A DISAGREEMENT IS NOT AUTOMATICALLY A DEFECT. The two implementations are
allowed to differ where this module documents a deliberate difference -- most
of all on names: `dns` decodes to dotted ASCII with no `\\DDD` escaping, so
three different wire names can render as one identical string (audit F7, closed
as a documented contract; `Record.labels` carries the true wire boundaries and
`dnssec/canonical.zig` enforces consistency against them). dnspython escapes
instead, and preserves structure. So NAME-SET differences are reported for
reading, and only accept/reject divergence is treated as a finding.
"""
import collections
import hashlib
import re
import sys

# ⚠ THE BASELINE, AND WHY THERE IS ONE AT ALL.
#
# The first version of this script failed whenever `zig accepts, dnspython
# rejects` was non-zero. That was wrong, and wrong in a way worth naming: on a
# hostile random corpus it is ALWAYS non-zero, so the instrument could only
# fail -- the mirror of the "cannot fail" defect, and the same shape found in
# `tc`'s reach probe hours earlier.
#
# The two implementations disagree BY DESIGN and the disagreement is not a
# defect. `dns` decodes the wire for the record types it knows and keeps the
# rest as RAW; dnspython parses every type semantically and refuses messages
# whose RDATA it cannot make sense of. Measured on the corpus below: of the
# 2538 packets in that direction, 1620 are dnspython `FormError` and 833
# `BadEDNS` -- its own strictness about RDATA and EDNS. The remaining 85
# (`BadLabelType`, `BadPointer`) were sampled, not exhausted: the three
# inspected were all a name inside the RDATA of a type this module stores as
# RAW, i.e. the same scope difference.
#
# So the useful question is not "do they ever differ" but "did the difference
# MOVE". These counts are pinned against a fingerprinted corpus; a change in
# any of them is a real signal and the run fails. If dnspython itself moves,
# re-pin deliberately and say so in the commit -- do not widen the check.
PINNED_CORPUS_SHA256 = "071650ba24c9eb39f41de11239bfaf8cf4b5269c8609db6ac2e03c2cf21a6dc5"
PINNED_RECIPE = "gen_corpus.py 25000 1, dnspython 2.8.0, 2026-09-16"
PINNED = {
    "packets": 31177,
    "both accept": 6187,
    "zig accepts, dnspython rejects": 2538,
    "zig rejects, dnspython accepts": 130,
    "both reject": 22322,
}

try:
    import dns.message
    import dns.name
    import dns.rdatatype
except ImportError:
    print("⛔ dnspython is not installed -- this oracle cannot run.\n"
          "   pip install dnspython", file=sys.stderr)
    sys.exit(2)


def zname(n):
    labs = [l for l in n.labels if l != b""]
    return b".".join(labs)


def py_proj(raw):
    try:
        m = dns.message.from_wire(raw, ignore_trailing=True, one_rr_per_rrset=True)
    except Exception as e:
        return ("ERR", type(e).__name__)
    items = []
    for q in m.question:
        items.append(("Q", zname(q.name), q.rdtype, q.rdclass))
    for sec in (m.answer, m.authority, m.additional):
        for rs in sec:
            for rd in rs:
                names = []
                for attr in ("target", "exchange", "mname", "rname", "address"):
                    v = getattr(rd, attr, None)
                    if isinstance(v, dns.name.Name):
                        names.append(zname(v))
                items.append(("R", zname(rs.name), int(rs.rdtype), int(rs.rdclass), tuple(names)))
    return ("OK", tuple(items))


def main():
    if len(sys.argv) < 3:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    hexes = [l.strip() for l in open(sys.argv[1]) if l.strip()]
    zig = [l.rstrip("\n") for l in open(sys.argv[2], encoding="latin1")]

    # ⚠ The two files must line up packet for packet. A short `zig.txt` -- a
    # probe that crashed halfway, a corpus regenerated with a different seed --
    # would otherwise silently compare packet N against packet M and report the
    # mismatches as findings about the module.
    if len(hexes) != len(zig):
        print(f"⛔ corpus has {len(hexes)} packets but the zig output has {len(zig)} "
              f"lines. They must correspond one-to-one; regenerate both.", file=sys.stderr)
        return 2
    if not hexes:
        print("⛔ the corpus is empty -- nothing was compared", file=sys.stderr)
        return 2

    both_ok = zig_ok_py_err = zig_err_py_ok = both_err = 0
    namediff = []
    py_err_kinds = collections.Counter()
    zig_err_kinds = collections.Counter()
    for h, z in zip(hexes, zig):
        raw = bytes.fromhex(h)
        p = py_proj(raw)
        zok = z.startswith("OK")
        if not zok:
            zig_err_kinds[z.split()[1] if len(z.split()) > 1 else "?"] += 1
        if p[0] == "ERR":
            py_err_kinds[p[1]] += 1
        if zok and p[0] == "OK":
            both_ok += 1
            pn = sorted(set(x[1] for x in p[1]) |
                        set(n for x in p[1] if x[0] == "R" for n in x[4]))
            zn = sorted(set(bytes.fromhex(x) for x in re.findall(r"[QR]<([0-9a-f]*)>", z)) |
                        set(bytes.fromhex(x) for x in
                            re.findall(r"=(?:CNAME|NS|PTR)<([0-9a-f]*)>", z)) |
                        set(bytes.fromhex(x) for x in re.findall(r"=MX\d+<([0-9a-f]*)>", z)) |
                        set(bytes.fromhex(y) for x in
                            re.findall(r"=SOA<([0-9a-f]*)><([0-9a-f]*)>", z) for y in x) |
                        set(bytes.fromhex(x) for x in
                            re.findall(r"=SRV\d+,\d+,\d+<([0-9a-f]*)>", z)))
            if pn and zn and pn != zn and len(namediff) < 25:
                namediff.append((h, pn, zn))
        elif zok and p[0] == "ERR":
            zig_ok_py_err += 1
        elif (not zok) and p[0] == "OK":
            zig_err_py_ok += 1
        else:
            both_err += 1

    n = len(hexes)
    print(f"packets={n}")
    print(f"  both accept                      {both_ok}")
    print(f"  zig accepts, dnspython rejects   {zig_ok_py_err}")
    print(f"  zig rejects, dnspython accepts   {zig_err_py_ok}")
    print(f"  both reject                      {both_err}")
    print(f"  zig error kinds:       {dict(zig_err_kinds)}")
    print(f"  dnspython error kinds: {dict(py_err_kinds.most_common(8))}")
    print(f"  name-set differences on commonly-accepted packets: {len(namediff)} "
          f"(reported, not judged -- see the header)")
    for h, pn, zn in namediff[:6]:
        print(f"    pkt={h[:80]}...\n      dnspython={pn}\n      zig      ={zn}")

    # ⚠ And it EXITS on the result. Until 2026-09-16 the audit's version printed
    # its counts and returned 0 whatever they were -- the "cannot fail" shape
    # that three other parked instruments in this collection also had.
    if both_ok == 0:
        print("\n⛔ NOT ONE packet was accepted by both. The corpus, the probe or "
              "the oracle is broken -- this is not a finding about the module.",
              file=sys.stderr)
        return 2

    digest = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
    if digest != PINNED_CORPUS_SHA256:
        print(f"\n(corpus is not the pinned one -- counts reported, not judged."
              f"\n to compare against the baseline use: {PINNED_RECIPE})")
        return 0

    got = {
        "packets": n,
        "both accept": both_ok,
        "zig accepts, dnspython rejects": zig_ok_py_err,
        "zig rejects, dnspython accepts": zig_err_py_ok,
        "both reject": both_err,
    }
    moved = [(k, PINNED[k], got[k]) for k in PINNED if PINNED[k] != got[k]]
    if moved:
        print(f"\n⛔ the pinned corpus gave different counts than when it was pinned "
              f"({PINNED_RECIPE}):", file=sys.stderr)
        for k, want, have in moved:
            print(f"     {k}: pinned {want}, got {have}", file=sys.stderr)
        print("   Either this module's decoder changed, or dnspython did. Find out "
              "which before re-pinning.", file=sys.stderr)
        return 1
    print(f"\n✅ every count matches the baseline pinned at {PINNED_RECIPE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
