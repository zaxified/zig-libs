#!/usr/bin/env python3
"""Compute a module card's `**Audit:**` mutation entry from verdict tables.

    score.py whole --table T.tsv [--table T2.tsv ...] --date YYYY-MM-DD
                   (--src HASH | --src-from-report FILE --module M) [--total N]
                   [--card modules/<m>/SPEC.md --write]
    score.py delta --card modules/<m>/SPEC.md --table T.tsv ... --date ...
                   (--src HASH | --src-from-report FILE) [--write]
    score.py --self-test

Rules (owner, 2026-11-22; scripts/mutation/README.md section 4a):
  1. Cumulative: a DELTA run adds its counts to the card's existing ones.
     The delta's own numbers belong in a dated SPEC paragraph (printed here).
  2. No baseline, no card: a card entry without counts (`src ?`, `none`) is not
     written by a delta run; the script prints the numbers and refuses.
  3. A whole-module run always yields a score, even a cut-short one:
     killed/total counts every mutant, OPEN = total - killed - eq
     (survived-not-analysed + never-run).  HANG counts as killed; UNCLEAR
     never does (OPEN, with a warning).
  4. The src hash is passed by the caller or read from the `zig build
     maturity-report` TSV (column 7, "src now").
The output is exactly what the grade gate (scripts/gates/gates.zig, the
`**Audit:**` parser) accepts: `mutation <date> (<killed>/<total>[, <n> eq])`.
Table format: a header row with a `verdict` column (and an `id` column), or
run.sh's headerless `id<TAB>VERDICT<TAB>secs<TAB>reason`.  Later tables and
later rows override earlier ones per id (a rerun, or the analysed verdicts).
"""
import argparse
import os
import re
import sys
import tempfile

KILLED, EQ, OPEN = "killed", "eq", "open"


def classify(raw):
    """Map a verdict cell to killed / eq / open; None for the baseline PASS."""
    m = re.match(r"[A-Za-z]+", raw.strip())  # `KILLED-DEBUG`, `EQUIVALENT (cost-only)`: the first word
    w = m.group(0).upper() if m else ""
    if w in ("KILLED", "KILL", "HANG"):
        return KILLED
    if w.startswith("EQ") or w.startswith("UNOBS"):
        return EQ
    if w == "PASS":
        return None
    return OPEN  # SURVIVED, UNCLEAR, OPEN, FINDING, anything unknown


def read_tables(paths):
    """-> ({id: (class, raw verdict)}, [warnings])"""
    verdicts, warns = {}, []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            rows = [l.rstrip("\n").split("\t") for l in f if l.strip() and not l.startswith("#")]
        parse_rows(rows, p, verdicts, warns)
    return verdicts, warns


def parse_rows(rows, name, verdicts, warns):
    idc, vc = 0, 1
    if rows and any(c.strip().lower() == "verdict" for c in rows[0]):
        head = [c.strip().lower() for c in rows[0]]
        vc = head.index("verdict")
        idc = head.index("id") if "id" in head else 0
        rows = rows[1:]
    for r in rows:
        if len(r) <= max(idc, vc) or not r[idc].strip().isdigit():
            warns.append("%s: skipped row %r" % (name, "\t".join(r)[:60]))
            continue
        i = int(r[idc])
        if i == 0:
            continue  # the baseline
        c = classify(r[vc])
        if c is None:
            warns.append("%s: PASS verdict on mutant %d counted as OPEN" % (name, i))
            c = OPEN
        verdicts[i] = (c, r[vc].strip())


def tally(verdicts, total=None):
    """-> (killed, total, eq, open, warnings)"""
    warns = []
    killed = sum(1 for c, _ in verdicts.values() if c == KILLED)
    eq = sum(1 for c, _ in verdicts.values() if c == EQ)
    seen = len(verdicts)
    if total is None:
        total = seen
        if seen and max(verdicts) != seen:
            warns.append("ids are not 1..%d contiguous (max id %d): never-run mutants are NOT counted; pass --total N" % (seen, max(verdicts)))
    elif total < seen:
        raise SystemExit("score.py: --total %d is less than the %d mutants in the tables" % (total, seen))
    unclear = sorted(i for i, (_, raw) in verdicts.items() if raw.upper().startswith("UNCLEAR"))
    if unclear:
        warns.append("UNCLEAR is never a kill (counted OPEN): ids %s" % ",".join(map(str, unclear)))
    suffixed = sorted(i for i, (c, raw) in verdicts.items()
                      if c == KILLED and not re.fullmatch(r"(?i)killed|kill|hang", raw))
    if suffixed:
        warns.append("verdict with a suffix counted as killed by its first word: ids %s" % ",".join(map(str, suffixed)))
    unknown = sorted(i for i, (c, raw) in verdicts.items()
                     if c == OPEN and not re.match(r"(SURVIVED|UNCLEAR|OPEN)", raw.upper()))
    if unknown:
        warns.append("unrecognised verdict (counted OPEN): ids %s" % ",".join(map(str, unknown)))
    return killed, total, eq, total - killed - eq, warns


def fmt_entry(date, killed, total, eq):
    score = "(%d/%d%s)" % (killed, total, ", %d eq" % eq if eq else "")
    return "mutation %s %s" % (date, score)


AUDIT_RE = re.compile(r"^\*\*Audit:\*\* (review [^·]*?) · (mutation [^·]*?) · (src \S+)[ \t]*$", re.M)
SCORE_RE = re.compile(r"^mutation (\S+) \((\d+)/(\d+)(?:, (\d+) eq)?\)$")


def read_card(text):
    m = AUDIT_RE.search(text)
    if not m:
        raise SystemExit("score.py: no well-formed `**Audit:** review .. · mutation .. · src ..` line in the card")
    s = SCORE_RE.match(m.group(2))
    old = (int(s.group(2)), int(s.group(3)), int(s.group(4) or 0)) if s else None
    return m, old


def src_from_report(path, module):
    """The `zig build maturity-report` TSV: column 2 module, column 7 `src now`."""
    with open(path, encoding="utf-8") as f:
        for l in f:
            c = l.rstrip("\n").split("\t")
            if len(c) >= 8 and c[1] == module and re.fullmatch(r"[0-9a-f]{16}", c[6]):
                return c[6]
    raise SystemExit("score.py: no row for module %r with a 16-hex src in %s" % (module, path))


def write_card(path, text, m, entry, src):
    new = "**Audit:** %s · %s · src %s" % (m.group(1), entry, src)
    out = text[:m.start()] + new + text[m.end():]
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(out)
    os.replace(tmp, path)


def run_whole(tables, date, src, total=None):
    v, w = read_tables(tables)
    k, t, e, o, w2 = tally(v, total)
    return fmt_entry(date, k, t, e), (k, t, e, o), w + w2


def run_delta(card_text, tables, date, src):
    """-> (entry or None, delta tuple, warnings, message)"""
    m, old = read_card(card_text)
    v, w = read_tables(tables)
    k, t, e, o, w2 = tally(v)
    return m, old, (k, t, e, o), w + w2


def cli(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", choices=["whole", "delta"])
    ap.add_argument("--table", action="append", default=[])
    ap.add_argument("--card")
    ap.add_argument("--date")
    ap.add_argument("--src")
    ap.add_argument("--src-from-report")
    ap.add_argument("--module")
    ap.add_argument("--total", type=int)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.mode or not a.table or not a.date:
        ap.error("mode, --table and --date are required")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", a.date):
        ap.error("--date must be YYYY-MM-DD")
    if a.mode == "delta" and not a.card:
        ap.error("delta needs --card")
    if a.write and not a.card:
        ap.error("--write needs --card")
    src = a.src
    if not src and a.src_from_report:
        mod = a.module or (os.path.basename(os.path.dirname(os.path.abspath(a.card))) if a.card else None)
        if not mod:
            ap.error("--src-from-report needs --module or --card")
        src = src_from_report(a.src_from_report, mod)
    if not src or not re.fullmatch(r"[0-9a-f]{16}", src):
        ap.error("need --src <16 hex> or --src-from-report")
    text = open(a.card, encoding="utf-8").read() if a.card else None

    if a.mode == "whole":
        entry, (k, t, e, o), warns = run_whole(a.table, a.date, src, a.total)
        for w in warns:
            print("warning: " + w, file=sys.stderr)
        print("%s · src %s" % (entry, src))
        print("killed %d, eq %d, open %d, total %d" % (k, e, o, t), file=sys.stderr)
        if a.write:
            m, _ = read_card(text)
            write_card(a.card, text, m, entry, src)
            print("wrote %s" % a.card, file=sys.stderr)
        return 0

    m, old, (k, t, e, o), warns = run_delta(text, a.table, a.date, src)
    for w in warns:
        print("warning: " + w, file=sys.stderr)
    print("delta paragraph numbers: %d/%d%s, %d open" % (k, t, ", %d eq" % e if e else "", o))
    if old is None:
        print("REFUSED: the card's mutation entry has no counts (`%s`): a delta's counts would read as a "
              "whole-module score. Card NOT written; whole-module run needed." % m.group(2), file=sys.stderr)
        return 1
    nk, nt, ne = old[0] + k, old[1] + t, old[2] + e
    entry = fmt_entry(a.date, nk, nt, ne)
    print("cumulative: %d/%d, %d eq + %d/%d, %d eq = %d/%d, %d eq" % (old[0], old[1], old[2], k, t, e, nk, nt, ne))
    print("%s · src %s" % (entry, src))
    if a.write:
        write_card(a.card, text, m, entry, src)
        print("wrote %s" % a.card, file=sys.stderr)
    return 0


def quiet_cli(argv):
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return cli(argv)


def self_test():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append("%s: got %r want %r" % (name, got, want))

    def tab(rows, header=None):
        v, w = {}, []
        parse_rows(([header] if header else []) + [r.split("\t") for r in rows], "t", v, w)
        return v

    # verdict spelling
    for s, c in [("KILLED", KILLED), ("HANG", KILLED), ("killed", KILLED), ("EQUIVALENT", EQ),
                 ("EQ", EQ), ("UNOBSERVABLE", EQ), ("EQUIVALENT (cost-only)", EQ),
                 ("SURVIVED", OPEN), ("UNCLEAR", OPEN), ("OPEN", OPEN), ("weird", OPEN), ("PASS", None)]:
        check("classify " + s, classify(s), c)

    # netaddr-shaped table (header with a verdict column): 783 K + 38 EQ + 3 UNOBSERVABLE
    rows = ["%d\tf.zig\t1\texpr\t1\tKILLED\tx" % i for i in range(1, 784)]
    rows += ["%d\tf.zig\t1\texpr\t1\tEQUIVALENT\tx" % i for i in range(784, 822)]
    rows += ["%d\tf.zig\t1\texpr\t1\tUNOBSERVABLE\tx" % i for i in range(822, 825)]
    v = tab(rows, "id file line kind run verdict note".split())
    check("netaddr whole", tally(v)[:4], (783, 824, 41, 0))
    check("netaddr whole entry", fmt_entry("2026-11-11", 783, 824, 41), "mutation 2026-11-11 (783/824, 41 eq)")

    # rule 1: cumulative delta 783/824 (41 eq) + 13/14 (1 eq) -> 796/838, 42 eq
    card = ("**Audit:** review 2026-11-12 · mutation 2026-11-11 (783/824, 41 eq) · src 0123456789abcdef\n")
    m, old = read_card(card)
    check("card parse", old, (783, 824, 41))
    d = tab(["%d\tKILLED" % i for i in range(1, 14)] + ["14\tEQUIVALENT"])
    dk, dt, de, do, _ = tally(d)
    check("delta numbers", (dk, dt, de, do), (13, 14, 1, 0))
    check("cumulative", fmt_entry("2026-11-15", old[0] + dk, old[1] + dt, old[2] + de),
          "mutation 2026-11-15 (796/838, 42 eq)")

    # rule 2: no counts -> refuse (exit 1, card untouched)
    with tempfile.TemporaryDirectory() as td:
        card_p = os.path.join(td, "SPEC.md")
        tsv = os.path.join(td, "t.tsv")
        with open(tsv, "w") as f:
            f.write("1\tKILLED\t1\t\n2\tSURVIVED\t1\t\n")
        for bad in ("mutation 2026-10-01 · src ?", "mutation none · src ?"):
            body = "# x\n**Audit:** review 2026-11-12 · %s\n" % bad
            open(card_p, "w").write(body)
            rc = quiet_cli(["delta", "--card", card_p, "--table", tsv, "--date", "2026-11-22",
                      "--src", "0123456789abcdef", "--write"])
            check("rule 2 rc (%s)" % bad, rc, 1)
            check("rule 2 untouched (%s)" % bad, open(card_p).read(), body)

        # --write on a delta with counts keeps the review part, `---` neighbours untouched
        open(card_p, "w").write("# x\n" + card + "next line\n")
        rc = quiet_cli(["delta", "--card", card_p, "--table", tsv, "--date", "2026-11-22",
                  "--src", "fedcba9876543210", "--write"])
        check("delta write rc", rc, 0)
        check("delta write", open(card_p).read(),
              "# x\n**Audit:** review 2026-11-12 · mutation 2026-11-22 (784/826, 41 eq) · src fedcba9876543210\nnext line\n")

        # rule 3: a cut-short whole run: 3 killed (one HANG), 1 EQ, 1 survived, 1 UNCLEAR, ids 7..10 never run
        with open(tsv, "w") as f:
            f.write("0\tPASS\t1\t\n1\tKILLED\t1\t\n2\tHANG\t20\t\n3\tKILLED\t1\t\n"
                    "4\tSURVIVED\t1\t\n5\tUNCLEAR\t1\t\n6\tEQUIVALENT\t0\t\n")
        entry, nums, warns = run_whole([tsv], "2026-11-22", "x", total=10)
        check("rule 3 entry", entry, "mutation 2026-11-22 (3/10, 1 eq)")
        check("KILLED-DEBUG", classify("KILLED-DEBUG"), KILLED)
        check("rule 3 open", nums, (3, 10, 1, 6))
        check("UNCLEAR warned", any("UNCLEAR" in w and "5" in w for w in warns), True)
        # without --total the gap is warned about
        _, nums2, warns2 = run_whole([tsv], "2026-11-22", "x")
        check("no total", nums2, (3, 6, 1, 2))
        check("no-total no-warn (contiguous 1..6)", [w for w in warns2 if "contiguous" in w], [])
        # a later table overrides: the analysed EQ replaces SURVIVED
        t2 = os.path.join(td, "t2.tsv")
        with open(t2, "w") as f:
            f.write("id\tverdict\tnote\n4\tEQUIVALENT\tcost-only\n")
        entry, nums, _ = run_whole([tsv, t2], "2026-11-22", "x")
        check("override", nums, (3, 6, 2, 1))
        check("eq 0 spelling", fmt_entry("2026-11-22", 40, 40, 0), "mutation 2026-11-22 (40/40)")

        # whole --write on a card without counts
        open(card_p, "w").write("**Audit:** review none · mutation 2026-10-01 · src ?\n")
        rc = quiet_cli(["whole", "--card", card_p, "--table", tsv, "--date", "2026-11-22", "--total", "10",
                  "--src", "0123456789abcdef", "--write"])
        check("whole write rc", rc, 0)
        check("whole write", open(card_p).read(),
              "**Audit:** review none · mutation 2026-11-22 (3/10, 1 eq) · src 0123456789abcdef\n")

        # src from the maturity-report TSV
        rep = os.path.join(td, "rep.tsv")
        with open(rep, "w") as f:
            f.write("P3\tfoo\tprof\t-\tscope\taudit\t" + "ab" * 8 + "\tfresh\t-\t-\t-\n")
        check("src from report", src_from_report(rep, "foo"), "ab" * 8)

        # gate grammar: every entry we emit must match the gate's accepted shape
        for e in (fmt_entry("2026-11-22", 3, 10, 1), fmt_entry("2026-11-22", 4, 4, 0)):
            check("gate shape " + e, bool(re.fullmatch(r"mutation \d{4}-\d\d-\d\d \(\d+/\d+(, \d+ eq)?\)", e)), True)

    for f in fails:
        print("FAIL " + f, file=sys.stderr)
    print("score.py self-test: %s" % ("FAILED (%d)" % len(fails) if fails else "ok"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:]))
