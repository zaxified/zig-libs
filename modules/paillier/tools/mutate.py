#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/paillier/tools/mutate.py              # the whole table
    modules/paillier/tools/mutate.py m5 m13       # only those rows
    modules/paillier/tools/mutate.py --controls   # only the two positive controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

This is the instrument that produced audit F7, and F7 is the reason it is worth
keeping: **10 of 15 mutations survived a fully green suite**, the sharpest being
a constant `r` for every encryption -- while SPEC says "Paillier's IND-CPA
security lives entirely in the fresh uniform `r`". Several of those have since
been pinned by new tests; the rest are accepted, documented risk. A table of
verdicts is therefore a regression record, not a to-do list.

⚠ Every row copies the LIVE `modules/paillier/src/root.zig` into a per-process
scratch tree and mutates the copy. Never a snapshot of its own
(CONVENTIONS.md §9).

⚠ THE COMMAND LINE ROTS SEPARATELY FROM THE ANCHORS, and only running catches
it. The shell runner this replaces passed `--dep montint` alone. Measured
2026-09-16 against the live module: that fails, because `root.zig` now imports
`testkit` at file scope for its fuzz corpus. With `--dep montint --dep testkit`
the same command is exit 0, 40 passed / 1 skipped. `whois` shipped a migrated
runner with exactly this defect and every row read RED, the control included.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/paillier/src/root.zig"
WORK = ROOT / ".zig-cache/paillier-mutate"
MUT = WORK / f"mut-{os.getpid()}"

# (tag, old, new, description, expect)
#
# `expect` is None for rows whose verdict has not been pinned yet -- measure
# first, pin second. The audit's own verdicts are NOT copied forward: several
# fix passes have closed findings since, and a fix is exactly what turns a row
# from GREEN to RED.
MUTATIONS = [
    # ── ciphertext validation ───────────────────────────────────────────────
    ('m1', '    if (c.c.isZero()) return error.InvalidCiphertext;',
     '    if (false and c.c.isZero()) return error.InvalidCiphertext;',
     'drop the zero-ciphertext check', 'GREEN'),
    ('m2', '    if (x.isZero()) return error.InvalidCiphertext; // gcd(c, n) != 1',
     '    if (false and x.isZero()) return error.InvalidCiphertext; // gcd(c, n) != 1',
     'drop the non-unit check (gcd(c, n) != 1)', 'GREEN'),
    ('m3', '    if (!brem.eqlZero()) return error.InvalidCiphertext;',
     '    if (false and !brem.eqlZero()) return error.InvalidCiphertext;',
     'drop L-exactness in decrypt', 'RED'),
    ('m16', '    if (c.c.isZero()) return error.InvalidCiphertext;',
     '    if (false) return error.InvalidCiphertext;',
     'drop BOTH zero guards at once', 'GREEN'),

    # ── randomness: where IND-CPA actually lives ────────────────────────────
    ('m4', '        if (r.isZero()) continue;\n        return r;',
     '        return r;',
     'allow r = 0', 'GREEN'),
    # ⚠ m5's anchor is NOT the audit's. That one named
    # `random.bytes(...)` + the mask + `// Constructed against n_sq`, and two
    # things happened to it: the F1 fix rewrote `sampleNonzeroLtN` (the old
    # draw folded ~28.9% of values onto `r - n` instead of redrawing), and the
    # bare `random.bytes` + mask pair now matches TWICE in the file. So the old
    # text matches zero times -- the row read "not applied" while looking like
    # a result. Re-derived against the current source, anchored on the `r`
    # construction, which is unique.
    ('m5', '        const r = Fe.fromBytes(pk.n_sq, buf[0..n_len], .big) catch continue;\n'
           '        if (r.isZero()) continue;',
     '        const r = Fe.fromPrimitive(u32, pk.n_sq, 3) catch unreachable; // MUTATION: r is a constant\n'
     '        if (r.isZero()) continue;',
     'r is the SAME constant for every encryption (IND-CPA gone)', 'RED'),

    # ── key generation ──────────────────────────────────────────────────────
    ('m6', '        if (isProbablePrime(m, random)) return;',
     '        if (true or isProbablePrime(m, random)) return;',
     'isProbablePrime always true', 'RED'),
    ('m7', 'const mr_rounds = 64;', 'const mr_rounds = 1;',
     'Miller-Rabin 64 rounds -> 1 (the 2^-128 guarantee)', 'RED'),
    ('m8', '            if (!topBitsMatch(p_bytes, q_bytes)) break;',
     '            if (true or !topBitsMatch(p_bytes, q_bytes)) break;',
     'bypass the FIPS 186-5 closeness guard AT THE CALL SITE', 'GREEN'),
    ('m9', '    if (bp.order(bq) == .eq) return error.InvalidPrimes; // p == q',
     '    if (false and bp.order(bq) == .eq) return error.InvalidPrimes; // p == q',
     'allow p == q', 'GREEN'),
    ('m10', '    if (bp.toConst().orderAgainstScalar(3) == .lt) return error.InvalidPrimes;\n'
            '    if (bq.toConst().orderAgainstScalar(3) == .lt) return error.InvalidPrimes;',
     '    if (false) return error.InvalidPrimes;',
     'allow p, q < 3', 'GREEN'),
    ('m11', '    if (!rem.eqlZero()) return error.InvalidPrimes;',
     '    if (false and !rem.eqlZero()) return error.InvalidPrimes;',
     'drop L-exactness in fromPrimes (rejects composite factors)', 'GREEN'),
    ('m12', '    const mu = Fe.fromBytes(n, &mu_buf, .big) catch return error.InvalidPrimes; // canonical mod n',
     '    const mu = n.add(Fe.fromBytes(n, &mu_buf, .big) catch return error.InvalidPrimes, n.one()); // canonical mod n',
     'perturb mu by one', 'RED'),

    # ── secret hygiene ──────────────────────────────────────────────────────
    #
    # ⚠ m13 was ONE row until 2026-09-16 and its anchor matched TWICE, so
    # `str.replace` disarmed both sites at once and the verdict was about
    # neither on its own. The second site is new: the F2 fix (secret copies
    # surviving on the dead stack) added a `var sk = sk_in; defer secureZero`
    # inside `decrypt` itself. Two guards, two rows, each anchored by context.
    ('m13', '    pub fn deinit(sk: *SecretKey) void {\n'
            '        std.crypto.secureZero(u8, std.mem.asBytes(&sk.lambda));',
     '    pub fn deinit(sk: *SecretKey) void {\n'
     '        if (false) std.crypto.secureZero(u8, std.mem.asBytes(&sk.lambda));',
     'SecretKey.deinit no longer zeroes lambda', 'RED'),
    ('m13b', '    var sk = sk_in;\n    defer {\n'
             '        std.crypto.secureZero(u8, std.mem.asBytes(&sk.lambda));',
     '    var sk = sk_in;\n    defer {\n'
     '        if (false) std.crypto.secureZero(u8, std.mem.asBytes(&sk.lambda));',
     "decrypt's own copy is no longer zeroed (the audit F2 fix)", 'GREEN'),

    # ── parsing bounds and homomorphic arithmetic ───────────────────────────
    ('m14', '        if (n_bytes.len == 0 or n_bytes.len > modulus_bytes) return error.InvalidPublicKey;',
     '        if (n_bytes.len == 0) return error.InvalidPublicKey;',
     'drop the n_bytes upper bound', 'GREEN'),
    ('m15', '    if (k.isZero()) return .{ .c = pk.n_sq.one() };',
     '    if (k.isZero()) return .{ .c = c.c };',
     'mulPlaintext(k = 0) returns c instead of 1', 'RED'),
]

# ⚠ The rows that judge the RUNNER rather than the module. `PC-bad` is the
# audit's own `pc_break_gpow`: it breaks `g^m` itself, so every round trip
# fails -- a RUNTIME failure caught by assertions, not a compile error. A
# control that can only fail in the compiler proves the mutation landed and
# proves nothing about whether the test binary ran.
CONTROLS = [
    ('PC-ok', 'const mr_rounds = 64;',
     'const mr_rounds = 64; // PC-ok: a no-op edit, the suite must stay GREEN',
     'no-op edit -- if this is RED the runner is broken, not the module', 'GREEN'),
    ('PC-bad', '    if (pk.g.eql(g_std)) return pk.n_sq.add(pk.n_sq.mul(m, n_fe), one);',
     '    if (pk.g.eql(g_std)) return pk.n_sq.add(pk.n_sq.mul(m, n_fe), pk.n_sq.add(one, one));',
     'break g^m itself -- if this is GREEN the suite did not run', 'RED'),
]


def build_and_run():
    """Build the mutated copy and run its tests. Returns (verdict, detail)."""
    r = subprocess.run(
        [str(ROOT / "scripts/capped"), "zig", "test", "-O", "ReleaseSafe",
         "--cache-dir", str(ROOT / ".zig-cache"),
         # ⚠ testkit is NOT optional -- see the module docstring.
         "--dep", "montint", "--dep", "testkit",
         "-Mroot=" + str(MUT / "root.zig"),
         "-Mmontint=" + str(ROOT / "modules/montint/src/root.zig"),
         "-Mtestkit=" + str(ROOT / "modules/testkit/src/root.zig")],
        capture_output=True, text=True, timeout=1800)
    out = r.stdout + r.stderr
    if "no module named" in out or "unable to load" in out or "FileNotFound" in out:
        first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
        return "BROKEN", "the runner could not build at all: " + first[:100]
    if r.returncode == 0:
        return "GREEN", ""
    detail = next((l.strip() for l in out.splitlines()
                   if "passed;" in l and "failed" in l), "")
    if not detail:
        first = next((l.strip() for l in out.splitlines() if "error:" in l), "")
        return ("RED", "compile: " + first[:90]) if first else ("RED", "")
    return "RED", detail


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    table = list(CONTROLS)
    if "--controls" not in sys.argv:
        table += [m for m in MUTATIONS if not args or m[0] in args]
    known = {m[0] for m in MUTATIONS} | {c[0] for c in CONTROLS}
    unknown = [a for a in args if a not in known]
    if unknown:
        print("unknown row(s): " + ", ".join(unknown), file=sys.stderr)
        return 2

    WORK.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("ZIGLIBS_MEM_MAX", "4G")

    bad_anchor, mismatched, broken, results = [], [], [], []
    for tag, old, new, desc, expect in table:
        if MUT.exists():
            shutil.rmtree(MUT)
        MUT.mkdir(parents=True)
        shutil.copy(SRC, MUT / "root.zig")
        target = MUT / "root.zig"
        text = target.read_text()
        n = text.count(old)
        if n != 1:
            kind = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
            bad_anchor.append((tag, kind, desc))
            print(f"  {tag:<7} {kind:<14} {desc}", flush=True)
            continue
        target.write_text(text.replace(old, new))

        verdict, detail = build_and_run()
        results.append((tag, verdict, expect, desc))
        mark = ""
        if verdict == "BROKEN":
            broken.append((tag, desc))
        elif expect and verdict != expect:
            mark = f"  ⛔ expected {expect}"
            mismatched.append((tag, verdict, expect, desc))
        print(f"  {tag:<7} {verdict:<6} {desc}{mark}", flush=True)
        if detail:
            print(f"          {detail}", flush=True)

    if MUT.exists():
        shutil.rmtree(MUT)

    green = [r for r in results if r[1] == "GREEN" and not r[0].startswith("PC-")]
    print(f"\n{len(results)} rows: "
          f"{sum(1 for r in results if r[1] == 'RED')} RED, "
          f"{sum(1 for r in results if r[1] == 'GREEN')} GREEN, "
          f"{len(broken)} BROKEN, {len(bad_anchor)} anchor problems")
    if green:
        print("\nGuards the suite did NOT notice:")
        for tag, _, _, desc in green:
            print(f"   {tag:<7} {desc}")

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} row(s) could not BUILD. That is a defect in this "
              f"runner's command line, not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} anchor(s) no longer name a unique site. A row "
              f"that was not applied is MISSING, not passing -- re-derive it.",
              file=sys.stderr)
        rc = 1
    if mismatched:
        print(f"\n⛔ {len(mismatched)} row(s) came back against their pinned verdict.",
              file=sys.stderr)
        rc = 1
    ctl = {r[0]: r[1] for r in results if r[0].startswith("PC-")}
    if ctl.get("PC-ok") != "GREEN" or ctl.get("PC-bad") != "RED":
        print(f"\n⛔ THE CONTROLS FAILED (PC-ok={ctl.get('PC-ok')}, "
              f"PC-bad={ctl.get('PC-bad')}). The runner is broken and every row "
              f"above is meaningless.", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
