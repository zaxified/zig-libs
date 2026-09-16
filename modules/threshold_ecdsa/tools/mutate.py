#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fault injection: would this module's suite notice if a guard were removed?

    modules/threshold_ecdsa/tools/mutate.py               # the whole table
    modules/threshold_ecdsa/tools/mutate.py m1_gamma      # only that row
    modules/threshold_ecdsa/tools/mutate.py --controls    # only the controls

RED   = the suite noticed (the guard is pinned by a test)
GREEN = the suite passed with the guard gone (the guard is INVISIBLE to it)

This is the instrument behind audit findings F3 and F4, and those are the
reason it earns a place in the tree. F3: the Gamma commit-reveal layer could be
disarmed ENTIRELY -- `verifyPoK` returning true and `commitGamma` returning a
constant -- and all 66 tests passed, while the module's own doc comment says
that layer is "what stops a rushing adversary from choosing its GAMMA_i AFTER
seeing everyone else's". F4: three more security guards deleted individually,
each with a green suite, one of them the equation that is the whole reason
MtAwc exists. The tests that looked like coverage passed BY THE WRONG ROUTE --
a tampered value changed the Fiat-Shamir challenge and fell over on an earlier
equation, so the named check never ran.

⚠ Every row copies the LIVE `modules/threshold_ecdsa/src/*.zig` into a
per-process scratch tree and mutates the copy. Never a snapshot of its own,
never the tracked tree (CONVENTIONS.md §9).

⚠ The paths are derived from this file's location. The audit's version hard-
coded an absolute `/home/<user>/workspace/zig-libs` in six scripts, which is
both unportable and a personal path in a public repository.
"""
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
SRC = ROOT / "modules/threshold_ecdsa/src"
WORK = ROOT / ".zig-cache/te-mutate"
MUT = WORK / f"mut-{os.getpid()}"

# (tag, [(file, old, new), ...], description, expect)
#
# `expect` is None until measured. The audit's verdicts are deliberately NOT
# copied forward: F3 and F4 have been fixed since, and a fix is exactly what
# turns a row from GREEN to RED. Measure first, pin second.
MUTATIONS = [
    ('m1_gamma', [
        ('signing.zig',
         'fn verifyPoK(index: u32, big_gamma: Element, proof: SchnorrProof) bool {',
         'fn verifyPoK(index: u32, big_gamma: Element, proof: SchnorrProof) bool {\n'
         '    if (true) return true; // MUTATION: accept every Schnorr proof\n'),
        ('signing.zig',
         'fn commitGamma(index: u32, big_gamma: Element) [32]u8 {',
         'fn commitGamma(index: u32, big_gamma: Element) [32]u8 {\n'
         '    if (true) return [_]u8{0} ** 32; // MUTATION: commitment binds nothing\n'),
    ], 'disarm the Gamma commit-reveal layer ENTIRELY (audit F3)', 'RED'),

    ('m3_piprm', [
        ('aux_proofs.zig',
         '        if (aux.h1.isZero() or aux.h1.eql(one)) return false;\n'
         '        if (aux.h2.isZero() or aux.h2.eql(one)) return false;',
         '        _ = one; // MUTATION: Piprm.verify step-1 precondition deleted'),
    ], "delete Piprm.verify's degeneracy precondition (audit F4c)", 'RED'),

    ('m4_pimod_w', [
        ('aux_proofs.zig',
         '            if ((jacobiBig(gpa, &wb, &nb) catch return false) != -1) return false;',
         '            _ = wb; _ = nb; // MUTATION: Jacobi witness check deleted'),
    ], "delete Pimod.verify's Jacobi witness check (audit F4b)", 'RED'),

    ('m5_mtawc_curve', [
        ('zkproofs.zig',
         '        if (!lhs.equivalent(b_e.add(u1_pt))) return false;',
         '        _ = lhs; _ = b_e; _ = u1_pt; // MUTATION: MtAwc curve check deleted'),
    ], 'delete the equation that binds MtA input b to the public B (audit F4a)', 'RED'),
]

# ⚠ The rows that judge the RUNNER rather than the module.
#
# `PC-bad` is the audit's own positive control: deleting the `s1 <= q^3` range
# check in `verifyAliceRange`. It was measured RED (65 passed, 1 failed) on the
# test named "GG18 A.1 reject (SECURITY-CRITICAL)", so a green row elsewhere
# means a hole in the suite rather than a broken harness. It fails at RUNTIME,
# not in the compiler -- a control that can only fail while compiling proves
# the mutation landed and proves nothing about whether the tests ran.
#
# `PC-ok` appends a comment to that same line: byte-different, behaviour-
# identical, and anchored on text already known to be unique.
CONTROLS = [
    ('PC-ok', [
        ('zkproofs.zig',
         '    if (intCompare(proof.s1, &q3_bytes) == .gt) return false;\n    // ...and the work bound',
         '    if (intCompare(proof.s1, &q3_bytes) == .gt) return false; // PC-ok: no-op\n    // ...and the work bound'),
    ], 'no-op edit -- if this is RED the runner is broken, not the module', 'GREEN'),

    ('PC-bad', [
        ('zkproofs.zig',
         '    if (intCompare(proof.s1, &q3_bytes) == .gt) return false;\n    // ...and the work bound',
         '    // MUTATION: range check deleted\n    // ...and the work bound'),
    ], 'delete the s1 <= q^3 range check -- if GREEN the suite did not run', 'RED'),
]


def build_and_run():
    """Build the mutated copy and run its tests. Returns (verdict, detail)."""
    r = subprocess.run(
        [str(ROOT / "scripts/capped"), "zig", "test", "-O", "ReleaseSafe",
         "--cache-dir", str(ROOT / ".zig-cache"),
         "--dep", "paillier", "--dep", "montint",
         "-Mthreshold_ecdsa=" + str(MUT / "root.zig"),
         "--dep", "montint",
         "-Mpaillier=" + str(ROOT / "modules/paillier/src/root.zig"),
         "-Mmontint=" + str(ROOT / "modules/montint/src/root.zig")],
        capture_output=True, text=True, timeout=3600)
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
    for tag, edits, desc, expect in table:
        if MUT.exists():
            shutil.rmtree(MUT)
        MUT.mkdir(parents=True)
        for f in SRC.glob("*.zig"):
            shutil.copy(f, MUT / f.name)

        # ⚠ Every edit of a row must land, or the row is meaningless. A row that
        # applied two of its three edits is not a weaker verdict, it is a
        # DIFFERENT mutation than the one its description names.
        problem = None
        for fname, old, new in edits:
            target = MUT / fname
            text = target.read_text()
            n = text.count(old)
            if n != 1:
                problem = "PATCH-MISS" if n == 0 else f"AMBIGUOUS({n})"
                problem += f" [{fname}]"
                break
            target.write_text(text.replace(old, new))
        if problem:
            bad_anchor.append((tag, problem, desc))
            print(f"  {tag:<16} {problem:<22} {desc}", flush=True)
            continue

        verdict, detail = build_and_run()
        results.append((tag, verdict, expect, desc))
        mark = ""
        if verdict == "BROKEN":
            broken.append((tag, desc))
        elif expect and verdict != expect:
            mark = f"  ⛔ expected {expect}"
            mismatched.append((tag, verdict, expect, desc))
        print(f"  {tag:<16} {verdict:<6} {desc}{mark}", flush=True)
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
            print(f"   {tag:<16} {desc}")

    rc = 0
    if broken:
        print(f"\n⛔ {len(broken)} row(s) could not BUILD. That is a defect in this "
              f"runner's command line, not a verdict about the module.", file=sys.stderr)
        rc = 1
    if bad_anchor:
        print(f"\n⛔ {len(bad_anchor)} row(s) no longer name a unique site. A row that "
              f"was not applied is MISSING, not passing -- re-derive it.", file=sys.stderr)
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
