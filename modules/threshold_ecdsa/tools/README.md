# `threshold_ecdsa` verification instruments

One instrument, run by hand. It is not wired into `zig build`: a row costs a
full ReleaseSafe build plus the module's 96 tests, which is far more than a test
lane should carry (`CONVENTIONS.md` §9).

Figures below were measured on 2026-09-16 against the tree as it stands.

## Would the suite notice if a guard were removed?

    modules/threshold_ecdsa/tools/mutate.py               # the whole table
    modules/threshold_ecdsa/tools/mutate.py m1_gamma      # only that row
    modules/threshold_ecdsa/tools/mutate.py --controls    # only the controls

Four mutations and two positive controls. Each row copies the live
`src/*.zig` into a per-process scratch tree, applies **every** edit of that row,
and rebuilds the suite from the copy. The tracked tree is never written to.

Measured: **6 rows, 5 RED, 1 GREEN, 0 BROKEN, 0 anchor problems** — the single
GREEN is the `PC-ok` control. Every real mutation is caught:

| mutant | guard it removes | audit | today |
|---|---|---|---|
| `m1_gamma` | the Γ commit-reveal layer, **entirely** (`verifyPoK` returns true *and* `commitGamma` binds nothing) | GREEN | **RED** |
| `m5_mtawc_curve` | the equation binding MtA input `b` to the public point `B` | GREEN | **RED** |
| `m4_pimod_w` | `Pimod.verify`'s Jacobi witness check `(w/Ñ) = −1` | GREEN | **RED** |
| `m3_piprm` | `Piprm.verify`'s step-1 degeneracy precondition on `h1`/`h2` | GREEN | **RED** |

### This is what the fix campaign looks like from the outside

Those four rows are the reason the instrument is worth keeping, and the reason
its verdicts are **measured, not inherited**. When the 2026-09-04 audit ran
them, all four were GREEN:

- `m1_gamma` disarmed the whole commit-reveal layer and **all 66 tests passed**,
  while the module's own doc comment says that layer is "what stops a rushing
  adversary from choosing its `Γ_i` AFTER seeing everyone else's".
- The three F4 guards each deleted individually, each with a green suite. The
  tests that *looked* like coverage passed **by the wrong route**: a tampered
  value changed the Fiat-Shamir challenge and fell over on an earlier equation,
  so the named check never ran at all.

They are RED today because F3 and F4 were fixed and pinned. Copying the audit's
verdicts into `expect` would have pinned every one of them upside down.

### The controls, and why `PC-bad` is the audit's own

`PC-ok` appends a comment to a line known to be unique — byte-different,
behaviour-identical, and it must stay **GREEN**. `PC-bad` deletes the
`s1 <= q³` range check in `verifyAliceRange` and must come back **RED**;
measured at `95 passed; 0 skipped; 1 failed`, the failure being the test named
*"GG18 A.1 reject (SECURITY-CRITICAL)"*.

That it fails at **runtime** matters. A control that can only fail in the
compiler proves the mutation landed and proves nothing about whether the test
binary ran and its assertions were evaluated — so it cannot tell "the suite
caught it" from "the suite never executed", which is the one thing a control
exists to distinguish.

⚠ A row that applies only some of its edits is not a weaker verdict, it is a
**different mutation** than its description names. `m1_gamma` has two edits;
the runner refuses the row unless both anchors match exactly once.

⚠ The paths come from the script's own location. The audit's version hardcoded
an absolute `/home/<user>/workspace/zig-libs` in **six** scripts — unportable,
and a personal path in a public repository.

## What was deliberately not brought over

The audit left 14 files in `.zig-cache/audit-threshold-ecdsa/` (64 MB). One
became the runner above; the rest were dropped, each for a stated reason:

- `ctgrind_probe.zig`, `ctrun.sh`, `_ct_gen.zig`, `build.sh`, `build2.sh` — the
  module now has `src/ctgrind_harness.zig` and **three pinned rows** in
  `scripts/ctgrind-expected.tsv` (`share`, `nonce`, `betaprime`), inside a gate.
  A scratch probe outside the gate is strictly worse than that.
- `probe_h2_order2.zig` — audit F1 (an order-2 generator accepted by
  `AuxParams.validate`) is fixed and pinned by
  *"AuxParams.validate rejects an order-2 generator (audit F1 HIGH, 2026-09-10
  fix)"*, alongside two tests that document the remaining soundness gaps
  explicitly.
- `probe_keyshare_panic.zig` — audit F2/F8: the twelve public `fromBytes*`
  entry points now carry fuzz harnesses in `zkproofs.zig` and `root.zig`.
- `probe_perf.zig`, `common.zig`, `mkperf.sh`, `_perf_gen.zig` — a benchmark.
  Its numbers are not lost: `A1/threshold_ecdsa.md` records the per-`t` totals
  (1736/1711/1662 ms at `t=2`, 5195/5178/5092 at `t=3`, 10410/10311 at `t=4`),
  a second calmer session, the per-primitive breakdown summing to 422.2 ms
  against a measured 425.8, and the allocation peaks. F6 and F7 remain open as
  work in the code, not as a need for this instrument.
- `probe0.zig` — five lines that print one constant.
- `mutate.py` + `mutest.sh` — replaced by the runner above, which adds the
  controls, the exit code, and the refusal to report a half-applied row.
