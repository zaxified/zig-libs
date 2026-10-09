# `<name>` — specification

<!-- SKELETON. 219 of 225 modules have a SPEC.md; the six that do not are the
     smallest glue. Delete a heading that genuinely does not apply to this
     module rather than leaving it empty — an empty heading reads as an
     unanswered question, and this file is where a reader goes to find out
     what was decided and what was refused. -->

## Maturity

**Grade:** *(written by `zig build gen-catalog` — never by hand)*

**Scope:** unsurveyed

**Audit:** review none · mutation none · src ?

**Hardening:** fuzz none · ct n/a — <why this module holds no secret>

**Performance:** not measured

**Evidence:** unclassified

**Known defects:** none recorded

**Downstream consumer:** no

<!-- The card a consumer reads first, and the one the README catalog's Grade
     column is computed from. Everything but the Grade line is yours; the Grade
     line is generated from them plus the anchor grade below (CONVENTIONS.md §8,
     "Maturity"). The grade is the WORST axis; the profile beside it (S E A H P)
     shows every axis, so a 3 says what would make it a 2.

     Scope (S) — how much of what a user expects this module covers, against the
                 reference implementation and the notable Rust/Go/C ones. Set only
                 by a survey (SURVEY-PLAYBOOK.md), never by feel:
                 `ahead — <reference, version> (surveyed YYYY-MM-DD)` parity AND a
                   measured lead, stated on an `**Ahead:**` line (below) → 1;
                 `parity — …` nothing a user would notice is missing → 2;
                 `core — …` the main use cases, gaps listed under Backlog → 3;
                 `mvp — …` the happy path, gaps a user will hit → 4;
                 `poc — …` a demonstration, finish it before anyone consumes it → 5.
                 `unsurveyed` until then — the grade then carries a `?`, and so
                 does a survey older than a year.
     Ahead     — only with scope `ahead`, refused without it. One or more claims,
                 separated by ` · `, each `<kind> — <claim> (measured YYYY-MM-DD)`:
                 `speed` — faster than the FASTEST implementation in the field (not
                   merely the reference); `**Performance:**` must show `fastest <y>×`
                   with y < 1, from a bench kept in `tools/` (CONVENTIONS.md §9);
                 `correctness` — a defect in the reference found by our oracle, with
                   the case that reproduces it;
                 `feature` — something a user notices that the reference lacks.
                 A lead older than 180 days counts as parity until re-measured.
     Audit (A) — the latest `review` (a security/adversarial audit of THIS module
                 whose findings or verdict are recorded) and the latest `mutation`
                 run over its tests: YYYY-MM-DD, `?` when it happened but the date
                 is lost, `none`. After the mutation date, its score:
                 `(<killed>/<total>, <n> eq)` — survivors not shown equivalent keep
                 the audit at 2. `src` is the hash of the Zig sources the audit
                 read (`zig build maturity-report`, column `src now`); once the code
                 changes the audit is STALE and counts 2. Carrying a hash over a
                 purely mechanical change (a Zig migration, `zig fmt`) is allowed;
                 the commit that does it says so.
                 1 = both dated, scored clean, over the current src · 2 = both, but
                 stale/unscored · 3 = one of them, or a `?` · 4 = neither.
     Hardening (H) — `fuzz`: when the deterministic fuzz driver last ran this
                 module's harnesses (`YYYY-MM-DD (<seeds>, reach <r>%)`); `ct`: when
                 ctgrind last checked its secret-dependent code. Each is a date,
                 `?` (done, not recorded), `none`, or `n/a — <why>` (refused for
                 fuzz when the module has a harness). 1 = every applicable item
                 dated · 3 = some · 4 = none · all n/a = no cap.
     Performance (P) — worst-workload time ratios, ours/theirs, lower is better:
                 `ref <x>× <impl> · fastest <y>× <impl> (measured YYYY-MM-DD)`;
                 `fastest ?` when the fastest in the field is not measured,
                 `fastest ref` when the reference IS the fastest. A range `a–b` is
                 read as b. `not measured`, or `n/a — <why>` where speed is not
                 what a user picks this module for.
                 1 = x ≤ 1 and y ≤ 1.25 · 2 = x ≤ 1.1 · 3 = x ≤ 2, or not
                 measured · 4 = x > 2. (P2's 10 % is the noise of a worst-of-N
                 ratio at parity; it holds only for a bench that alternates
                 the sides and keeps each one's best of several rounds —
                 CONVENTIONS.md §9, kind 3.)
     Evidence (E) — class C/D only (no outside truth; class A/B take E from the
                 anchor grade below — EXTERNAL with a live `tools/interop.zig`
                 oracle 1, frozen EXTERNAL 2, MIXED 3, REDERIVED 4, SELF 5):
                 `model-fuzz — <model>` an independent reference model the fuzz
                   driver compares against → 1;
                 `model — <model>` a reference model or a checked invariant → 2;
                 `kat — <what>` hand-computed values only → 3; `unclassified` → 3.
                 Delete the line for a class A/B module.
     Known defects (D) — an open defect that makes the module unsafe to rely on.
                 Any text other than `none recorded` sets the grade to 5.
     Downstream consumer — `yes` if a project outside this repo depends on it.
                 A consumed module must grade 3 or better; check-catalog-table
                 fails otherwise. -->

## Compared with

<!-- Required once Scope is surveyed (check-catalog-table enforces it): who
     "the competition" is, so the Scope verdict can be checked and re-run.
     Written by the survey (SURVEY-PLAYBOOK.md). Stars and activity go stale,
     hence the date. Delete this section while Scope is `unsurveyed`. -->

Surveyed YYYY-MM-DD per `SURVEY-PLAYBOOK.md`; stars and activity as of that date.

| Project | Language | Licence | Stars | Last release / push | What a user notices against this module |
|---|---|---|--:|---|---|
| [owner/repo](https://github.com/owner/repo) — **reference** | Rust | MIT | 12.3k | v1.2.3 (2026-08) | … |

**Where we are ahead:** … · **Where we are behind:** … (→ Backlog items)

## What this module is, and what it is not

One paragraph. Then the scope line that matters most: **what a reader might
reasonably expect here and will not find.** Name it, and say whether that is
deferred or refused. A capability silently absent is the thing that wastes
someone's afternoon.

## Wire format / algorithm

The construction, in enough detail that a second implementation could agree
with this one byte for byte. Cite the RFC, paper or published vectors by
section number, not by name alone.

## Constant-time contract

⚠ Only if this module touches secrets. State **which values are secret**, which
operations are claimed constant-time w.r.t. them, and — the part usually
missing — **what is deliberately not**. A blanket claim is worse than none: it
is what a reader relies on when they should be careful.

If a claim is machine-checked, say by what (`scripts/checks/ctgrind.sh <name>`, a row
in `scripts/checks/ctgrind-expected.tsv`). If it rests on reading the code, say that
instead. Those are different grades of evidence and must not be written alike.

## Limits and refusals

Every hard bound the code enforces, with the number and where it comes from.
A limit derived from a spec cites the spec; a limit chosen by us says so and
says why. If a constant is pinned by a test, name the test.

## Anchoring

Where the expected values in the tests come from. Distinguish, in these words:

- **External anchor** — published vectors, bytes captured from a foreign
  implementation, or a live run against a foreign peer. It can fail us.
- **Re-derived** — an in-house oracle reaching the answer another way. Catches
  a typo; does **not** catch a shared misreading of the spec.
- **Self** — we wrote the expected values from our own reading.

⚠ An external anchor is produced by an INSTRUMENT, and that instrument is part
of the module: it lives in `src/` if it is pure Zig, in `modules/<name>/tools/`
if it needs a foreign toolchain (`CONVENTIONS.md` §9), and never in a scratch
directory. An anchor whose producer cannot be re-run is a number nobody can
check — name the file here.

⚠ Never record a design reference ("we looked at how X does it") as an anchor.
State the grade in the machine-checked form `check-catalog` reads:

**Anchor grade:** class <A|B|C|D> · oracle <EXTERNAL|REDERIVED|MIXED|SELF|n/a>

Class A/B means an outside truth exists (a wire format others must agree with, or
a published construction with vectors) and the oracle may not be `n/a`. Class C/D
means none exists — an internal algorithm, or our own design — and the oracle must
be `n/a`, because grading one invents anchor debt that cannot be paid.

## What is deliberately not done

Decisions to refuse work, with the reason. This is the section that stops the
same proposal arriving every few months — and the one whose absence made a
separate archive necessary until 2026-08-13. Distinguish **not now** from
**never** from **superseded by something external**; they are not the same and
get confused constantly.

## Open

What is known to be missing or unverified. An honest gap here is worth more
than a claim that does not hold.
