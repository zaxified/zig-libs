# Changelog

**Index only.** This file lists which modules each dated tag touched; the
detail lives in `modules/<name>/CHANGELOG.md`, so a consumer of three modules
reads three files instead of scanning every release section here.

Tags are dates (`YYYY-MM-DD`), not semantic versions, and assert one thing:
every module passed every lane at that commit. Policy and the reasoning —
why semver would be both unenforceable and uninformative here — are in
`CONVENTIONS.md` §8. `v0.1.0` remains as history; nothing after it is a
semantic version.

## Unreleased

The collection grew 77 → 225 modules since v0.1.0, spanning pairing/EC
crypto, Bitcoin/Lightning, post-quantum, FHE/ZK/MPC, protocol security,
distributed fabric and kernel/networking. Every module now carries a
`CHANGELOG.md`, not only the ones with a code change to record: each
one's audit — PASS, findings fixed, or (for the small number rated CRIT)
the fixed defect stated plainly — is itself a maturity fact worth dating,
and a module with no post-creation history still gets its `New module:`
entry so per-module maturity is trackable without the internal audit
directory.

### Collection-wide notes (belong to no single module)

- **Tooling:** two module sets that the shell scripts kept their own copies of
  now have one source each. Which modules talk to a **live external peer** is
  `.live` on the `module_list` entry, beside `heavy` and `example` where the
  same kind of fact already lived; it was a string in `scripts/test-lib.sh`
  read by three scripts, so a module that gained a live peer and was not added
  kept running in parallel — the exact flakiness that variable exists to
  prevent, and invisible until it bit. Which modules own a **constant-time
  harness** is now derived from `modules/<m>/src/ctgrind_harness.zig` existing:
  that fact was written out three times (build.zig's `ctgrind_harnesses`,
  `ctgrind.sh`'s `ALL_MODULES`, and implicitly its `TARGETS` keys), so a
  harness added without editing all three was never measured with every gate
  still green. `zig build module-graph` publishes both, the scripts read them
  from there, and `ctgrind.sh` now refuses to run when a harness in the tree
  has no recipe — previously that case reported "no harness for module", which
  was the opposite of true.

- **Tooling:** the README module catalog is now **generated in full** —
  `zig build gen-catalog`, gated by `check-catalog-table`. Each row's
  description and Platform cell come from the module's own `meta.doc` /
  `meta.platform_note`, its section from `module_list`'s `.libs`, its Deps cell
  from `.deps`; `README.md` holds no catalog fact of its own. The 230 blurbs
  moved out of the table into the modules verbatim — verified by regenerating
  and comparing: all 230 rows came back with identical content, so the move was
  a relocation and not a rewrite. Rows are alphabetical, so ordering stops being
  a third hand-maintained fact, and a module now appears in **every** library it
  is tagged with (its home in brackets in the others), which is what the
  many-to-many tag was for. Prose lives with the module because it goes stale
  when the code changes; the taxonomy lives in `module_list` because a misfiling
  is only visible next to its neighbours.

- **Tooling (superseded the same day by the above):** `zig build gen-catalog` first rendered only the parts of the README module
  catalog that are views of `module_list` rather than prose — a row's section
  placement from `.libs[0]`, its Deps cell from `.deps`. Both were previously
  only *guarded* against drift, which keeps two lists in sync instead of making
  them one; the guards stay as tripwires but the arrangement now has an
  authoritative source. Verified by reproducing all 230 Deps cells byte-exactly
  from the field before anything else changed. The one-line description and the
  Platform cell are deliberately left hand-written: measured, the blurbs are
  30 KB of prose existing nowhere else (221 of 230 differ from the module's own
  README opening), and the Platform cell carries nuance the `meta.platform`
  enum does not have.

- **Taxonomy:** modules are now filed into six **libraries** — `web`, `net`,
  `storage`, `crypto`, `format`, `os` — via a required `.libs` field on the
  `module_list` entry, first entry primary. `zig-libs` was already a plural
  with no singular written down anywhere machine-readable: the same grouping
  existed only as README section headings, which nothing checked, and
  `testkit` (a test-only harness) had been filed under *Networking*. The
  primary library and the section a module's catalog row is printed under are
  now held to agreement in both directions by `check-catalog`, and the
  `Serialization / OS / agent` catch-all was split, since it does not survive
  becoming a singular name. A module may carry further libraries it is worth
  reaching for from — `x509` is `crypto` and `net` — which
  `zig build gen-libs-table` renders into README's *Libraries* table and
  `check-libs-table` keeps from going stale. Sixteen modules already had a
  dependency edge crossing a library boundary; that is where the initial extra
  tags came from, but the field is a judgement and is deliberately not gated
  against that evidence.

- **Security audit:** all CRIT/HIGH findings from a collection-wide audit
  were fixed. Findings named for a specific module are detailed in that
  module's own changelog; this line is the pointer for the audit as a
  whole.
- **Performance campaign:** in addition to the per-module wins recorded in
  the module changelogs, audited hot paths across the collection landed
  within ~≤3× of C peers, and several constant-time leaks were fixed, in
  modules not individually named for either.
- **Tooling:** `zig build check-catalog` consistency gate added (found
  and fixed 6 modules missing README catalog rows), and
  `zig build check-changelog` (found 16 module changelogs that the
  then-existing root index had never listed — nothing had ever checked it).
- **Tooling:** `zig build check-changelog` now also requires that every
  module in `module_list` HAS a `CHANGELOG.md`. It read each one with
  "skip if unreadable", so a module with no changelog at all was skipped
  along with every claim about it — measured, not assumed: deleting a
  module's changelog *and* its then-required root index bullet, which is
  the state a newly added module arrives in, left the gate green. The
  sentence above about every module carrying one was therefore a fact
  about a morning and not an invariant; it is one now. **What a module
  author must do:** write `modules/<name>/CHANGELOG.md` from the module's
  first commit (`CONVENTIONS.md` §8; `modules/_template/` ships the
  skeleton and the checklist).
- **Tooling:** `zig build check-changelog` now also requires that the file at
  `modules/<name>/CHANGELOG.md` **is a changelog** — a `# ` title naming the
  module, and an `## Unreleased` heading. The previous fix stopped one layer
  short, and again the hole was measured, not reasoned about: truncating a
  module changelog to zero bytes still passed, because an empty file has no
  entries to date, no `## Unreleased` section to compare, and the root
  index link it then carried still resolved. A module could hold a
  zero-byte placeholder and read as fully documented. An ENTRY under
  `## Unreleased` is still not required — after a tag is cut that section is
  legitimately empty.
- **Docs:** the per-module index that used to stand here — one bullet for
  each of the 225 module changelogs — was removed, and with it the gate's
  index-membership and `BREAKING`-mirror checks. Every module now has a
  changelog, so "which modules have one" answers itself, and the bullets
  restated their own targets: checked before deleting, all 225 summaries
  (including all 128 finding-counts) were derivable from the file each
  pointed at, so no content was lost. The one fact the index alone carried
  — which modules have a **BREAKING** change pending — is a question for
  the tree, not a copy of it: `rg -l '\*\*BREAKING' modules/*/CHANGELOG.md`
  answers it (12 modules today, exactly the set the index tagged) with no
  drift surface, whereas the mirror needed a gate whose only subject was
  the copy the index itself created. `CONVENTIONS.md` §8 carries the
  reasoning.
- **Policy:** dated-tag versioning + spin-off policy adopted
  (`CONVENTIONS.md` §8); this changelog split is one product of it.

## v0.1.0 — 2026-07-10

Initial public release: 77 modules, 1844 tests, CI green in Debug +
ReleaseFast, MIT (fping-lineage attribution preserved in `NOTICE` §1).
