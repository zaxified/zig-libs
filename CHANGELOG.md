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

- **New `example-apps/`:** standalone applications built on zig-libs, each its
  own project with its own `build.zig`/`build.zig.zon` and a dependency pinned
  to a dated release tag. Copy a directory anywhere, run `./init.sh`, get a
  binary — the primary purpose, and the manifests are written for it alone.
  First one is `ssh-demo`, moved out of `modules/ssh/example/` where 2339 lines
  of client-and-server had been squeezed into the single file that slot allows.
  Two checks are arranged from OUTSIDE the app so its manifest stays the
  customer's, and both are blocking: `scripts/check-apps.sh` builds each with
  `zig build --fork=../..`, overriding the pin with the working tree, and on a
  tag ref `--pinned` builds each from its manifest as written — fetch by URL and
  hash, compile the exported package, which is the artifact a downloader gets
  and the only one that goes through `.paths`. An app's source is written
  against the TREE; the pin exists for the downloader, because a tag is the only
  ref carrying the all-lanes-green claim. A third use was considered and
  dropped: running two builds of the same source at two versions against each
  other. For `ssh`, the only app with both ends of a protocol in one binary, 20
  live interop tests against real OpenSSH dominate it — a foreign implementation
  fails independently of us, our own previous version shares every misreading of
  the RFC we have. `scripts/tag.sh` rewrites the
  pins when a tag is cut, which works only because `example-apps/` is outside
  `.paths`: editing an app does not change the package hash, so the hash the
  bump writes stays correct after the commit that writes it (verified by
  hashing a clean export with and without an `example-apps/` tree). An app
  importing exactly one module discharges that module's example obligation —
  more strictly than `modules/<m>/example/` does, since it goes through the
  package manager rather than an in-repo `addImport`.

- **`example-apps/` are built in the mode they claim, and are RUN by the gate.**
  Two separate fixes, the second found by the first. Each app's `build.zig` said
  "ReleaseSafe by default … `-Doptimize=ReleaseFast` if you have measured that
  you need it" and delivered neither: `standardOptimizeOption` with a
  `preferred_optimize_mode` registers `-Drelease=[bool]` and **not**
  `-Doptimize`, and with no flag it returns `.Debug`. So every build of every
  app — including the gate's — was a Debug build, and the documented flag was
  rejected as an invalid option. The apps now declare `-Doptimize` themselves
  and default to `ReleaseSafe`. On top of that, `scripts/check-apps.sh --run`
  now runs each app's `smoke.sh` in `ReleaseSafe` **and** `ReleaseFast`, which
  is where a `std.debug.assert` guard is compiled out. `http-service` also
  learned to stop on SIGTERM, because its `DebugAllocator` leak check only
  executes on a clean exit and nothing had ever given it one.

- **Packaging fix:** `build.zig.zon`'s `.paths` did not list `LICENSE` or
  `NOTICE`, so neither was part of the package. `.paths` decides what a
  consumer actually receives; a file outside it is visible on GitHub and absent
  from every fetched copy. For an MIT collection that means the permission
  notice did not travel with the code, and `NOTICE` — the file written
  specifically to tell a consumer whether consuming this obliges them to
  anything beyond MIT — never reached one. Both are listed now, and
  `zig build check-package` keeps them there. **This changes the package hash**,
  so a consumer pinning by hash re-pins at the next tag, which they would be
  doing anyway.

- **Tooling / audit of the repo root and `scripts/`:** `chk2` and `chk2b` —
  5547 NUL bytes each, identical, referenced by nothing, committed by accident
  in `55dd448` — deleted from the repo root. `zig build check-uapi` is now in
  the gate: it works and passes (689 kernel constants matched, 0 mismatched,
  across five modules) but nothing ran it, and being host-dependent was a
  reason not to fold it into `check-catalog`, never a reason not to run it —
  it skips rather than fails when python3 or the headers are missing. Wiring it
  in exposed why it never was: its summary went through `std.log.info`, which
  writes to stderr, and the driver treats "exit 0 with anything on stderr" as a
  failure — deliberately, after four defects of exactly that shape. The summary
  goes to stdout now. New
  `zig build check-scripts-doc` requires every file in `scripts/` to be named
  in `scripts/README.md`; that README is the only map of the harness and had
  drifted three entries, one of them `check-http-sizeprobe.sh`, which the gate
  runs on every invocation. `scripts/check-citations.py` stays manual and now
  says why: measured on `dns` it pairs an `RFC NNNN` mention with any nearby
  quoted string, so a quoted SPEC.md heading reports as a mismatch. Also
  removed a dead `catalogRowModule` left behind when the catalog row-mover
  became the full renderer.

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
