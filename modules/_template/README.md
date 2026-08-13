# _template

Copy this folder to `modules/<name>/`, then work through the list below. Steps
2 and 4–7, and the `Provenance:` line of step 3, are each enforced by a gate —
`check-catalog`, `check-changelog`, `check-testonly` and the dark-test check
(`scripts/dark-tests.sh`) — all of which run in CI and in both `scripts/test.sh`
lanes, so skipping one is a red build, not a style note. What those gates cannot
read — whether the prose is any good, whether the tests assert anything — is
what review is for. `CONVENTIONS.md` §6 is the narrative version; the rules
live in §2–§8.

1. **`src/root.zig`** — keep the `SPDX-License-Identifier` line first, then the
   `meta` block (vocabulary in `CONVENTIONS.md` §4), the public API with
   doc-comments, and tests. **Read `CONVENTIONS.md` §2.2 before writing any
   random draw**: a value that becomes a secret has to come from a fail-closed
   source, and a module that gets it wrong is a finding. The placeholder test
   this template ships fails on purpose — delete it, do not weaken it.
   Add a `SPEC.md` for anything with a real threat model or a non-obvious
   design invariant.
2. **Register it** in `module_list` in the root `build.zig`:
   `.{ .name = "<name>", .deps = &.{ "dep1", ... } }`. A dependency only the
   tests need goes in `.test_deps` instead (`CONVENTIONS.md` §6.1, proven by
   `zig build check-testonly`). The three copies of the dep list — `build.zig`,
   `meta.deps` and the README catalog row — must agree; `check-catalog`
   compares them.
3. **This README** — document **what it is**, **status** (extract/gap/adopt),
   **model-after** (the other-language reference), the **seed** location if
   extracting from an existing project, and how a consumer uses it. The
   `Provenance:` line at the bottom is required by `check-catalog`.
4. **Root `README.md`** — add the module's catalog table row, whose first cell
   is the module name in backticks, and bump the `N modules` count in the
   status line. If the Non-goals section names what you just built, remove that
   row.
5. **`CHANGELOG.md`** — fill in the copied skeleton (dated `New module:` entry)
   **and add its one-line pointer to the root `CHANGELOG.md`** under
   "### Modules with a changelog". Both halves are required:
   `zig build check-changelog` fails on a module with no changelog, a changelog
   with no index line, an index line pointing at no file, an entry with a
   missing or malformed date, or a `BREAKING` tag that disagrees between the
   two. See `CONVENTIONS.md` §8.
6. **`ANCHORS.tsv`** — add exactly one row: CLASS `A`/`B` (the module faces the
   outside world, so its test oracle must be a real external authority) or
   `C`/`D` (no outside exists, ANCHOR is `n/a`). The file's own header has the
   vocabulary. `check-catalog` fails without the row.
7. **Multi-file modules** — every submodule needs a `test { _ = <file>; }` line
   in `root.zig`. A bare `pub const x = @import("x.zig")` re-export does **not**
   pull `x`'s tests into the test binary: they are never compiled, never run,
   and the suite total agrees with itself (`zig build check-dark-tests`;
   `CONVENTIONS.md` §6 step 3).
8. **Third-party material** — a *studied* design reference gets an entry in the
   root `NOTICE`; *ported* source puts its terms in `modules/<name>/NOTICE`
   instead, never in the root file.
9. **Run it** — `zig build test-<name>`, then `zig build test` (or
   `scripts/test.sh changed`), green in **Debug and ReleaseFast**, and
   `zig fmt --check modules/<name>` clean. Once per clone:
   `git config core.hooksPath scripts/hooks`, which refuses a commit whose
   staged Zig/ZON blobs are not `zig fmt` clean.

Then replace the line below. `zig build check-catalog` requires every module
README to carry one, and it must say which of the three cases applies (see
`CONVENTIONS.md` §5 and the root `NOTICE` §0):

- clean-room from a public spec/RFC → no `NOTICE` entry, cite the spec here;
- a third-party implementation **studied** as a design reference → an entry in
  the root `NOTICE`, linked from here;
- third-party source actually **ported** → its terms in `modules/<name>/NOTICE`,
  beside the code that owes them, linked from here.

Provenance: TODO — clean-room from <spec>, no third-party source ported or
studied, so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0).
