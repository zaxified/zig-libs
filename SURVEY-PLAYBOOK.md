# Competitive survey playbook

Moved into this repository on 2026-09-08: it is process documentation for
`zig-libs` modules, and the licence rule it carries is this repository's own
policy, so it belongs beside `CONVENTIONS.md` rather than in a developer's
notebook where no reader of this repo would find it.

Every module that is going to ship an example application gets this survey first.
Its output is a **ranked list of gaps to finish** in that module; the application is
built only afterwards. The `rdap`/`whois` survey of 2026-08-22 is the worked pilot.

## ⛔ Licence discipline — read this before opening any foreign source

**Permissive source (MIT, BSD, Apache-2.0) may be read and ported; copyleft source may
not.** This is not advisory. (Owner, 2026-10-15, correcting the earlier "MIT only, never copy"
reading; the MCP SDK case below, 2026-10-20.)

1. **Establish the licence before reading a single line of source.** Check the
   repository's `LICENSE` file *and* the GitHub API's `spdx_id`. They disagree more
   often than you would expect — and when they do, **the LICENSE file's text is
   authoritative and the API is only a hint.** Both directions of error are real:
   `ntpd-rs` carries `LICENSE-MIT` + `LICENSE-APACHE` but the API reports
   `NOASSERTION`, and `rust-minisign`'s LICENSE is the verbatim MIT body that merely
   omits the "MIT License" header line, which is enough to defeat the detector. Trusting
   the API alone would have wrongly locked us out of both. Quote what you read.
2. **MIT, BSD, Apache-2.0, and any mix of them, are fine** — including a repository
   whose `LICENSE` says it is mid-transition with each contribution under one of them
   (the official MCP Go, TypeScript and Rust SDKs, MIT→Apache-2.0; API: `NOASSERTION`).
   A port carries the upstream copyright + licence text in `modules/<m>/NOTICE` and a
   `ported from <project> <version> <file>` comment (root `NOTICE` §0).
3. **Copyleft (GPL, LGPL, AGPL, MPL …): source is off limits** — it would taint the
   MIT code. It may still serve as a black-box oracle, and README, reference
   documentation, issues and pull-request prose are fair game — that text is the
   authors' own writing about their software, not the licensed software itself. A great
   deal can be learned from a bug report; the Rust MCP SDK's whole reversal was
   reconstructed that way.
4. **Unknown or proprietary licence: off limits** as copyleft is.
5. **Read before you port, verify before you claim.** A port is a decision about a
   specific hot spot or behaviour, recorded in the NOTICE; a gap claimed from reading
   foreign code is still checked against OUR code (file:line, profile) first.
6. **State the licence you found for every project in the report**, including the ones
   you decided not to read. A survey that does not name its licences cannot be trusted
   and will be sent back.

## What the survey must answer

1. **What do we actually implement?** Which RFCs and which parts of them; what the
   public API lets a user do; what is explicitly out of scope; what is stubbed. Be
   specific — "supports X" is useless. Separate what the **tests exercise** from what
   the **prose asserts**.
2. **How do we compare?** Find the notable Rust and Go implementations — verify they
   exist and are maintained rather than assuming from memory — and the **Zig alternatives**
   (`std` and the ecosystem): for a Zig consumer they are the closest competition. Where
   a de-facto reference implementation exists (often C: libzstd, OpenSSL, curl), it is
   the Scope line's yardstick. Compare on what a real
   user notices, not on line counts. Say plainly where **we are ahead**; the pilot found
   two such places and that mattered as much as the gaps.
3. **What is worth finishing?** A ranked list. Each item: what it is, why a user would
   care, rough effort, and whether it fits this repo (check `CONVENTIONS.md` §2 — pure
   Zig, no C, no libc, no external dependencies). Split the verdicts three ways:
   **missing and it matters** / **deliberately not doing it** / **nobody does this**.

## Where the verdict goes

The survey ends by setting the module's **`**Scope:**` line** in the `## Maturity` card of its
`SPEC.md` — `ahead`, `parity`, `core`, `mvp` or `poc`, naming the reference implementation
and the survey date (definitions in `modules/_template/SPEC.md`) — by writing the SPEC's
`## Compared with` table (every project compared against: link, language, licence, stars,
latest release or push, what a user notices; the reference marked **reference** and the
fastest implementation in the field marked **fastest** — usually a C, C++ or Rust one, rarely
the reference; `check-catalog-table` refuses a surveyed Scope without the table), and by filing
the "missing and it matters" items under the SPEC's `## Backlog / deferred`. `ahead` is
parity plus a lead, and the survey states the lead on the card's `**Ahead:**` line; a speed
lead is measured against the **fastest** row, never just the reference, with the bench kept
in `tools/` and its ratios on the `**Performance:**` line. Then run `zig build gen-catalog`:
the module's grade loses its provisional `?` and may go down. A survey that leaves the Scope
line at `unsurveyed` has not finished.

## Standing rules

- Mark every claim as verified or inferred. An unmarked guess is worse than a gap.
- Prefer a **reference tool we can diff against** (`fping` is why `zig-fping`'s tests
  are strong). If the module has one, name it — it becomes the application's oracle.
- Check whether the module's own SPEC/README still tells the truth; the pilot found
  stale test counts in both files it looked at.
