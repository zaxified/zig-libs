# Competitive survey playbook

Moved into this repository on 2026-09-08: it is process documentation for
`zig-libs` modules, and the clean-room rule it carries is this repository's own
policy, so it belongs beside `CONVENTIONS.md` rather than in a developer's
notebook where no reader of this repo would find it.

Every module that is going to ship an example application gets this survey first.
Its output is a **ranked list of gaps to finish** in that module; the application is
built only afterwards. The `rdap`/`whois` survey of 2026-08-22 is the worked pilot.

## ⛔ Licence discipline — read this before opening any foreign source

**Only MIT-licensed source may be read.** This is not advisory.

1. **Establish the licence before reading a single line of source.** Check the
   repository's `LICENSE` file *and* the GitHub API's `spdx_id`. They disagree more
   often than you would expect — and when they do, **the LICENSE file's text is
   authoritative and the API is only a hint.** Both directions of error are real:
   `ntpd-rs` carries `LICENSE-MIT` + `LICENSE-APACHE` but the API reports
   `NOASSERTION`, and `rust-minisign`'s LICENSE is the verbatim MIT body that merely
   omits the "MIT License" header line, which is enough to defeat the detector. Trusting
   the API alone would have wrongly locked us out of both. Quote what you read.
2. **Dual `MIT OR Apache-2.0` is fine** — take the MIT option and say so.
3. **Anything else: source is off limits.** README, reference documentation, issues
   and pull-request prose are still fair game — that text is the authors' own writing
   about their software, not the licensed software itself. A great deal can be learned
   from a bug report; the Rust MCP SDK's whole reversal was reconstructed that way.
4. ⚠ **"Other" / `NOASSERTION` counts as not-MIT.** Several ecosystems are mid
   relicensing — the official MCP Go, TypeScript and Rust SDKs each say inside their
   own `LICENSE` that the repository is transitioning MIT→Apache-2.0 per contribution.
   Do not read their source.
5. **Never copy code** — not into the report, not into the repo, not "as a reference".
   What we want out of a survey is *behaviour and reasoning*, never an implementation.
   `zig-libs` is a public, clean-room repository and takes no code from elsewhere.
6. **State the licence you found for every project in the report**, including the ones
   you decided not to read. A survey that does not name its licences cannot be trusted
   and will be sent back.

## What the survey must answer

1. **What do we actually implement?** Which RFCs and which parts of them; what the
   public API lets a user do; what is explicitly out of scope; what is stubbed. Be
   specific — "supports X" is useless. Separate what the **tests exercise** from what
   the **prose asserts**.
2. **How do we compare?** Find the notable Rust and Go implementations — verify they
   exist and are maintained rather than assuming from memory. Compare on what a real
   user notices, not on line counts. Say plainly where **we are ahead**; the pilot found
   two such places and that mattered as much as the gaps.
3. **What is worth finishing?** A ranked list. Each item: what it is, why a user would
   care, rough effort, and whether it fits this repo (check `CONVENTIONS.md` §2 — pure
   Zig, no C, no libc, no external dependencies). Split the verdicts three ways:
   **missing and it matters** / **deliberately not doing it** / **nobody does this**.

## Standing rules

- Mark every claim as verified or inferred. An unmarked guess is worse than a gap.
- Prefer a **reference tool we can diff against** (`fping` is why `zig-fping`'s tests
  are strong). If the module has one, name it — it becomes the application's oracle.
- Check whether the module's own SPEC/README still tells the truth; the pilot found
  stale test counts in both files it looked at.
