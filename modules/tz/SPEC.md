# tz — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
IANA time-zone offset lookup: zone name → UTC offset/DST at a given instant. Pure logic, no OS calls,
no filesystem — the whole tzdata table is a compiled-in Zig array (`tz_data.zig`, generated ahead of
time by the `tz-gen` tool, not ported into this module). Each of the 600 IANA zones
carries an explicit list of UTC-offset transitions from 1970 onward (real tzdata transition history,
`zic` output); `offsetAt` binary-searches that list for the offset in effect at a given Unix instant.
Past the last explicit transition (tzdata typically stops emitting these around 2037/2038), it falls
back to evaluating the zone's POSIX-TZ footer rule (`std offset [dst [offset] [, start[/time],
end[/time]]]`) for the target year — the same mechanism `localtime(3)` uses beyond the precomputed
table. `find` binary-searches `zones` (case-sensitive, matching IANA spelling exactly) by name. No
allocation anywhere; reentrant, no shared state. Composes `datefmt` (extracted separately) for the
POSIX-TZ footer's calendar math. `src/root.zig` is original work of the zig-libs authors (MIT);
`tz_data.zig` is generated data from the IANA tzdata 2026a release (public domain) — see NOTICE.

## Threat model / out of scope
Not a security-sensitive module — a pure offset-lookup table over a fixed, trusted, compiled-in data
set; there is no untrusted-input attack surface (the only "input" is a zone name string and an i64
instant, both looked up/computed with bounded, panic-free logic). Resource bound: O(log n) binary
search over a fixed 600-entry table, no unbounded loops. Failure mode: `find` returns `null` for an
unknown zone name (never panics); `offsetAt` on a zone whose POSIX footer uses an unsupported rule
form falls back to the last explicit transition's offset rather than erroring (a documented
approximation, not a crash).

## Verification
`zig build test-tz` (Debug and `-Doptimize=ReleaseFast`): zone lookup by name, offset lookup
before/between/at-or-after the last explicit transition, POSIX-footer-rule evaluation for a
present-day instant, DST flag correctness across a transition, and POSIX footer `Jn`/plain-`n`
Julian-day rule evaluation (including a leap-year positive control — see Backlog). Correctness oracle
is this module's own test values plus the generated tzdata table (produced by `tz-gen` from the real
IANA release, not hand-authored, so wrong-by-construction errors are ruled out by the generator rather
than by these tests alone).

## Backlog / deferred
- **Done (this session):** the POSIX footer parser now also evaluates the `Jn` (1<=n<=365, Julian day,
  Feb 29 never counted — day 60 is always March 1) and plain `n` (0<=n<=365, zero-based day of year,
  Feb 29 counted) rule forms, alongside the pre-existing `Mm.w.d` form, all through the same
  `ruleDateUnix`/`posixOffset` evaluation path (`src/root.zig`). No current tzdata-2026a zone's footer
  actually uses `Jn`/`n` (all 600 use `Mm.w.d`), so this is forward cover for zones/releases that do,
  exercised by synthetic-zone tests (`Test/Jn`, `Test/n`) rather than a real IANA entry. A leap-year
  positive control (`J59` vs plain `59`) proves the two forms are not accidentally aliased: `J59` is
  Feb 28 in both a leap (2024) and non-leap (2023) year, while plain `59` is Feb 29 in the leap year
  and March 1 in the non-leap year — different UTC instants for the same digit, in the year that makes
  Feb 29 exist. (Note: the *POSIX day-number* that lands on Feb 29 is 59, not 60 — Jn is 1-based so
  `J60`≡March 1 always, and the zero-based `n` only reaches Feb 29 at index 59; `n=60` is March 1 in a
  leap year too, so `59` is the number that actually demonstrates the divergence.)
- **Deferred — tzdata refresh cadence tooling:** out of scope for this extraction. Regenerating
  `tz_data.zig` from a newer IANA tzdata release requires the `tz-gen` generator, a separate tool not
  ported into this module (see README "Defer"); this module has no loader to redirect and no version
  accessor to add — `tz_data.zig`'s header comment already states the pinned release (tzdata 2026a) and
  the regeneration path (`tz-gen`, `zig build run`). A "point the loader at a fresh tzdata dir" helper
  doesn't apply here (there is no runtime loader — the table is compile-time-embedded, by design, per
  the module's no-filesystem/no-syscalls threat model above). Refreshing the pinned release is a
  `tz-gen`-tool concern, not a `tz` (this module)-API concern.

## Status
`extract · any · util · reentrant` + deps: `datefmt` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** 600 zones from real IANA-generated table; Jn/n forms only synthetic hand zones

**How it got there.** No external oracle exists for what remains. real zic footers are always M-form; Jn/n is unreachable from any current IANA release
