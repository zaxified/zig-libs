# iec62351 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Docs: `SPEC.md`'s pointer to the goosestalker attribution was `../NOTICE`,
  which from the module directory resolves to `modules/NOTICE` — a path that has never existed.
  It means this module's own `NOTICE`. Found by the new link-resolution check in
  `zig build check-catalog`, not by the audit pass that fixed the `src/` links.
- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** the local `fuzzSeed` /
  `fuzzSeedInto` copies in this module's fuzz files are now `testkit.fuzz`. The
  helper existed **33 times across 12 modules in three shapes**, each carrying its
  own note about the same trap (the returned array has to be container-level or
  the slice dangles with the right length and garbage behind it). Proved
  byte-identical to the copies it replaces before they were deleted, and the
  comparison test was itself broken on purpose first to show it was not vacuous.
  `testkit` added to this module's `test_deps`; test-only, nothing a consumer
  imports changed.

- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** all 8 fuzz harnesses in this
  module were replaying a single fixed input, and two of them were testing
  nothing at all. A `Smith` ranged draw returns the range MINIMUM unless the
  eight octets it reads as a little-endian u64 already lie inside the range, and
  `smith.bytes` had eaten the seed before the length draw ran, so every harness
  saw the empty input. The frame draws are now `smith.slice(&buf)`, the flags
  that used to precede them (`fuzzFind`'s PDU kind, `fuzzParse`'s header
  profile, `fuzzExtension`'s `expect_iv`) follow them and use `value(u64)`, and
  every harness carries a corpus built by this module's own encoders. Measured
  over those corpora, non-empty inputs / inputs the parser accepts: ACSE field
  discovery 0 -> 7/2 (and the PDU kind was `.aare` on every run before, `.aarq`
  on 5 of 7 now), signed tokens 0 -> 5/2, BER 0 -> 14/6, GOOSE frames 0 -> 7/4
  (profile `.ts2007` on every run before, `.ed2020` on 5 of 7 now), GOOSE
  extensions 0 -> 6/4, certificate inspection 0 -> 6.
- **2026-09-06** — **NO CONSUMER-VISIBLE CHANGE:** the two harnesses that were
  testing nothing. `tlsprofile.fuzzCorrupt`, named "a real certificate with one
  octet corrupted", drew `smith.index(der.len)` and `smith.value(u8)` — both
  collapse — so it did `der[0] ^= 0` and inspected the PRISTINE certificate on
  every run: **0 octets changed.** It now draws both from `value(u64)`, with a
  16-seed corpus: **16 distinct (index, mask) pairs, 16 of 16 octets changed.**
  `replay.fuzzGoose` built its (stNum, sqNum, t) triple from three ranged draws,
  so it offered the guard the SAME identity 32 times running: over 8 seeds,
  **1 distinct identity across 256 steps and 8 acceptances** (the eight first
  steps, one per seed) — the "accepting must mean the pair moved strictly
  forward" branch could never see a pair that had moved. Now **256 distinct
  identities and 15 acceptances.**

- **2026-08-18** — Portability fix (`check-portable`): `ber.writeHeader`'s multi-byte
  length branch shifted its `usize` `content_len` by a hardcoded `shift: u6`, which
  fails to compile on a 32-bit target where `Log2Int(usize)` is `u5`. Retyped `shift`
  as `std.math.Log2Int(usize)` — `content_len` is a genuine buffer-sized `usize`, so the
  shift-amount type should be derived from the target rather than hardcoded. Compile-
  only, identical semantics (shift amounts here are `8 * (n-1-i)` with `n <=
  @sizeOf(usize) + 1`, comfortably inside `u5`); no behavioural test added. Verified:
  `zig build portable-iec62351` and `zig build test-iec62351 --summary all` (120/120)
  both green.
- **2026-08-06** — Security audit: four findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-23** — New module: IEC 62351 power-systems security — GOOSE/SV
  authentication (62351-6) over caller-supplied PDU bytes, MMS application
  authentication (62351-4), and the TLS profile requirements as a checkable policy.
