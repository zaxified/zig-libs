# iec62351 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-13** — A1 finding N1 (cross-module, fixed in `iec61850` in the same commit). The
  sibling's GOOSE decoder silently accepted a frame this module secured and dropped the
  extension. New `src/iec61850_seam_test.zig` runs `iec61850.goose.Frame.decode`/
  `decodeSecured`/`Pdu.decode` on a frame built by `goose.build` (`iec61850` added as a
  test-only dependency). README states the receive-side order.

- **2026-09-10** — A1 fix campaign, audit findings N2/N4/N5/N6/N7/N8/N9/N10/N11 (0 consumers in the repo, `DECISIONS.md` P1/P4).
  - **N2 (HIGH): BEHAVIOURAL, not breaking.** `SessionDescription`'s four most consequential booleans (`secure_renegotiation`, `mutual_authentication`, `chain_validated`, `revocation_checked`) no longer default to `true` — they are now required fields. A minimal construction used to silently claim all four; now the compiler requires an explicit answer, every time.
  - **N4 (MEDIUM):** `GooseIdentity` gains `clock_failure`/`clock_not_synchronized` (default `false`, matching pre-existing behavior) and `GooseOptions` gains `require_synchronised` (default `false`), symmetric to `SvOptions.require_synchronised`. Off by default: **NO CONSUMER-VISIBLE CHANGE** unless a caller opts in.
  - **N5 (MEDIUM):** `README.md`'s `iec61850` wiring example named nonexistent functions (`encodePdu`/`decodePdu`; the real names are `Pdu.encode`/`Pdu.decode`) and passed a `UtcTime` struct where `GooseIdentity.t_ns` wants nanoseconds, with no converter shown. Corrected, with the actual seconds+24-bit-fraction arithmetic inline. Doc-only.
  - **N6 (MEDIUM):** `acse.passwordMatches`'s own comparison is correct (a full 32-byte `std.crypto.timing_safe.eql`), but the suite could not distinguish it from a comparison narrowed to fewer bytes — mutation `a[0] == b[0]` survived 120/120 by luck (the fixed test passwords' digests differ at byte 0 anyway, most of the time). Added a deterministic test that searches for a genuine digest-byte-0 collision (no entropy, average ~256 SHA-256 calls) and asserts it is still rejected. Measured: the new test alone catches the `a[0] == b[0]` mutation (124/125, reverted to 125/125). Only the N=1 rung of the audit's ladder is practical at value-test level for a hash-based comparison (N=2/4/8 would need a preimage search infeasible in a unit test); noted in the audit record.
  - **N7 (MEDIUM): BEHAVIOURAL, not breaking.** `findAuthFields`/`insertAuthFields` now reject `error.TrailingBytes` when the outer `[APPLICATION n]` element's encoded length does not cover the whole input — the second half of ledger F3 (2026-08-06), which only `SignedToken.parse` actually got.
  - **N8 (LOW):** added the missing test for `forbid_ca_certificate`'s `basicConstraints cA` arm (only the `keyUsage keyCertSign` arm had one) — mutation T10 (deleting that arm) now fails the suite. The other three guards named in N8 (G8/A5 canonicity, A4 empty signature) remain untested but are, as the audit itself found, defense-in-depth rather than reachable holes (a shortened inner element breaks the outer MAC/signature first).
  - **N9 (LOW): refuted, already fixed.** The finding describes `fuzzParse` filling 160 random bytes and almost never passing the length gate (~0.23%); commit `7d1fc4d2` (2026-09-06) replaced that with a structured `smith.slice` draw plus a corpus built from the module's own encoders (4 of 7 seeds parse successfully today). The Zig 0.16.0 compiler bug that keeps `--fuzz` from building in Debug is unchanged and is not this module's defect.
  - **N10 (LOW):** `build.zig`'s `iec62351` entry no longer declares `.libs = &.{"net"}` — the module has no I/O of its own (`rg 'std\.Io|posix|Socket'` finds none).
  - **N11 (LOW): BEHAVIOURAL, not breaking.** `goose.parse` now rejects `error.UnknownEtherType` when the leading two octets are neither `ether_type_goose` (0x88b8) nor `ether_type_sv` (0x88ba) — previously read and returned unchecked, so a caller who stripped the wrong link-layer offset (14 vs 18 octets, the classic 802.1Q-tag mistake) got a `Frame` built from the wrong start point with no signal anything was wrong.
  - N1 (HIGH) and N3 (HIGH) are left open — both are explicitly "rozhodnutí uživatele" in the audit's own words: N1 needs a cross-module decision in `iec61850` (out of this module's and this campaign slot's scope), N3 needs a deployment-specific default numeric value the audit itself declined to pick.

  `scripts/modtest iec62351`: 126/126 (Debug, ReleaseSafe, ReleaseFast), up from 120/120 baseline. `zig fmt --check` clean on all four edited `.zig` files plus `build.zig`.

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
