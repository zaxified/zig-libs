# frost — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-08** — **FIX (secrets on the dead stack):** the dead-stack burn's buffer is now
  16-aligned instead of the vector type's natural 32. At 32 the burn's frame was realigned, and
  the up to 56 bytes between its saved frame pointer and the buffer — the top of the frame the
  burned body had used — stayed unzeroed (found by `threshold_ecdsa`'s stack probe: half of a
  secret survived there). No API change.
- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE (speed):** the dead-stack burn zeroes with
  volatile 32-byte vector stores instead of `std.crypto.secureZero` (a volatile byte memset,
  ~3 B/ns without libc): ~30× faster per KiB burned. Same size, same depth; the ReleaseFast stack
  probe still reads 0.
- **2026-10-08** — **BREAKING:** `round1Commit(nonces: *const SigningNonces)` and `round2Sign(…,
  nonces: *const SigningNonces, …)` take the nonce pair by pointer, as frost-core's `&SigningNonces`.
  Security (HIGH): `generateNonces`, `round1Commit` and `round2Sign` left the signing share and the
  secret nonces on the dead stack — measured with the new `src/stackprobe_test.zig` (ReleaseFast) —
  and a nonce next to the published signature share is the share. Each now runs its work one
  `noinline` frame down and burns 32 KiB after it; the by-value pair was copied at the call
  boundary, outside any burn, hence the pointer. Migration: pass `&nonces`.
- **2026-10-08** — **BREAKING (error set):** `round2Sign` checks RFC 9591 §5.2's MUST that
  `commitment_list` carries this signer's own round-1 commitments (`nonces·G`), as frost-core's
  `sign` does: new `Round2SignError.IncorrectCommitment` when the listed hiding or binding
  commitment differs (a Coordinator could otherwise choose this signer's part of `R`);
  `InvalidCommitmentList` when the identifier is absent. An exhaustive `switch` over the error set
  needs the new arm. `trustedDealerKeygen` refuses `min_participants < 2` (RFC 9591 Appendix C.1;
  a threshold of 1 hands every participant the group secret) and zeroes the shares before freeing
  them on an error path. ctgrind `sign` 5 → 13 (the commitment recomputation and comparison).
  Audit 2026-10-08 (`SPEC.md`).

- **2026-10-06** — **NO CONSUMER-VISIBLE CHANGE:** SPEC consistency: other ciphersuites, DKG and `vssVerify` in Out of scope (and DKG in Threat model) now read "not yet — see Backlog", matching the survey Backlog.
- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **commit 8 / sign 5**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. ⭐ SPEC.md's "this module introduces no additional branches on secret scalars in its REAL code" is CONFIRMED: the `sign` target shows zero contexts in curve arithmetic — the whole signature-share equation (`root.zig:1018-1020`) is clean, and all five contexts are std's scalar-canonicality check at the "turn secret bytes into a Scalar" API boundary, disassembled to a real `jne` rather than assumed. `commit`'s eight split 4 `rejectIdentity`-shaped (two k256's, two this module's own redundant re-check) and 4 canonicality. ⚠ Not adjusted for single-process over-taint.

- **2026-09-07** — **NO CONSUMER-VISIBLE CHANGE:** out of `zig build
  check-testonly` again, with local copies of `testkit.fuzz`'s seed and cursor
  helpers instead of the shared ones. Enrolling this module via `test_deps` puts
  it in that gate, whose probe imports the *published* module and references
  every declaration three levels deep — which reaches `std.crypto.pcurves`'s
  secp256k1 scalar `sqrt`, a `@compileError("unimplemented")` because the group
  order is 1 mod 4. The probe cannot compile, through no fault of this module.
  ⛔ Local copies are what `testkit.fuzz` exists to abolish; what keeps these from
  drifting is that each carries an anchor test driving the real
  `std.testing.Smith` (and, for the cursor, its wrap and range behaviour), so a
  future Zig that changes `slice`'s framing fails here loudly rather than leaving
  the corpus quietly seeding nothing.

- **2026-09-07** — Test-only, no production change: `fuzzVerify`, the harness named "never
  panics on **corrupted** signature bytes", had never corrupted a byte. Its first draw was
  `smith.valueRangeAtMost(u8, 0, 6)` and it had no corpus, so `n_flips` was the range
  MINIMUM - **0** - on every input the ordinary lane ever ran: it verified the pristine
  RFC 9591 Appendix E.5 signature, unmodified, every round. Two things were wrong and
  fixing one would have bought nothing. (1) The draw: the perturbation script now comes out
  of one `smith.slice` read through `testkit.fuzz.Cursor`, so the byte draw is first and a
  seed is a readable `[flip count][position, value]...` script. (2) The flip BUDGET: the
  harness's own comment says the mutation lands "near the `Element`/`Scalar` canonical-range
  boundary", but secp256k1's `n` is `FFFFFFFF...FFFFFFFE BAAEDCE6...` - **fifteen leading
  0xFF octets** - so no edit of six octets can raise a 32-octet scalar above it, and
  `Scalar.fromBytes`'s range check could not have fired from this harness at any flip count
  it was able to draw. The cap is now 40 and one seed spends sixteen flips on exactly that
  refusal. Measured by the new `corpus:` guard: 7 non-empty scripts, **29 flips applied**
  (0 before), 6 signatures parsed, 2 verified - so four corrupted signatures got past
  `fromBytes` and were refused by the group equation, the path the target exists for.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `verify` (corrupted signature bytes against the fixed RFC 9591 Appendix E.5
  group public key/message) — `zig build check-fuzz` no longer names this
  module. No panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9591 Appendix
  E.5's published test vectors.
- **2026-07-12** — New module: FROST — Flexible Round-Optimized Schnorr Threshold
  signatures (RFC 9591), secp256k1/SHA-256 ciphersuite — a t-of-n threshold Schnorr
  scheme: trusted-dealer keygen (Shamir + Feldman VSS), 2-round.
