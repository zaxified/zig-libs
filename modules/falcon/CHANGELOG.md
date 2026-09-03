# falcon — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-03** — Drift re-audit (717 lines since the last one). ⚠ **BREAKING:**
  `Signer.SignError` gained `TooManyRetries`. `signWithRng`'s rejection-sampling
  loop was `while (true)` with `sig_out.len == 0` as its only length check —
  every other undersized buffer made `compEncode` fail, `catch continue` swallow
  it, and the next draw fail identically. **The call never returned**: an
  unkillable, non-allocating spin, not an error. The first audit recorded
  "`sig_out` too small → `error.NoSpaceLeft`" as a PASS in the same sentence that
  named the `catch continue` two lines above it; the halves contradict and
  neither was executed. Now capped at `max_attempts = 64` draws, reporting
  `NoSpaceLeft` when every rejection was for want of room and `TooManyRetries`
  otherwise.
- **2026-09-03** — The constant-time fix from the first audit — `src/fpr.zig`'s
  integer emulation, raised as a HIGH — had **no guard of any kind**. Replacing
  `fpr.div`'s body with a native `/` leaves the whole suite green and the KATs
  byte-exact, because the emulation is bit-identical to IEEE-754 and no value
  test can see the difference; `falcon` is on neither `scripts/ctgrind.sh` nor
  `ctgrind-expected.tsv`. The property was held in place by a SPEC.md paragraph.
  New gate **`scripts/check-fp-freedom.sh`**, wired into every `scripts/test.sh`
  lane: disassembles a ReleaseFast build and fails if a variable-latency FP
  mnemonic reached a non-test symbol. Verified red under that mutation, naming
  `vdivsd` in `fft.polyLdlFft` (the secret Gram matrix), `fft.polyDivAutoadjFft`
  and `fft.polyInvnorm2Fft`.
- **2026-09-03** — The `PublicKey.verify` fuzz harness ran **exactly one input
  with zero bytes flipped**. Outside `--fuzz`, `std.testing.fuzz` with an empty
  corpus runs one input, and `valueRangeAtMost` falls back to the range's LOWER
  bound on exhausted input — so `valueRangeAtMost(u8, 0, 6)` gave 0 flips and the
  harness verified the pristine, valid KAT signature on every ordinary test run,
  while the changelog recorded "no panic/OOB found". Lower bound is now 1, with a
  test pinning it.
- **2026-09-03** — Docs: `example/main.zig` warned that the seeded PRNG was a
  keygen hazard and said nothing about passing the SAME `rng` to
  `signRandomized`, which emits a byte-identical 40-byte salt on every run —
  precisely what `signDeterministic` was deleted for. `SigningKey.secureZero`'s
  doc named double-call as the hazard; the real one is that a wiped key stays
  callable. SPEC.md's `objdump` evidence claimed the FP hits were confined to
  "exactly two functions"; re-running its own grep finds four (all tests, so the
  substantive claim survives — the reproducible count did not, and was already
  wrong when written).

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `PublicKey.verify` (corrupted compressed-signature bytes against the fixed
  NIST-KAT public key/message/nonce) — `zig build check-fuzz` no longer names
  this module. No panic/OOB found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against NIST Round-3 KAT's
  published test vectors.
- **2026-07-11** — New module: Full FN-DSA — Falcon-512 and Falcon-1024 (the NIST PQ
  lattice signature): verification + signing + key generation + all key/signature
  codecs, byte-exact vs the NIST Round-3 KATs for both parameter.
