# ct25519 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — **`mulBase`/`mulRistrettoBase` use a fixed-base comb:
  2.62× / 2.56× faster, same results (audit C3, C4, C9).** The base point ran
  the same 16-entry window ladder as any point, 252 doublings per multiply.
  It now runs the signed-radix-16 comb of Bernstein et al. 2012 §4 (ref10's
  `ge_scalarmult_base`) over a comptime 32×8 table: 64 additions, 4
  doublings, plus one always-performed add of `2^256·B` so all 256 scalar bits
  still count (ref10 instead requires `s < 2^255`). A deliberate exception to
  "never a new algorithm", admitted under `DECISIONS.md` P5; the four pieces of
  evidence are in `SPEC.md` § C3: bit-exact against the pre-C3 ladder on every
  nibble at every position, 33 boundary scalars and 20 000 random ones (10/10
  mutants red, 2 correct rewrites green); ctgrind `comb` target 0 contexts in
  `root.zig` with two positive controls firing (1 and 6 contexts at the
  mutated line); ReleaseFast A/B `mulBase` 56.3 → 21.5 µs, `ecvrf`
  `KeyPair.prove` 193.8 → 160.3 µs, control pair 1.01×.
  `mul(Edwards25519.basePoint, s)` stays on the ladder as the reference.
  New ctgrind targets `ladderbase` and `ladder` (the runtime-table path
  `voprf`/`opaque`/`bulletproofs` take, which had no target — C4), and an
  opt-in `src/bench.zig` (`CT25519_BENCH=1`, C9).
  NO CONSUMER-VISIBLE CHANGE in values or signatures; ~41 KiB more rodata.

- **2026-09-08** — **The scalar's by-value copy is now wiped here, because the
  caller cannot reach it.** `SPEC.md` said zeroization was "the caller's, on the
  scalar it supplied". A caller can wipe its own variable and nothing else: the
  copy the ABI leaves on `mul`'s frame is invisible to it. Measured with a
  painted-stack probe whose controls live inside the measurement — the 32-byte
  secret was readable in the dead frame after the call (SECRET 1, POS 1). Every
  entry point taking the scalar by value (`mul`, `mulBase`, `mulRistretto`,
  `mulRistrettoBase`) now copies it into a local and `defer`s `secureZero` on
  that copy; the three wrappers get their own wipe rather than relying on being
  inlined into `mul`, which would make the property a compiler's rather than
  the module's. Re-measured: SECRET 0 with POS still 1.
  `ecvrf` recorded the same defect from the other side — three surviving copies
  of its nonce, key algebraically recoverable — and concluded the fix belonged
  here. It does.
  Constant time unchanged: ctgrind still reports 2 contexts for `ct25519` and 3
  for `std`, so the wipe added no branch and was not elided.
  NO CONSUMER-VISIBLE CHANGE (same values, same signatures).

- **2026-08-10** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8032 §7.1's published test vectors.
- **2026-08-09** — New module: Constant-time-on-secrets scalar multiplication for
  Edwards25519 / Ristretto255.
