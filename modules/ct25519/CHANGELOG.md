# ct25519 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
