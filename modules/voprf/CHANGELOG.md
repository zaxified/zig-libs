# voprf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **Breaking:** `blindEvaluateVerifiableBatch` and
  `blindEvaluatePoprfBatch` gained `error.EmptyBatch` and
  `error.MismatchedLengths` in their respective error sets. Both used to
  guard `blinded.len >= 1 and evaluated_out.len == blinded.len` with
  `std.debug.assert`, then feed both caller-supplied slices to a
  `for (blinded, evaluated_out)` loop. ReleaseFast compiles the assert AND
  the loop's own runtime length-match check out together, so a mismatched
  `evaluated_out` read or wrote past its own bounds in the build that ships.
  Found by an audit sweep for this shape.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9497 Appendix
  A.1's published test vectors.
- **2026-07-12** — New module: (V)OPRF — Oblivious Pseudorandom Functions (RFC 9497),
  ristretto255-SHA-512 ciphersuite, all three modes: OPRF (base), VOPRF (verifiable) +
  POPRF (partially-oblivious).
