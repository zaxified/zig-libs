# bfv — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- The entropy seam is now typed instead of documented. **BREAKING:** the three
  production entry points that consume entropy — `keyGen`, `encrypt` and
  `genRelinKey` — take `io: std.Io` in place of `random: std.Random` and draw
  from `std.Io.random`, which std documents as a CSPRNG. The old signatures
  survive as `keyGenForTest` / `encryptForTest` / `genRelinKeyForTest` for the
  KATs (including the scripted-word test that pins which draws `keyGen` makes,
  in order) and the seeded end-to-end tests. A caller that was passing a real
  CSPRNG adapts by passing its `std.Io`; a caller that was passing
  `DefaultPrng` no longer compiles, which is the point.

  Why the parameter type and not a doc sentence: `std.Random` is a vtable, so
  `DefaultPrng.init(0).random()` is indistinguishable from a CSPRNG at the call
  site. With `u,e0,e1` predictable an attacker computes `c0 − p0·u − e0 = Δ·m`
  and recovers the plaintext **without the secret key** — encryption randomness
  is the whole of BFV's IND-CPA claim — while `genRelinKey` publishes an
  encryption of `s²` to the evaluator under masks the evaluator can reproduce.
  `std.Io` cannot be constructed from a seeded PRNG, so the degraded call stops
  being expressible. Two tests pin the shape: one reads the signatures at
  comptime, one shows the `std.Io` path actually draws (two keypairs, and two
  encryptions of the same plaintext, differ) and round-trips.
