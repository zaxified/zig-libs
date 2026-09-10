# ecvrf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — A1 fix campaign: `prove` now zeroes its own copy of the
  secret nonce `k` and `expandSecretKey`'s own dead-frame copy of `x`
  (E4, partial — residual copies of both remain, traced to std's own
  `scalar` arithmetic, out of this module's reach); five new
  `kat_test.zig` regressions close the untested half of `validateKey`
  (order-4/order-8 points, E3), add an existential-forgery check against
  a narrowed challenge comparison (E2), and pin `decodeProof`'s Gamma
  structural check against the two `catch unreachable`s downstream (E5);
  `SPEC.md` corrected — no `@panic` on a degenerate secret scalar/nonce
  since the move to `ct25519` (E11), and the constant-time table's
  "nine" secret-scalar multiplications corrected to five (E12);
  `proofToHash`'s doc comment now carries RFC 9381 §5.2's warning against
  calling it on unauthenticated `pi` (E13). No public API change. See
  `A1/ecvrf.md` for the full disposition, including what was found
  already fixed and what stays open.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9381 Appendix
  B.3's published test vectors.
- **2026-07-16** — New module: ECVRF-EDWARDS25519-SHA512-TAI — RFC 9381 Verifiable
  Random Function (suite_string `0x03`) over `std.crypto.ecc.Edwards25519` + SHA-512 — a
  VRF is the public-key analogue of a keyed hash.
