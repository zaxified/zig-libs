# ecvrf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-14** — **BEHAVIOURAL + NEW API:** A1 E14, E16, E10 (KeyPair half), E4 (documented).
  E14/E16: `string_to_point` now decodes strictly per RFC 8032 §5.1.3 (new `stringToPoint`):
  a `Gamma` or public key with `y >= p`, or with a sign bit on a point whose `x` is 0, is refused
  (`error.InvalidProof` / `error.InvalidPublicKey`); `std`'s `fromBytes` had accepted both as a
  second spelling of an existing point. Used for the TAI candidate too. `verify` hashes
  `point_to_string(Gamma)` as RFC 9381 §5.3 step 10 writes it — byte-identical to the input after
  strict decoding, so honest proofs verify exactly as before.
  E10: new `KeyPair.fromSecretKey` / `KeyPair.prove` derive the public key once; measured
  ReleaseFast median 228 380 → 176 229 ns per proof (−22.8 %), same bytes on every RFC 9381 vector.
  The precomputed-base half of E10 (`ct25519`) is left to the campaign's performance pass.
  E4: `prove`'s secrets now reach its steps by pointer and the SHA-512 states that absorb `sk` and
  the prefix are wiped; the dead-stack probe (ReleaseFast) went from `x=3 k=1 sk=0` to
  `x=0 k=1 sk=1`. The remainder lives in `std` and is documented in SPEC as a known limitation
  (owner's decision: no std patch); every remaining copy still recovers the key.

- **2026-09-10** — **NO CONSUMER-VISIBLE CHANGE:** `verify`'s last step used
  to call `proofToHash(pi)`, which re-decoded `pi` (re-checking `s`'s
  canonicity and re-parsing `Gamma`'s point encoding) purely to reach the
  hash tail `verify` had already done that work for a few lines above.
  Factored the tail into a private `hashOutputFromGamma`, called from both
  `proofToHash` (after its own `decodeProof`) and `verify` (with the
  `gamma_point` it already has). Same bytes out, bit-for-bit (existing
  round-trip test unchanged, still passes). Measured (ReleaseFast, 400
  iters): 167,788 ns/op after vs. 182,163 ns/op with the old re-decode
  restored, +8.6% (A1 E10 point 3; points 1-2 — a `KeyPair`-shaped `prove`
  API and a precomputed base in `ct25519` — remain open, real API
  decisions).
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
