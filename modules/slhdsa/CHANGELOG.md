# slhdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** - Test-only, no production change: `fuzzVerify` had never looked at a
  signature's content. It opened `smith.bytes(&buf)` and then drew
  `smith.valueRangeAtMost(u32, 0, signature_length + 32)`; a ranged `Smith` draw reads eight
  octets as a little-endian `u64` and returns the range MINIMUM when fewer than eight
  remain, and `bytes` had already eaten them - so `len` was **0** on every input the
  ordinary lane ever ran, and `verify` returned false off its
  `sig.len != signature_length` guard every round. The "full structural-parse path" its own
  comment promises had never been entered. Now one `smith.slice(&buf)`, seeded from the
  module's own `sign` (an SLH-DSA signature that verifies is not reachable from arbitrary
  bytes) plus targeted corruptions of the randomizer, a FORS block and the last hypertree
  layer, and the two off-by-one lengths. Measured by the new `corpus:` guard: 6 non-empty
  seeds, **4 at exactly `signature_length`** and so past the guard and into the
  FORS/hypertree reconstruction (0 before), 1 accepted.

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on `liboqs` /
  `PQClean` SPHINCS+ (design reference, not a test anchor).
- **2026-07-11** — New module: SLH-DSA (FIPS 205, standardized SPHINCS+) post-quantum
  stateless hash-based signatures.
