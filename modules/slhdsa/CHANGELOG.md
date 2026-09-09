# slhdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, taking `SK.seed` and `SK.prf` separately through `SlhDsaSha2_128f.sign()`. Measured ReleaseFast: **4 in-file contexts for `seed`, 8 for `prf`**, untainted control 0 and no-`-fvalgrind` trap 0 in every row. ⭐ Non-zero, and it does NOT contradict `SPEC.md:69-72`'s "chain lengths derive from the public digest" carve-out: every context is a branch over a WOTS+ chain length (`engine.zig:296`) or an auth-path index parity bit (`engine.zig:424`, `:539`), i.e. over values a verifier recomputes from the published signature. A binary taint cannot tell those apart from a branch on a secret byte, which is why the per-line attribution — not the total — is what this row is for.

- **2026-09-09** — The module has a `NOTICE` for the first time. `src/kat_vectors.zig` carries
  NIST's ACVP known-answer vectors for all twelve SLH-DSA parameter sets, and the provenance
  was recorded only in that file's doc comment — right place for it, but a reader asking "what
  does this module owe?" had nothing to open. It owes nothing: these are the validation
  vectors of a U.S. federal standard, a work of the United States Government not subject to
  copyright there (17 U.S.C. §105), the same position `modules/ctap2pin/NOTICE` already takes
  for NIST SP 800-38A. Recorded as a provenance note, with the one thing not re-verified in
  this pass (the ACVP-Server repository's own licence file) stated rather than assumed.

- **2026-09-07** — Test-only, no production change: `fuzzVerify` had never looked at a
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
