# slhdsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **BREAKING, HIGH (dead stack):** key generation and signing left SK.seed and
  SK.prf on the dead stack, in library frames and in the caller's frame, because every
  secret crossed the API BY VALUE (`keyGenFromSeed(sk_seed, sk_prf, pk_seed) KeyPair`,
  `keyGen(seed)`, `sign`/`signInternal(…, sk: SecretKey, …)`, `SecretKey.fromBytes/toBytes`).
  New `src/stackprobe_test.zig` (ReleaseFast, 1 MiB window, needles = every 16-byte window of
  SK.seed and SK.prf, the SHA2 HMAC key blocks of PRF_msg and the WOTS+ chain-start secrets of
  the top-layer tree; negative control 0, positive control found), SHA2-128f/128s/192f/256f and
  SHAKE-128f/256s/256f, over keyGen, keyGenFromSeed, sign, signInternal (hedged),
  SecretKey.fromBytes/toBytes. **Before:** every call had residue, e.g. SHA2-128f keyGen SK.seed
  10 + SK.prf 5 windows over 5 calls (hits 95..559 B below the region top), sign 25 + 10
  (up to 2143 B), SHAKE-256s sign 60 + 20 (up to 17 KiB); dirty depth 4.5 KiB (SHA2-128f keyGen)
  to 25.9 KiB (SHAKE-256s sign). **After:** 0 everywhere. No WOTS+ or HMAC-block residue was
  found before or after (the F outputs and key blocks do not survive in these frames); the
  needle formula is checked against the engine by finding a recomputed chain-start secret in
  the signature it made. FORS leaf secrets are not recomputed (`SPEC.md` backlog).
  **API (BREAKING):** `keyGenFromSeed(out: *KeyPair, sk_seed, sk_prf, pk_seed: *const [n]u8)`,
  `keyGen(out: *KeyPair, seed: *const [3n]u8)`, `signInternal(out, msg, sk: *const SecretKey,
  addrnd)`, `sign(out, msg, sk: *const SecretKey, ctx, addrnd)`, `SecretKey.fromBytes(out:
  *SecretKey, bytes: *const [4n]u8)`, `SecretKey.toBytes(sk: *const SecretKey, out: *[4n]u8)`.
  `PublicKey` and `verify*` are unchanged. The bodies run one frame down and the stack they
  dirtied is zeroed (`src/burn.zig`: 24 KiB for keygen, 32 KiB for signing, sized from the
  measured depth — 17.2 KiB / 25.1 KiB for the deepest probed set, SHAKE-256s). Migration:
  `var kp: Scheme.KeyPair = undefined; Scheme.keyGen(&kp, &seed);` and `&kp.sk` at the
  `sign` call. No other module calls the changed functions (`x509` uses `verify` only).

- **2026-10-05** — Audit: first dated mutation run (11 mutants, all killed; `SPEC.md` § "Mutation
  run 2026-10-05"). No code or test change.

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
