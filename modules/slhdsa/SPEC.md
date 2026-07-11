# slhdsa — spec

Design + threat notes for auditors. Usage: see ./README.md. Provenance:
clean-room from FIPS 205 (public standard, no `NOTICE` entry needed — see
README.md "Provenance").

## Design & invariants

**Spec:** NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard"
(August 2024) — the standardized SPHINCS+. Implemented: Algorithms 2/4
(toInt/base_2b), 5-8 (WOTS+), 9-11 (XMSS), 12-13 (hypertree), 14-17
(FORS), 18-20 (internal keygen/sign/verify), 22/24 (pure external
sign/verify with context), and the §11.2 SHA2 security-category-1
instantiations (H_msg = MGF1-SHA-256 over SHA-256; PRF/F/H/T_l =
Trunc_16(SHA-256(PK.seed ‖ 0^48 ‖ ADRS_c ‖ …)); PRF_msg = HMAC-SHA-256;
compressed 22-byte ADRS). One parameter set: **SLH-DSA-SHA2-128f**
(n 16, h 66, d 22, h' 3, a 6, k 33, lg_w 4, m 34).

- **KAT-verified against the official NIST oracle.** Byte-exact vectors
  from the NIST ACVP gen-val JSON (`SLH-DSA-keyGen-FIPS205` +
  `SLH-DSA-sigGen-FIPS205`, `internalProjection.json`): keyGen (seeds →
  pk/sk), deterministic internal sigGen, hedged internal sigGen (explicit
  additionalRandomness), and pure external sigGen with a 110-byte context.
  A single wrong bit anywhere in the ADRS handling, hash instantiation,
  WOTS+/XMSS/FORS structure or index arithmetic changes the 17 088-byte
  signature, so byte-exactness over these four cases exercises the entire
  construction. Exact tcIds in `src/kat_vectors.zig`; tests in
  `src/kat_test.zig`.
- **No new cryptographic primitive.** Everything reduces to
  `std.crypto.hash.sha2.Sha256` / `std.crypto.auth.hmac.sha2.HmacSha256`.
  The only original code is FIPS 205's own structure (addresses, chains,
  trees, index arithmetic). The one deviation from the naive spec text is
  the standard SHA2 midstate optimization: PK.seed ‖ toByte(0, 48) is
  exactly one SHA-256 block, absorbed once per keygen/sign/verify and the
  midstate copied per hash call — an implementation of the same function,
  covered by the KATs.
- **Malformed input → `false`/typed error, never a panic.** `verify`
  length-checks the signature (exact 17 088) and context (≤ 255) before any
  indexing; everything after is fixed-size. `sign` returns
  `error.ContextTooLong` for a context over 255 bytes. Message bytes are
  only ever streamed into hashes. Verified in Debug AND ReleaseFast
  (`zig build test-slhdsa -Doptimize=ReleaseFast`) so illegal-behavior
  checks ran over the whole KAT battery.
- **Statelessness is the scheme's own property** — no key state to update
  after signing (unlike XMSS/LMS), so the API is plain value types and
  `meta.concurrency = .reentrant` holds trivially.
- **Comptime parameterization.** `params.Params` carries every Table 2
  knob; `Params.validate()` compile-time-checks the internal relations
  (h = h'·d, m = its three digest slices, tree index ≤ 64 bits) and
  `engine.SlhDsa` compile-errors on any not-yet-implemented hash
  instantiation rather than silently mis-signing.

## Threat model / out of scope

- **Signing is not constant-time hardened.** Verification is public-input;
  for signing, hash-based schemes have no secret-dependent branching in
  the structure itself (chain lengths derive from the public digest), but
  no systematic side-channel review was done. Secret keys are not zeroized
  on drop — callers with a real key-hygiene requirement must
  `std.crypto.secureZero` their copies.
- **Deterministic vs hedged signing:** `addrnd = null` is the FIPS 205
  deterministic variant (opt_rand = PK.seed). FIPS 205 recommends hedged
  signing where randomness is available (fault-attack + multi-target
  resistance); callers supply the n random bytes — this module never
  reaches for OS entropy itself.
- **Out of scope this pass:** the other eleven parameter sets (SHAKE
  instantiation, SHA2 categories 3/5 with their SHA-512 H_msg/PRF_msg),
  HashSLH-DSA pre-hash variants (§10.2.2), and streaming/incremental
  signing APIs. The `keyGen`/`sign` seeds/randomness are caller-supplied
  by design (std 0.16 removed `std.crypto.random`).
- **Signature size is inherent:** 17 088 B per signature at 128f. Protocol
  designs that cannot carry that should pick a different scheme (or the
  128s set once implemented — 7 856 B, slower signing).

## Verification

- `zig build test-slhdsa` — 18 tests: NIST ACVP KATs (4 byte-exact cases),
  WOTS+/XMSS/FORS component round-trips, base_2b/ADRS bit-layout unit
  tests, Table 2 derived-length checks, keygen→sign→verify round-trip,
  tamper battery (bit flips in R/FORS/HT regions, wrong message, wrong
  context, wrong key, wrong lengths, oversized context), hedged ≠
  deterministic. Green in Debug and ReleaseFast.
- Oracle: NIST ACVP gen-val vectors (github.com/usnistgov/ACVP-Server,
  `gen-val/json-files/`, retrieved 2026-07-11) — the same corpus NIST uses
  for FIPS 205 validation testing.
