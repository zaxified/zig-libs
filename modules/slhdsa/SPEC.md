# slhdsa — spec

Design + threat notes for auditors. Usage: see ./README.md. Provenance:
clean-room from FIPS 205 (public standard, no `NOTICE` entry needed — see
README.md "Provenance").

## Design & invariants

**Spec:** NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard"
(August 2024) — the standardized SPHINCS+. Implemented: Algorithms 2/4
(toInt/base_2b), 5-8 (WOTS+), 9-11 (XMSS), 12-13 (hypertree), 14-17
(FORS), 18-20 (internal keygen/sign/verify), 22/24 (pure external
sign/verify with context), and **both §11 hash instantiations** over all
twelve Table 2 parameter sets:

- **§11.1 SHAKE:** F/H/T_l/PRF = SHAKE256(PK.seed ‖ ADRS ‖ …, 8n) with the
  full 32-byte ADRS; H_msg = SHAKE256(R ‖ PK.seed ‖ PK.root ‖ M, 8m);
  PRF_msg = SHAKE256(SK.prf ‖ opt_rand ‖ M, 8n).
- **§11.2 SHA2:** compressed 22-byte ADRS; F/PRF =
  Trunc_n(SHA-256(PK.seed ‖ toByte(0, 64−n) ‖ ADRS_c ‖ …)) at **every**
  category; category 1 uses SHA-256 for H/T_l (block-padded to 64),
  MGF1-SHA-256 for H_msg and HMAC-SHA-256 for PRF_msg; categories 3/5 use
  SHA-512 for H/T_l (block-padded to 128), MGF1-SHA-512 and HMAC-SHA-512.

The engine is comptime-generic (`SlhDsa(params.Params)`); the tweakable-hash
context (`Thash`) is comptime-selected by `Params.hash`, so the same
WOTS+/XMSS/hypertree/FORS code serves all twelve sets.

- **KAT-verified against the official NIST oracle, per parameter set.**
  Byte-exact vectors from the NIST ACVP gen-val JSON
  (`SLH-DSA-keyGen-FIPS205` + `SLH-DSA-sigGen-FIPS205`,
  `internalProjection.json`): for **each of the twelve sets** one keyGen
  case (seeds → pk/sk) and one deterministic internal sigGen case
  (sk + message → full signature, then verified); for SHA2-128f
  additionally a hedged internal case (explicit additionalRandomness) and
  a pure external case with a 110-byte context. A single wrong bit
  anywhere in the ADRS handling, hash instantiation (incl. the SHA-256 vs
  SHA-512 split and the SHAKE full-ADRS path), WOTS+/XMSS/FORS structure
  or index arithmetic changes the multi-kilobyte signature, so
  byte-exactness across all twelve sets exercises the entire construction
  at every n/h/d/a/k combination. Exact tgId/tcIds in
  `src/kat_vectors.zig`; tests in `src/kat_test.zig`.
- **No new cryptographic primitive.** Everything reduces to std.crypto's
  SHA-256/SHA-512, HMAC over them, and SHAKE256. The only original code is
  FIPS 205's own structure (addresses, chains, trees, index arithmetic).
  The one deviation from the naive spec text is the standard midstate
  optimization: PK.seed ‖ toByte(0, block−n) is exactly one compression
  block for the SHA-2 hashes, absorbed once per keygen/sign/verify and the
  midstate copied per hash call (for SHAKE the sponge state after
  absorbing PK.seed is copied the same way) — an implementation of the
  same function, covered by the KATs.
- **Malformed input → `false`/typed error, never a panic.** `verify`
  length-checks the signature (exact `signature_length`) and context
  (≤ 255) before any indexing; everything after is fixed-size. `sign`
  returns `error.ContextTooLong` for a context over 255 bytes. Message
  bytes are only ever streamed into hashes. Verified in Debug AND
  ReleaseFast (`zig build test-slhdsa -Doptimize=ReleaseFast`) so
  illegal-behavior checks ran over the whole KAT battery.
- **Statelessness is the scheme's own property** — no key state to update
  after signing (unlike XMSS/LMS), so the API is plain value types and
  `meta.concurrency = .reentrant` holds trivially.
- **Comptime parameterization.** `params.Params` carries every Table 2
  knob; `Params.validate()` compile-time-checks the internal relations
  (n ∈ {16, 24, 32}, h = h'·d, m = its three digest slices, tree index
  ≤ 64 bits, lg_w = 4).

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
- **Out of scope this pass:** HashSLH-DSA pre-hash variants (§10.2.2) and
  streaming/incremental signing APIs. The `keyGen`/`sign` seeds/randomness
  are caller-supplied by design (std 0.16 removed `std.crypto.random`).
- **Signature size is inherent:** 7 856 B (128s) up to 49 856 B (256f) per
  signature — see the size table in README.md. Protocol designs that
  cannot carry that should pick a different scheme; within SLH-DSA the
  "s" sets trade much slower signing for the smallest signatures.

## Verification

- `zig build test-slhdsa`: NIST ACVP KATs for all twelve
  parameter sets (keyGen + deterministic-internal sigGen each, byte-exact;
  128f also hedged-internal + pure-with-context), WOTS+/XMSS/FORS
  component round-trips (SHA2 cat-1 + SHAKE + SHA2 cat-3 hashes),
  base_2b/ADRS bit-layout unit tests (incl. the 12/14-bit FORS digits),
  Table 2 derived-length checks for every set, keygen→sign→verify
  round-trips (SHA2 + SHAKE), tamper battery (bit flips in R/FORS/HT
  regions, wrong message, wrong context, wrong key, wrong lengths,
  oversized context), hedged ≠ deterministic. Green in Debug and
  ReleaseFast.
- Oracle: NIST ACVP gen-val vectors (github.com/usnistgov/ACVP-Server,
  `gen-val/json-files/`, retrieved 2026-07-11) — the same corpus NIST uses
  for FIPS 205 validation testing.
