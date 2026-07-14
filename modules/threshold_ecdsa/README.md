# threshold_ecdsa

Pure-Zig GG20 threshold-ECDSA over secp256k1. **This module covers Phase 2a
(trusted-dealer keygen) + Phase 2b (ring-Pedersen aux params + the
semi-honest MtA core) + Phase 2c SCAFFOLD (MtA zero-knowledge range
proofs)** of the arc: keygen (2a) → aux-params/MtA (2b) → range proofs +
MtAwc (2c) → threshold signing (2d). Consumer: MPC custody (an ECDSA key
whose signing authority is split across `t`-of-`n` parties, none of whom
ever holds the whole key).

**Status: keygen + aux-params + MtA implemented; Phase 2c is a SCAFFOLD
(structs/transcript/wiring real, prove/verify math `@panic`-stubbed).** The
Shamir-secret-sharing + Feldman-VSS + Lagrange-interpolation core
(`splitSecretKey`, `groupPublicKey`, `derivePublicKeyShare`,
`reconstructSecret`) and the Paillier-keygen wiring inside
`keygenTrustedDealer` are direct ports of this repo's already-KAT-validated
`frost`/`bls12_381.threshold` constructions onto `std.crypto.ecc.Secp256k1`.
`generateAuxParams` derives the ring-Pedersen auxiliary parameters
`(N_tilde, h1, h2)` via a real safe-prime search (p̃ = 2p'+1 with p' also
prime) — see its doc comment. `mta` (the
`mtaAliceInit`/`mtaBobResponse`/`mtaAliceFinalize` protocol) is the
semi-honest multiplicative→additive share conversion: `α + β ≡ a·b (mod q)`,
built on `paillier`'s homomorphic ops.

`zkproofs` (Phase 2c) adds the GG18 Appendix A zero-knowledge proofs that
upgrade MtA to malicious security: `RangeProof`/`MtaProof`/`MtaProofWc`
structs and byte codecs, a real SHA-256 Fiat-Shamir `Transcript`, and the
`proveAliceRange`/`verifyAliceRange`/`proveBobMta`/`verifyBobMta`/
`proveBobMtaWc`/`verifyBobMtaWc` API — all REAL except the actual Sigma-
protocol number theory inside those six prove/verify functions, which is
`@panic("TODO(core): ...")` with the full construction transcribed in each
doc comment. `mta.zig` gained the matching **fail-closed** checked path:
`mtaAliceInitChecked`/`mtaBobResponseChecked` (real Paillier-primitive
composition, retaining the witnesses the proofs need) and
`mtaAliceFinalizeChecked` (real verify-then-decrypt control flow, calling
the still-stubbed `zkproofs.verifyBobMta`). The Phase-2b semi-honest
functions are unchanged and remain fully usable on their own.

`zig build test-threshold_ecdsa`: **23/30 tests pass, 7 intentionally
`@panic`** (both Debug and ReleaseFast) — every Phase-2a/2b test plus every
REAL Phase-2c piece (Transcript determinism/domain-separation, all three
proof structs' byte-codec round-trips, the checked-MtA composition/
correctness tests) passes; the 7 crashes are exactly the tests that call
into the six stubbed prove/verify functions (documented "honest accept"/
"reject" tests — see `zkproofs.zig`), left `@panic`ing on purpose per this
module's Phase-2c scaffold precedent (`SPEC.md`).

**Not yet (later phases):** the Phase-2c prove/verify NUMBER THEORY itself
(see `zkproofs.zig`'s module doc comment for exactly what a Fable pass must
implement, with GG18 Appendix A citations), and the threshold signing
rounds (Phase 2d).

- **Model after:** R. Gennaro, S. Goldfeder, "One Round Threshold ECDSA with
  Identifiable Abort" (GG20, IACR ePrint 2020/540); GG18 (ePrint 2019/114)
  for the ring-Pedersen construction AND Appendix A's MtA zero-knowledge
  range proofs. This repo's own `frost` (`deriveInterpolatingValue`) and
  `bls12_381.threshold` (`evalPolynomialAt`/Feldman/Lagrange) modules for
  the Shamir+VSS shape, ported onto secp256k1's scalar field/group; `bip340`
  for the Fiat-Shamir challenge-reduction idiom `zkproofs.Transcript` reuses.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant.
- **Deps:** `paillier` (each party's additively-homomorphic keypair).

## Provenance

Clean-room from the public GG18/GG20 papers (not copyrightable works — see
`CONVENTIONS.md` §5) plus this repo's own prior `frost`/`bls12_381.threshold`
modules (same authorship, ported not copied). See `NOTICE`.

## API

```zig
const tecdsa = @import("threshold_ecdsa");
const paillier = @import("paillier");

// 1. Shamir-split the group secret key (dealer-side; secret_key/coefficients
//    are normally drawn fresh via Scalar.random(io) — fixed here for
//    illustration).
const secret_key: tecdsa.Scalar = ...;
const coefficients: []const tecdsa.Scalar = ...; // length t-1

// 2. Each party's own Paillier keypair (paillier.generate for a real
//    deployment; paillier.fromPrimes for reproducible KATs).
const paillier_keys: []const paillier.KeyPair = ...; // length n

// 3. Each party's ring-Pedersen aux params, from generateAuxParams
//    (per-party; slow safe-prime search — use aux_modulus_bits in
//    production). Kept caller-supplied so keygen doesn't pay for the search.
const aux_params: []const tecdsa.AuxParams = ...; // length n
// e.g.: for each party i: aux_params[i] = tecdsa.generateAuxParams(rng, tecdsa.aux_modulus_bits);

const key_shares = try tecdsa.keygenTrustedDealer(
    allocator, t, n, secret_key, coefficients, paillier_keys, aux_params,
);
// key_shares[0].public_keys.entries is shared across every key_shares[i] —
// free it ONCE, then free key_shares itself. See KeyShare's doc comment.
defer allocator.free(key_shares);
defer allocator.free(key_shares[0].public_keys.entries);

// Each party ends up with:
const share = key_shares[0];
share.secret_share;      // x_i (SECRET)
share.group_public_key;  // X = x*G (PUBLIC)
share.verifying_share;   // X_i = x_i*G (PUBLIC, Feldman-consistent)
share.paillier_secret;   // this party's own Paillier secret key (SECRET)
share.public_keys;       // every party's Paillier pubkey + aux params (PUBLIC)
```

See `src/root.zig` for the full API — `splitSecretKey`/`groupPublicKey`/
`derivePublicKeyShare` are also exposed standalone (the same Shamir+Feldman
primitives `keygenTrustedDealer` composes), and `reconstructSecret` is
provided for tests/audit tooling only — see its doc comment for why a real
deployment never calls it.

## Backlog

- **Phase 2c (in progress — SCAFFOLDED, math not yet implemented):**
  `zkproofs.zig`'s six `@panic("TODO(core): ...")` prove/verify functions
  (`proveAliceRange`/`verifyAliceRange`, `proveBobMta`/`verifyBobMta`,
  `proveBobMtaWc`/`verifyBobMtaWc`) — the actual GG18 Appendix A Sigma-
  protocol number theory. See that file's module doc comment for the full
  status, the exact construction each stub's doc comment transcribes (NOT
  verified byte-for-byte against the paper — flagged `TODO(core)`), and the
  specific gaps (chiefly: the exact range bounds, deliberately not guessed).
- Phase 2c also has an open design question, noted in `SPEC.md`: whether
  GG18/GG20 truly reuse `MtaProof`'s exponent-mask `alpha`/response `s1` for
  `MtaProofWc`'s EC Schnorr commitment `u1_point`/check, or define a
  distinct EC-only mask — this scaffold assumes the reuse (the standard
  "prove once, use for both" economy) but it needs confirming against the
  paper.
- Phase 2d: the actual threshold-signing protocol (the interactive rounds
  that turn a message + `KeyShare`s + checked-MtA outputs into one ECDSA
  signature) — including pinning down exactly where plain MtA vs MtAwc is
  invoked (see `SPEC.md`'s Phase-2c/2d boundary note).
- Full Pedersen-style distributed key generation (no single dealer ever
  learns the group secret key) — this module is trusted-dealer only.
- `generateAuxParams` aux-param-correctness ZK proof (Πprm/Πmod): if a later
  variant broadcasts a proof that `h2 = h1^lambda`, retain `lambda` at setup
  (`generateAuxParamsInternal` already returns it) instead of discarding.
