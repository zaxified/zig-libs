# threshold_ecdsa

Pure-Zig GG20 threshold-ECDSA over secp256k1. **This module is now
end-to-end: Phase 2a (trusted-dealer keygen) + Phase 2b (ring-Pedersen aux
params + the semi-honest MtA core) + Phase 2c (MtA zero-knowledge range
proofs + MtAwc, IMPLEMENTED) + Phase 2d (online signing).** The arc: keygen
(2a) → aux-params/MtA (2b) → range proofs + MtAwc (2c) → threshold signing
(2d) → a standard secp256k1 ECDSA signature, verifiable under
`std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` against the group public key —
no threshold-aware verifier needed on the other end. Consumer: MPC custody
(an ECDSA key whose signing authority is split across `t`-of-`n` parties,
none of whom ever holds the whole key).

**Status:** keygen + aux-params + MtA + the Phase-2c zero-knowledge proofs
are all REAL and tested (`zig build test-threshold_ecdsa`: every Phase
2a/2b/2c test passes, no panics — see `SPEC.md` for the full breakdown).
**Phase 2d (`signing.zig`, this pass) is REAL end to end too:**
`signWithShares` runs the full GG20 online-signing protocol in-process over
a `t`-of-`n` `KeyShare` subset and produces a signature that genuinely
VERIFIES under `std`'s own ECDSA — its decisive test does not panic. The
one deliberate scope cut is GG20's identifiable-abort CULPRIT-NAMING
apparatus (see "Phase 2d" below and `signing.zig`'s module doc comment for
the exact boundary — the "abort-only v1" posture never returns a bad
signature, it just cannot say who caused an abort).

The Shamir-secret-sharing + Feldman-VSS + Lagrange-interpolation core
(`splitSecretKey`, `groupPublicKey`, `derivePublicKeyShare`,
`reconstructSecret`) and the Paillier-keygen wiring inside
`keygenTrustedDealer` are direct ports of this repo's already-KAT-validated
`frost`/`bls12_381.threshold` constructions onto `std.crypto.ecc.Secp256k1`.
`generateAuxParams` derives the ring-Pedersen auxiliary parameters
`(N_tilde, h1, h2)` via a real safe-prime search (p̃ = 2p'+1 with p' also
prime) — see its doc comment. `mta` (the
`mtaAliceInit`/`mtaBobResponse`/`mtaAliceFinalize` protocol, plus the
`*Checked` fail-closed variants) is the multiplicative→additive share
conversion: `α + β ≡ a·b (mod q)`, built on `paillier`'s homomorphic ops.

`zkproofs` (Phase 2c) is the GG18 Appendix A zero-knowledge layer that
upgrades MtA to malicious security: `RangeProof`/`MtaProof`/`MtaProofWc`
structs and byte codecs, a real SHA-256 Fiat-Shamir `Transcript` (binding
the verifier's aux params, the Paillier public key — modulus **and**
generator, audit F3 — every ciphertext/point, and every first-message
commitment; domain tags are at `v2` since the generator was added, a
deliberate BREAKING transcript revision, see `SPEC.md`), and the
`proveAliceRange`/`verifyAliceRange`/`proveBobMta`/`verifyBobMta`/
`proveBobMtaWc`/`verifyBobMtaWc` API — ALL REAL, verified against the actual
GG18 paper text (see `zkproofs.zig`'s module doc comment for the
verification-level caveats: self-consistency + the security-critical reject
paths, no cross-implementation KAT is possible for this proof family).

`signing` (Phase 2d, `signing.zig`) composes all of the above into
`signWithShares(allocator, shares, message, random) -> Signature`: samples
each party's `k_i`/`γ_i`, computes Lagrange-weighted `w_i`, runs a
commit-reveal + Schnorr proof of knowledge for each `Γ_i = γ_i·G`, runs the
REAL checked-MtA (for `k·γ`) and checked-MtAwc (for `k·x`, bound to each
party's public key share) over every ordered pair, reveals `δ = k·γ` to
derive `R = k⁻¹·G` and `r`, computes and sums each `s_i = m·k_i + r·σ_i`,
normalizes to low-S, and self-verifies the result under
`std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` before returning — never
returning an invalid signature. See `signing.zig`'s module doc comment for
the full phase-by-phase construction and its "Identifiable abort scope"
section for the one documented gap.

- **Model after:** R. Gennaro, S. Goldfeder, "One Round Threshold ECDSA with
  Identifiable Abort" (GG20, IACR ePrint 2020/540); GG18 (ePrint 2019/114)
  for the ring-Pedersen construction AND Appendix A's MtA zero-knowledge
  range proofs. This repo's own `frost` (`deriveInterpolatingValue`) and
  `bls12_381.threshold` (`evalPolynomialAt`/Feldman/Lagrange) modules for
  the Shamir+VSS shape, ported onto secp256k1's scalar field/group; `bip340`
  for the Fiat-Shamir challenge-reduction idiom `zkproofs.Transcript`/
  `signing.zig`'s commitment scheme reuse. `std.crypto.sign.ecdsa
  .EcdsaSecp256k1Sha256` is the FINAL verification target Phase 2d's output
  must satisfy.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant.
- **Deps:** `paillier` (each party's additively-homomorphic keypair),
  `montint` (`zkproofs.zig`'s constant-time Montgomery modexp over the
  ring-Pedersen commitments, wider than Paillier's own N²).

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

// 4. Sign: pick any t of the n KeyShares (the signing subset) and run the
//    Phase-2d online protocol in-process.
const signing = tecdsa.signing;
const subset = [_]tecdsa.KeyShare{ key_shares[0], key_shares[1] }; // any t
const sig = try signing.signWithShares(allocator, &subset, "message to sign", rng);

// The output is a STANDARD secp256k1 ECDSA signature:
const pk = try signing.ecdsa.PublicKey.fromSec1(&key_shares[0].group_public_key.toBytes());
try sig.verify("message to sign", pk); // std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256
```

See `src/root.zig` for the full keygen/MtA API — `splitSecretKey`/
`groupPublicKey`/`derivePublicKeyShare` are also exposed standalone (the
same Shamir+Feldman primitives `keygenTrustedDealer` composes), and
`reconstructSecret` is provided for tests/audit tooling only — see its doc
comment for why a real deployment never calls it. See `src/signing.zig` for
the full Phase-2d API (`signWithShares`, `lagrangeCoefficient`, the
`GammaCommitment`/`SchnorrProof`/`GammaReveal`/`DeltaShare`/`SigShare`
round-message types, and the `identifyAbortCulprit` stub).

## Backlog

- **Phase 2d identifiable abort (deferred — `signing.zig`'s
  `identifyAbortCulprit`, `@panic`-stubbed):** GG20's actual
  identifiable-abort apparatus (IACR ePrint 2020/540 §4) — when
  `signWithShares` returns `error.SigningAborted`, name EXACTLY which
  party's `k_i`/`γ_i`/`w_i` was used inconsistently across two different
  pairwise MtA sessions (a gap the per-pair range/MtA/MtAwc proofs alone do
  not close, since each attests to only ONE session's witness). This does
  NOT threaten the "never return a bad signature" invariant (the final
  self-check in `signWithShares` still catches any resulting bad `(r,s)`)
  — only ATTRIBUTION on abort. See `signing.zig`'s module doc comment
  ("Identifiable abort scope") for the precise boundary and what a full
  implementation needs (retained pairwise MtA transcripts + GG20's
  opening/decommitment sub-protocol).
- Phase 2d's Γ commit-reveal knowledge proof (`SchnorrProof`,
  `provePoK`/`verifyPoK`) is a standard textbook Fiat-Shamir Schnorr NIZK,
  NOT verified byte-for-byte against GG20's own `Πzk` instantiation (this
  scaffold pass did not have that section of the paper open) — functionally
  equivalent (proves knowledge of the same discrete log, same
  Fiat-Shamir-secure construction class) but flagged here for an
  independent check against the paper's exact parameterization.
- Full Pedersen-style distributed key generation (no single dealer ever
  learns the group secret key) — this module is trusted-dealer only.
- `generateAuxParams` aux-param-correctness ZK proof (Πprm/Πmod,
  `aux_proofs.zig`): **IMPLEMENTED** — struct/codec/Fiat-Shamir-transcript
  wiring, the trapdoor-retaining `generateAuxParamsWithTrapdoor`, AND the
  two proof cores (`Piprm`/`Pimod` `.prove`/`.verify`, CGGMP21 Fig.16/17)
  are all real and tested (`gate.aux_proofs_core_implemented` is `true`).
  **Closes audit F1's residual gap** (`AuxParams.validate`'s Jacobi check is
  necessary but not sufficient for quadratic residuosity): a crafted 3-prime
  `n_tilde` or an `h2 ∉ ⟨h1⟩` pair that both PASS `validate` are now REJECTED
  by `verifyWellFormed` — see `SPEC.md`'s "Πprm / Πmod" section. (Independent
  cryptographic review of the Fiat-Shamir instantiation before production
  MPC-custody use is still warranted, per the standing review debt below.)
- Independent cryptographic review of `zkproofs.zig`'s Phase-2c
  constructions against GG18 Appendix A before any production signing use
  (see `SPEC.md`'s verification-level section) — Phase 2d inherits this
  same residual audit debt, since it is built entirely on `zkproofs.zig`.
