# threshold_ecdsa

Pure-Zig GG20 threshold-ECDSA over secp256k1. **This module is Phase 2a of a
3-part arc: trusted-dealer keygen** (2a, this module) → MtA + range proofs
(2b) → threshold signing (2c). Consumer: MPC custody (an ECDSA key whose
signing authority is split across `t`-of-`n` parties, none of whom ever holds
the whole key).

**Status: scaffold.** The Shamir-secret-sharing + Feldman-VSS +
Lagrange-interpolation core (`splitSecretKey`, `groupPublicKey`,
`derivePublicKeyShare`, `reconstructSecret`) and the Paillier-keygen wiring
inside `keygenTrustedDealer` are REAL — direct ports of this repo's
already-KAT-validated `frost`/`bls12_381.threshold` constructions onto
`std.crypto.ecc.Secp256k1`. One piece is genuinely stubbed:
`generateAuxParams` (deriving the ring-Pedersen auxiliary parameters
Phase-2b/2c's zero-knowledge range proofs need) is real, non-mechanical
number theory — `@panic("TODO(core): ...")`, full construction in that
function's doc comment. `zig build test-threshold_ecdsa`: **9/10 tests pass**
in both Debug and ReleaseFast; the 10th (`generateAuxParams`'s own dedicated
test, deliberately last) panics by design — see SPEC.md.

- **Model after:** R. Gennaro, S. Goldfeder, "One Round Threshold ECDSA with
  Identifiable Abort" (GG20, IACR ePrint 2020/540); GG18 (ePrint 2019/114)
  for the ring-Pedersen construction. This repo's own `frost`
  (`deriveInterpolatingValue`) and `bls12_381.threshold`
  (`evalPolynomialAt`/Feldman/Lagrange) modules for the Shamir+VSS shape,
  ported onto secp256k1's scalar field/group.
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

// 3. Each party's ring-Pedersen aux params. generateAuxParams is STUBBED
//    today — see SPEC.md; callers must supply these themselves for now
//    (e.g. hand-constructed toy values for tests, as this module's own
//    tests do).
const aux_params: []const tecdsa.AuxParams = ...; // length n

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

- `generateAuxParams`: the ring-Pedersen number theory (safe-prime search +
  modexp) — see SPEC.md "Phase-2a boundary" and the function's own doc
  comment for the exact construction to transcribe.
- Phase 2b (separate later module): MtA (multiplicative-to-additive share
  conversion) + the GG20 zero-knowledge range proofs that consume
  `AuxParams`/`paillier` ciphertexts.
- Phase 2c (separate later module): the actual threshold-signing protocol.
- Full Pedersen-style distributed key generation (no single dealer ever
  learns the group secret key) — this module is trusted-dealer only.
