# threshold_ecdsa

Pure-Zig GG20 threshold-ECDSA over secp256k1. **This module covers Phase 2a
(trusted-dealer keygen) + Phase 2b (ring-Pedersen aux params + the
semi-honest MtA core)** of the arc: keygen (2a) → aux-params/MtA (2b) → range
proofs + MtAwc (2c) → threshold signing (2d). Consumer: MPC custody (an ECDSA
key whose signing authority is split across `t`-of-`n` parties, none of whom
ever holds the whole key).

**Status: keygen + aux-params + MtA implemented.** The Shamir-secret-sharing
+ Feldman-VSS + Lagrange-interpolation core (`splitSecretKey`,
`groupPublicKey`, `derivePublicKeyShare`, `reconstructSecret`) and the
Paillier-keygen wiring inside `keygenTrustedDealer` are direct ports of this
repo's already-KAT-validated `frost`/`bls12_381.threshold` constructions onto
`std.crypto.ecc.Secp256k1`. `generateAuxParams` derives the ring-Pedersen
auxiliary parameters `(N_tilde, h1, h2)` via a real safe-prime search
(p̃ = 2p'+1 with p' also prime) — see its doc comment. `mta` (the
`mtaAliceInit`/`mtaBobResponse`/`mtaAliceFinalize` protocol) is the
semi-honest multiplicative→additive share conversion: `α + β ≡ a·b (mod q)`,
built on `paillier`'s homomorphic ops. `zig build test-threshold_ecdsa`:
**14/14 tests pass** in both Debug and ReleaseFast (correctness net =
`α+β = a·b` over many random inputs + edge cases + a real-keygen composition;
`generateAuxParams` well-formedness incl. `h2 = h1^lambda`).

**Not yet (later phases):** the GG20 zero-knowledge range proofs / MtAwc
check that make MtA secure against a *malicious* party (Phase 2c — they
consume `AuxParams` as their Pedersen commitment base), and the threshold
signing rounds (Phase 2d). The MtA core here is correct but **semi-honest
only**.

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

- Phase 2c: the GG20 zero-knowledge range proofs + MtAwc check that upgrade
  the semi-honest `mta` core to malicious security (they consume `AuxParams`
  as their Pedersen commitment base). See `mta.zig`'s `TODO(2c)` notes.
- Phase 2d: the actual threshold-signing protocol (the interactive rounds
  that turn a message + `KeyShare`s + MtA outputs into one ECDSA signature).
- Full Pedersen-style distributed key generation (no single dealer ever
  learns the group secret key) — this module is trusted-dealer only.
- `generateAuxParams` aux-param-correctness ZK proof (Πprm/Πmod): if a later
  variant broadcasts a proof that `h2 = h1^lambda`, retain `lambda` at setup
  (`generateAuxParamsInternal` already returns it) instead of discarding.
