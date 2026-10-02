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

**Status:** every signer can run in its own process. `presign.Party` is
GG20 signing as one state machine per signer (§3.2): six message-in /
message-out rounds give a `Presignature`, and a message is then signed in ONE
round. Every check of the paper is made — including the Phase 5/6 sums
(`Σ R̄_j = G`, `Σ S_j = X`) that make releasing a signature share safe — and
an abort names the culprit for every fault GG20 §4.2 can attribute without
its opening protocol (all but types 5 and 7). `signing.signWithShares` drives
the same state machines in-process. Keygen is trusted-dealer only. Key
material interoperates with bnb-chain/tss-lib v3.0.0 in both directions
(`tools/tsslib`, `src/tsslib_interop.zig`). Not independently audited.

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

`presign` (`presign.zig`) composes all of the above into GG20 signing per
signer: Phase 1 broadcasts a Γ commitment and `Enc(k_i)` with range proofs,
Phase 2 runs MtA (`k·γ`) and MtAwc (`k·x`, bound to each signer's public
`W_j = λ_j·X_j`) per pair, Phase 3 publishes `δ_i` and a Pedersen commitment
`T_i` to `σ_i`, Phase 4 opens `Γ_i`, Phase 5 publishes `R̄_i = k_i·R` with a
proof that it matches `Enc(k_i)` and checks `Σ R̄_j = G`, Phase 6 publishes
`S_i = σ_i·R` with a proof that it matches `T_i` and checks `Σ S_j = X`.
Phase 7 (`signShare`/`combine`) is the online round. `ecproofs` holds the
curve-only proofs of §3.3. See `SPEC.md` "Signing" for the round table and
the caller's duties (authenticated reliable broadcast, a fresh session id,
timeouts, one presignature per message).

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

Test data: `src/tsslib_vectors.zig` is generated by `tools/tsslib` (README
there) from bnb-chain/tss-lib v3.0.0 (MIT), run as a black box — key material
from tss-lib's own keygen and the signatures tss-lib made, plus this module's
own key material and the signatures tss-lib made after importing it. Throwaway
test keys; no tss-lib code is part of the module.

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

// 4a. One process per signer: each signer runs its own Party; the caller's
//     transport delivers each Outgoing (to == null: broadcast) and hands the
//     received bytes to the next `advance`.
const presign = tecdsa.presign;
const sid: presign.SessionId = ...; // fresh per session, agreed by all signers
var party = try presign.Party.init(allocator, my_share, &.{ 1, 3 }, sid);
defer party.deinit();
var inbox: []const []const u8 = &.{};
for (0..6) |_| {
    const out = try party.advance(inbox, rng); // error.ProtocolAbort: see party.abort
    defer out.deinit(allocator);
    send(out.messages);
    inbox = receive(); // every message addressed to this party for this round
}
var presig = try party.finish(inbox);
defer presig.deinit();
// ... later, when the message is known (one round):
const share_msg = try presig.signShare(.{ .bytes = "message to sign" });
var abort: ?presign.Abort = null;
const sig = try presig.public.combine(.{ .bytes = "message to sign" }, all_shares, &abort);

// 4b. Or, with every share in one process, the same protocol in a loop:
const signing = tecdsa.signing;
const subset = [_]tecdsa.KeyShare{ key_shares[0], key_shares[1] }; // any t
const sig2 = try signing.signWithShares(allocator, &subset, "message to sign", rng);

// The output is a STANDARD secp256k1 ECDSA signature:
const pk = try signing.ecdsa.PublicKey.fromSec1(&key_shares[0].group_public_key.toBytes());
try sig2.verify("message to sign", pk); // std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256
```

See `src/root.zig` for the full keygen/MtA API — `splitSecretKey`/
`groupPublicKey`/`derivePublicKeyShare` are also exposed standalone (the
same Shamir+Feldman primitives `keygenTrustedDealer` composes), and
`reconstructSecret` is provided for tests/audit tooling only — see its doc
comment for why a real deployment never calls it. See `src/signing.zig` for
the in-process driver (`signWithShares`, `lagrangeCoefficient`) and
`src/presign.zig` for the per-signer state machine.

## Backlog

See `SPEC.md` "Backlog / deferred": dealer-free keygen together with
Πmod/Πfac proofs for every party's Paillier key (the BitForge class, which
arises once parties generate their own Paillier keys), attribution of GG20
abort types 5 and 7 (§4.3 opening protocol), presignature serialisation,
an echo-broadcast round, key refresh, and an independent cryptographic
review (`SPEC.md` "Auditor brief", A1–A9).
