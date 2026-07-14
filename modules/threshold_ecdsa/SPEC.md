# threshold_ecdsa — spec

Design + threat notes for auditors. Usage: see ./README.md.
Attribution/provenance: see ./README.md "Provenance" + ./NOTICE.

## Design & invariants

**Phase 2a (trusted-dealer keygen) + Phase 2b (ring-Pedersen aux params +
the semi-honest MtA core) of the GG20 threshold-ECDSA arc** (2a keygen → 2b
aux-params/MtA → 2c range proofs + MtAwc → 2d signing), over secp256k1
(`std.crypto.ecc.Secp256k1`, scalar field `Scalar` = Zq for q the group
order).

**Trusted-dealer model ONLY.** A single dealer holds the plaintext group
ECDSA secret key `x`, Shamir-splits it into `n` shares (degree-`(t-1)`
polynomial `f`, `f(0) = x`) via `splitSecretKey`, and distributes one share
to each party out-of-band, alongside a Feldman VSS commitment so every party
can verify its own share against the dealer's claim. The dealer sees, and
could retain, the whole secret key — exactly the same scope limitation this
repo's `bls12_381.threshold` and `frost.trustedDealerKeygen` document for
their own trusted-dealer paths. A full Pedersen-style DKG (interactive
complaint/justification sub-protocol, no single party ever learns `x`) is
explicitly OUT OF SCOPE — a distinct follow-up module, not merely a
different `splitSecretKey` signature.

**What's implemented (all REAL, `zig build test-threshold_ecdsa`: 14/14 in
Debug and ReleaseFast):**

- **Keygen core** — `Element` (SEC1-compressed secp256k1 point codec),
  `scalarFromIndex`/`evalPolynomialAt` (Shamir, Horner's method over Zq),
  `splitSecretKey` (Shamir + Feldman VSS assembly), `groupPublicKey`/
  `derivePublicKeyShare` (Feldman evaluation-in-the-exponent),
  `reconstructSecret` (Lagrange interpolation at x=0 — test/audit use
  only, see "Threat model" below), `FeldmanCommitments`/`AuxParams`/
  `PublicKeys`/`KeyShare`'s structs and byte codecs, and
  `keygenTrustedDealer`'s composition. Each is either mechanical plumbing
  or a direct, field/group-swapped port of this repo's own already-KAT-
  validated `frost.deriveInterpolatingValue`/`bls12_381.threshold
  .evalPolynomialAt`/`feldmanCommitCoefficient`/`derivePublicKeyShare`/
  `combineSignatures` constructions.
- **Ring-Pedersen aux params** — `generateAuxParams`: a real safe-prime
  search (p̃ = 2p'+1 with p' also prime, `generateSafePrime` — the
  paillier/rsa probable-prime shape + an extra Miller-Rabin pass on
  (candidate-1)/2 and a p̃ ≡ 3 (mod 4) filter), `N_tilde = p̃·q̃`, a random
  quadratic residue `h1 = r²`, a secret exponent `lambda ← [1, p'·q')`, and
  `h2 = h1^lambda mod N_tilde`. `lambda` is DISCARDED (the tuple's owner is a
  proof *verifier*, not a prover under its own `N_tilde`; see the function's
  doc comment for the retention decision + the Πprm `TODO(2c)`).
- **MtA (`mta.zig`)** — the semi-honest multiplicative→additive share
  conversion (`mtaAliceInit`/`mtaBobResponse`/`mtaAliceFinalize`), literally
  `paillier.mulPlaintext`+`addPlaintext`+`decrypt` composed. Correctness net:
  `α + β ≡ a·b (mod q)` over many random `(a,b)` + edge cases (`0`/`1`/`q-1`)
  + a real-`keygenTrustedDealer` composition test.

**Design decision: `keygenTrustedDealer` takes `aux_params` as
CALLER-SUPPLIED, not self-generated.** A caller generates each party's tuple
with `generateAuxParams` (a comparatively slow safe-prime search) and passes
the slice in, so the keygen path never pays for the search and the two
concerns test independently. A production caller obtains real `AuxParams`
from `generateAuxParams(rng, aux_modulus_bits)`; the serialization tests use
small non-secure hand-constructed values (`toyAuxParams()`) purely to
exercise the struct/codec.

**β sign convention + Z_N→Zq reduction (MtA).** Bob's additive share is
`β = −β' (mod q)` — the negation of the plaintext blinding `β'` he folds into
`c_B = Enc_A(a·b + β')`; Alice's `α` decrypts `a·b + β'`, so the `±β'` cancel.
Alice's decryption `α'` is a Paillier plaintext in `[0, N)`; since
`a·b + β' < q² + q` and the protocol requires `N > q² + q` (satisfied by any
real 2048-bit Paillier key, and by the ≥1024-bit keys the tests use), the
homomorphic sum never wraps, so `α'` is the true integer `a·b + β' < 2^512`,
reduced into Zq by the curve's constant-time `Scalar.fromBytes64`.

**MtA is SEMI-HONEST ONLY** — correct against passive adversaries, not secure
against a malicious party. The GG20 range proofs / MtAwc check that close
that gap are Phase 2c (see `mta.zig`'s `TODO(2c)`).

**Ring-Pedersen aux params' role (why Phase 2a carries this at all).**
GG18/GG20's Phase-2b/2c zero-knowledge range proofs (proving a Paillier
plaintext lies in a bounded range, without revealing it — needed for both
MtA's soundness and the final signing protocol's proofs) use a Pedersen-style
commitment mod a second, INDEPENDENT RSA-strength modulus `N_tilde` (distinct
from any party's own Paillier `n`) as their commitment base. Every party
generates its OWN `(N_tilde, h1, h2)` and broadcasts it (never the discrete
log `lambda` relating `h1`/`h2` — see `generateAuxParams`'s doc comment for
why `lambda` is secret and discarded, and the `TODO(2c)` note on whether a
future aux-param-correctness proof needs to retain it). Carrying `AuxParams`
in `KeyShare`/`PublicKeys`, even though the range proofs that consume it are
Phase 2c, means the key-distribution step doesn't need to run twice.

**Modulus size (`aux_modulus_bits = 2048`).** Matches `paillier.modulus_bits`
and `rsa`'s default modulus size — GG18/GG20 use an RSA-strength safe-prime
product for `N_tilde`, the same security-margin class as a party's own
Paillier `n`. `AuxModulus`/`AuxFe` are `std.crypto.ff.Modulus`/`.Fe` — the
exact fixed-width constant-time primitive `paillier`/`rsa` build on.

**Wire codecs.** `Element` (33-byte SEC1-compressed point, same shape as
`frost.Element` — reimplemented locally rather than imported, since this
module's only declared sibling dependency is `paillier`, per the task
brief). `FeldmanCommitments`/`PublicKeys` use a `u32-BE count || entries...`
length-prefixed shape (mirrors `bls12_381.threshold.VerificationVector`).
`AuxParams`/`KeyShare` compose length-prefixed sub-fields the same way. None
of this is a claimed interop wire format with any other threshold-ECDSA
implementation (tss-lib, multi-party-ecdsa, etc.) — it is this module's own
internal serialization, real and round-trip-tested, not a standard.

## Threat model / out of scope

- **`secret_share` (x_i) and `paillier_secret` are SECRET** — as sensitive
  as any raw ECDSA/Paillier private key. `KeyShare` does not add any
  handling beyond what `Scalar`/`paillier.SecretKey` already provide
  (no automatic zeroing on drop — Zig has no destructors); a careful
  caller zeroes/protects these the same way it would any other private-key
  material.
- **`reconstructSecret` is a TEST/AUDIT utility, not a production
  primitive.** The entire point of threshold ECDSA is that the raw secret
  key `x` is never assembled in one place during ordinary operation —
  Phase 2c (signing, a later module) computes a valid ECDSA signature
  WITHOUT ever calling anything like this function. It exists here so this
  module's own Shamir/Feldman self-consistency tests have something to
  assert against (mirrors `frost.deriveInterpolatingValue`'s and
  `bls12_381.threshold.combineSignatures`'s own "below-threshold gives a
  wrong answer, not an error" caveat — see their doc comments) — and as a
  documented emergency-recovery tool an operator might deliberately invoke
  out-of-band (with all the operational risk that implies), never as part
  of an automated signing path.
- **Const-time discipline.** Every scalar-field operation touching a secret
  (`evalPolynomialAt`'s `secret`/`coefficients`, `Scalar.add`/`.mul` inside
  it) goes through `std.crypto.pcurves.secp256k1`'s already-constant-time
  Montgomery-form arithmetic — no new judgment introduced here, same
  posture `frost`/`bls12_381.threshold` document for their identical Horner
  loops. `reconstructSecret`'s Lagrange coefficients are computed from
  PUBLIC participant indices only (same reasoning as
  `frost.deriveInterpolatingValue`'s doc comment), so that arithmetic
  needs no special discipline beyond using `Scalar`'s existing ops.
- **`generateAuxParams` const-time posture.** The safe-prime *search* is
  inherently variable-time (how long it took reveals nothing about the primes
  kept) — same acceptable posture `paillier.generatePrime`/`rsa` establish.
  The secret exponent `lambda`'s use in `h2 = h1^lambda mod N_tilde` is the
  constant-time `AuxModulus.pow`, mirroring `paillier.fromPrimes`'s
  `g^lambda mod n²`. All secret buffers (p̃/q̃/p'/q'/`lambda` source bytes)
  are `secureZero`'d.
- **MtA const-time posture.** MtA touches secrets `a`/`b`/`α`/`β`/`β'` and
  Alice's Paillier secret key; every step is an already-constant-time
  `paillier` op (`encrypt`/`mulPlaintext`/`addPlaintext`/`decrypt`, whose
  secret exponent never uses `powPublic`) or infallible constant-time curve
  arithmetic (`Scalar.neg`/`fromBytes64`). The one variable-time step is the
  `L`-function big-int division *inside* `paillier.decrypt` (inherited, not
  introduced — see `paillier`'s SPEC). **MtA is semi-honest only** — see the
  boundary section; range proofs (Phase 2c) add malicious security.
- **No signature is produced anywhere in this module.** Its output
  (`KeyShare`s + MtA additive shares) is inert — it cannot sign anything
  without Phase 2c (range proofs / MtAwc) and Phase 2d (the signing protocol
  itself), both separate, later, out-of-scope.
- **No official KAT vectors exist for threshold-ECDSA** (unlike `frost`'s
  RFC 9591 Appendix E.5) — verification here is self-consistency
  (Shamir-reconstruct-equals-original-secret, Feldman-derived-equals-
  direct-scalar-mult, byte round-trips), the same posture
  `bls12_381.threshold` uses for its own tests.

## Phase 2a / 2b / 2c / 2d boundary

- **Phase 2a (done, this module):** trusted-dealer Shamir+Feldman keygen,
  each party's Paillier keypair, each party's ring-Pedersen aux params
  (`generateAuxParams`, real). Output: `KeyShare` per party.
- **Phase 2b (done, this module — `mta.zig`):** MtA, the semi-honest
  multiplicative→additive share conversion the parties' `paillier` homomorphic
  ops exist to support. Output: additive shares `α`/`β` with
  `α + β ≡ a·b (mod q)`.
- **Phase 2c (out of scope, later):** the GG20 zero-knowledge range proofs
  (proof of correct Paillier encryption, range proofs bounding a plaintext,
  consuming `AuxParams`/`PublicKeys` as their Pedersen commitment base) + the
  MtAwc check — the layer that upgrades the semi-honest MtA core to malicious
  security.
- **Phase 2d (out of scope, later):** the actual threshold ECDSA signing
  protocol — the interactive rounds that turn a message + the parties'
  `KeyShare`s + Phase-2b's MtA outputs into a single valid ECDSA signature
  verifiable under `KeyShare.group_public_key`.

## Backlog / deferred

- Phase 2c: range proofs / MtAwc (malicious security for MtA) — see
  `mta.zig`'s `TODO(2c)` notes.
- Phase 2d: the threshold-signing protocol.
- `generateAuxParams` aux-param-correctness ZK proof (Πprm/Πmod): if a later
  variant broadcasts a proof that `h2 = h1^lambda`, retain `lambda` at setup
  (`generateAuxParamsInternal` already returns it) instead of discarding —
  see the function's doc comment `TODO(2c)`.
- Full Pedersen-style DKG (no single dealer) — a distinct follow-up module,
  not a `splitSecretKey` signature change.
- Minimum-key-size floor enforcement on `AuxParams`/`PublicKeys`/`KeyShare`
  `fromBytes*` paths (mirrors `paillier`'s own deferred "minimum-key-size
  floor" backlog item — no floor is enforced on parsed `n_tilde`/Paillier
  `n` today beyond `std.crypto.ff`'s own overflow/non-canonical rejection).
