# threshold_ecdsa — spec

Design + threat notes for auditors. Usage: see ./README.md.
Attribution/provenance: see ./README.md "Provenance" + ./NOTICE.

## Design & invariants

**Phase 2a (trusted-dealer keygen) of a 3-part GG20 threshold-ECDSA arc**
(2a keygen → 2b MtA + range proofs → 2c signing), over secp256k1
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

**What's REAL vs STUBBED (the load-bearing fact of this scaffold):**

- **REAL** — `Element` (SEC1-compressed secp256k1 point codec),
  `scalarFromIndex`/`evalPolynomialAt` (Shamir, Horner's method over Zq),
  `splitSecretKey` (Shamir + Feldman VSS assembly), `groupPublicKey`/
  `derivePublicKeyShare` (Feldman evaluation-in-the-exponent),
  `reconstructSecret` (Lagrange interpolation at x=0 — test/audit use
  only, see "Threat model" below), `FeldmanCommitments`/`AuxParams`/
  `PublicKeys`/`KeyShare`'s STRUCTS and byte codecs, and
  `keygenTrustedDealer`'s composition (Shamir split + Paillier-keypair
  wiring + `KeyShare` assembly). Every one of these is either pure
  mechanical plumbing or a direct, field/group-swapped port of this
  repo's own already-KAT-validated `frost.deriveInterpolatingValue`/
  `bls12_381.threshold.evalPolynomialAt`/`feldmanCommitCoefficient`/
  `derivePublicKeyShare`/`combineSignatures` constructions — see each
  function's doc comment in `root.zig` for the exact correspondence.
- **STUBBED** — `generateAuxParams` only: deriving cryptographically-sound
  ring-Pedersen parameters (`N_tilde`, `h1`, `h2`) is genuine number theory
  (a safe-prime search distinct from `paillier.generatePrime`'s plain
  probable-prime search, plus sampling a secret exponent from an order this
  module has no existing primitive for) — `@panic("TODO(core): ...")`, full
  construction in the function's own doc comment in `root.zig`.

**Design decision: `keygenTrustedDealer` takes `aux_params` as
CALLER-SUPPLIED, not self-generated.** The task framing for this scaffold
explicitly left this call: either have `keygenTrustedDealer` call the
stubbed `generateAuxParams` internally (which would make EVERY keygen test
panic, including the already-real Shamir/Feldman/Paillier-wiring paths), or
accept `aux_params` as a parameter and keep those paths fully testable today.
This module took the second option. Consequences:

- `splitSecretKey`, `groupPublicKey`, `derivePublicKeyShare`,
  `reconstructSecret`, and `keygenTrustedDealer`'s Shamir/Paillier-wiring
  behavior are all exercised by PASSING tests today (`zig build
  test-threshold_ecdsa`: 9/10 pass in Debug and ReleaseFast).
- Only a test that directly calls `generateAuxParams` panics — it is
  deliberately the LAST test in `root.zig` so `--summary all` shows every
  other test's pass/fail before the crash. This mirrors this repo's
  existing `ssh.userauth`/`ssh.openSession`/`ssh.exec` scaffold precedent
  (three `@panic("TODO(agent): ...")` reserved functions in an otherwise
  fully-tested module) rather than the alternative pattern some other
  modules in this repo used at an earlier scaffold stage (an entire
  crypto-core pass deferred, every test panicking).
- A production caller cannot get real `AuxParams` from this module alone
  yet — it must wait for `generateAuxParams` (or provide its own, at its
  own risk) before deploying. This module's own tests use small,
  explicitly-non-secure hand-constructed `AuxParams` values (see
  `toyAuxParams()` in `root.zig`'s tests) purely to exercise the
  (already-real) struct/codec.

**Ring-Pedersen aux params' role (why Phase 2a carries this at all).**
GG18/GG20's Phase-2b/2c zero-knowledge range proofs (proving a Paillier
plaintext lies in a bounded range, without revealing it — needed for both
MtA's soundness and the final signing protocol's proofs) use a Pedersen-style
commitment mod a second, INDEPENDENT RSA-strength modulus `N_tilde` (distinct
from any party's own Paillier `n`) as their commitment base. Every party
generates its OWN `(N_tilde, h1, h2)` and broadcasts it (never the discrete
log `lambda` relating `h1`/`h2` — see `generateAuxParams`'s doc comment for
why `lambda` is secret and discarded, and the `TODO(core)` note on whether a
future Phase-2b prover needs to retain a related value). Carrying `AuxParams`
in `KeyShare`/`PublicKeys` NOW (Phase 2a), even before Phase 2b consumes it,
means the key-distribution step doesn't need to run twice.

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
- **`AuxParams`/`generateAuxParams`'s eventual constant-time posture** is
  DEFERRED along with the number theory itself — a follow-up crypto pass
  implementing `generateAuxParams` must apply the same discipline
  `paillier.generatePrime`/`rsa`'s prime search already establish (variable
  time in how long the safe-prime search takes is acceptable and
  unavoidable; the resulting `lambda`'s use in `h2 = h1^lambda mod N_tilde`
  must be constant-time in `lambda`, mirroring `paillier.fromPrimes`'s own
  `g^lambda mod n²` step).
- **No signature is produced anywhere in this module.** Phase 2a's output
  (`KeyShare`) is inert key material — it cannot be used to sign anything
  without Phase 2b (MtA + range proofs) and Phase 2c (the signing protocol
  itself), both separate, later, out-of-scope modules.
- **No official KAT vectors exist for threshold-ECDSA** (unlike `frost`'s
  RFC 9591 Appendix E.5) — verification here is self-consistency
  (Shamir-reconstruct-equals-original-secret, Feldman-derived-equals-
  direct-scalar-mult, byte round-trips), the same posture
  `bls12_381.threshold` uses for its own tests.

## Phase-2a / 2b / 2c boundary

- **Phase 2a (this module):** trusted-dealer Shamir+Feldman keygen, each
  party's Paillier keypair, each party's ring-Pedersen aux params
  (struct/codec real, generation stubbed). Output: `KeyShare` per party.
- **Phase 2b (separate, later module, depends on this one + `paillier`):**
  MtA (multiplicative-to-additive share conversion, the protocol
  `paillier`'s homomorphic ops exist to support — see `paillier`'s own
  "Phase-2 boundary" note) and the GG20 zero-knowledge range proofs (proof
  of correct Paillier encryption, range proofs bounding a plaintext,
  consuming `AuxParams`/`PublicKeys` as their Pedersen commitment base).
- **Phase 2c (separate, later module):** the actual threshold ECDSA signing
  protocol — the interactive rounds that turn a message + the parties'
  `KeyShare`s + Phase-2b's MtA outputs into a single valid ECDSA signature
  verifiable under `KeyShare.group_public_key`.

## Backlog / deferred

- `generateAuxParams`'s number theory (safe-prime search, sampling from the
  squares-subgroup order) — see the function's own doc comment; suggested
  follow-up tier is a small, self-contained Fable or Opus pass, not a large
  one (the surrounding scaffolding, struct, and codec are already done).
- `TODO(core)` note inside `generateAuxParams`'s doc comment: confirm
  against GG20/Phase-2b's exact range-proof constructions whether the
  PROVER additionally needs to retain `lambda` locally, or whether
  discarding it (this doc comment's current assumption) is correct.
- Full Pedersen-style DKG (no single dealer) — a distinct follow-up module,
  not a `splitSecretKey` signature change.
- Minimum-key-size floor enforcement on `AuxParams`/`PublicKeys`/`KeyShare`
  `fromBytes*` paths (mirrors `paillier`'s own deferred "minimum-key-size
  floor" backlog item — no floor is enforced on parsed `n_tilde`/Paillier
  `n` today beyond `std.crypto.ff`'s own overflow/non-canonical rejection).
