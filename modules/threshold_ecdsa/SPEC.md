# threshold_ecdsa — spec

Design + threat notes for auditors. Usage: see ./README.md.
Attribution/provenance: see ./README.md "Provenance" + ./NOTICE.

## Design & invariants

**Phase 2a (trusted-dealer keygen) + Phase 2b (ring-Pedersen aux params +
the semi-honest MtA core) + Phase 2c (MtA zero-knowledge range proofs,
GG18 Appendix A, verified against the paper) + Phase 2d (online signing,
`signing.zig`) of the GG20 threshold-ECDSA arc** (2a keygen → 2b
aux-params/MtA → 2c range proofs + MtAwc → 2d signing), over secp256k1
(`std.crypto.ecc.Secp256k1`, scalar field `Scalar` = Zq for q the group
order). See the dedicated "Phase 2c" and "Phase 2d" sections below for
those layers' design and status.

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

**What's implemented (all REAL, no panics — Phase 2c's prove/verify number
theory AND Phase 2d's online signing are now implemented and tested, see the
dedicated sections below). `zig build test-threshold_ecdsa` passes, and the
security-critical reject tests are NOT skipped in the default run: this
module is marked `heavy` in the root `build.zig`, so a Debug request builds
it at ReleaseSafe, where the `builtin.mode == .Debug` guards on the
2048-bit-keygen fixtures do not fire. (Those guards still matter under
`-Dstrict-debug`, which forces genuine Debug — that mode DOES skip them, and
is not the CI default.) The audit-F1/F2/F3 received-parameter validation and
its reject tests are fast and run in EVERY mode:**

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
  doc comment for the retention decision). A separate trapdoor-retaining
  variant, `generateAuxParamsWithTrapdoor`, exists for a party that DOES
  need to act as a Πprm/Πmod prover — see the "Πprm / Πmod" section below.
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

**MtA (`mtaAliceInit`/`mtaBobResponse`/`mtaAliceFinalize`) is SEMI-HONEST
ONLY** — correct against passive adversaries, not secure against a malicious
party. The GG18 range proofs / MtAwc check that close that gap are Phase 2c,
which is now **IMPLEMENTED** — structs, transcript, fail-closed wiring AND
the prove/verify number theory are all real (see the dedicated "Phase 2c"
section below and `zkproofs.zig`'s module doc comment). The malicious-secure
entry point `mtaAliceFinalizeChecked` is a working alternative to the
semi-honest path, not a scaffold. (This paragraph described the scaffold
state and was left stale by the pass that implemented Phase 2c; corrected
here, since it contradicted the rest of this file on exactly the security
property that matters.)

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
- **This module DOES produce signatures** — `signing.signWithShares`
  (Phase 2d) emits a real secp256k1 ECDSA signature, and verifies it against
  the group public key before returning (`error.SigningAborted` otherwise).
  The keygen/MtA layers on their own are inert, but the module as a whole is
  not. (This bullet used to read "no signature is produced anywhere in this
  module", true only before Phase 2c/2d landed here rather than in a
  follow-up module; corrected.)
- **No official KAT vectors exist for threshold-ECDSA** (unlike `frost`'s
  RFC 9591 Appendix E.5) — verification here is self-consistency
  (Shamir-reconstruct-equals-original-secret, Feldman-derived-equals-
  direct-scalar-mult, byte round-trips), the same posture
  `bls12_381.threshold` uses for its own tests.

## Phase 2c — MtA zero-knowledge range proofs (`zkproofs.zig`, IMPLEMENTED)

**Design.** GG18 (ePrint 2019/114) Appendix A defines two Sigma-protocol,
Fiat-Shamir-transformed proofs over the ring-Pedersen commitment scheme
(`AuxParams`) Phase 2a/2b already carry:

- **Alice's range proof (Πᵢ)** — proves `c_A = Enc_A(a; r_A)` encrypts an
  `a` inside the agreed bounded range, without revealing `a`/`r_A`. Six
  public values: a Pedersen commitment to `a` (`z`), a Paillier-shaped
  commitment to a random mask (`u`), a Pedersen commitment to that mask
  (`w`), a Paillier-randomness response (`s`), and two INTEGER (non-modular)
  responses (`s1`, `s2`) — `s1` is the value whose boundedness IS the range
  proof.
- **Bob's MtA proof (Π^MtA)** — proves `c_B = c_A^b · Enc_A(β'; r_B)` was
  correctly derived from the public `c_A`, with `b`/`β'` in range and `r_B`
  a fresh Paillier blind Bob actually knows. Ten public values: the natural
  extension of Alice's proof with a second commitment/mask/response triple
  (for `β'`) plus one "homomorphic consistency" commitment (`v`) that binds
  the whole thing to the specific `c_A`/`c_B` pair.
- **MtAwc (Π^MtAwc)** — Bob's MtA proof plus a Schnorr commitment (`u1_point
  = alpha·G`) proving the same `b` satisfies `b·G == B` for a public point
  `B` — needed by GG20's signing round for the `k·x` share conversion.

`zkproofs.zig` implements all three. The struct layouts, byte codecs, and a
real SHA-256 Fiat-Shamir `Transcript` (domain-separated per proof kind,
binding the verifier's `AuxParams`, the Paillier public key — modulus `N`
**and** generator `Γ`, see the audit-F3 section below — every
ciphertext/point in play, and the proof's own first-message commitments)
are REAL and tested. The six `proveAliceRange`/`verifyAliceRange`/
`proveBobMta`/`verifyBobMta`/`proveBobMtaWc`/`verifyBobMtaWc` functions now
carry the full number theory (sample masks → commit → Fiat-Shamir challenge
→ integer response → verification equations), **verified against the ACTUAL
GG18 paper** — Appendix A.1 "Range Proof", A.2 "Respondent ZK Proof for
MtAwc", A.3 "Respondent ZK Proof for MtA" (retrieved from the NSF Public
Access mirror of the CCS'18 version, same Appendix A as ePrint 2019/114) —
and structurally cross-checked against bnb-chain/tss-lib's `crypto/mta`
(structure/bounds reference only, no code ported; recorded in NOTICE).

**Exact bounds used, with sources:**

- Alice's proof (paper A.1, identical in tss-lib): prover samples
  `alpha ∈ Z_{q³}`, `beta ∈ Z_N^*`, `gamma ∈ Z_{q³·Ñ}`, `rho ∈ Z_{q·Ñ}`;
  verifier checks `s1 <= q³` + the two consistency equations. The paper's
  own conclusion: "the Verifier is convinced that m ∈ [-q³, q³]".
- Bob's proof (paper A.2/A.3) with **two deliberate hardenings** adopted
  from tss-lib/GG20 practice, both strictly STRONGER than the paper:
  - the paper samples `gamma ∈ Z_N^*` (the mask for `β'`) and imposes NO
    bound on the `t1` response; this module samples `gamma ∈ Z_{q⁷}` and the
    verifier checks `t1 <= q⁷`, which additionally BOUNDS Bob's additive
    blind `β'` — closing the unbounded-`β'` degree of freedom that the
    Alpha-Rays failure class abuses. This module's checked-MtA wiring samples
    `β' ∈ Z_q` (well inside tss-lib's `q⁵`), so honest proofs pass with slack.
    **This "closing" is SIZE-CONDITIONAL (audit F2): the `t1 <= q⁷` bound only
    bites when the Paillier `N` (and ring-Pedersen `Ñ`) it lives over EXCEED
    `q⁷ ≈ 2^1792`. Below ~2048 bits the check is VACUOUS — a `<= q⁷` modulus
    can never make it fire — so the "unbounded-`β'` freedom" would remain
    open. This is now ENFORCED: every RECEIVED Paillier `N` and aux `Ñ` on the
    checked-MtA / zkproofs path must clear `N > q⁷` (`root.paillierNMeetsFloor`
    / `root.nTildeMeetsFloor`), fail-closed at both the prove and verify
    entry points. The module no longer accepts 1024-bit keys on the checked
    path; all checked-path tests were bumped to 2048-bit accordingly.**
  - `tau` widens from the paper's `Z_{q·Ñ}` to `Z_{q³·Ñ}` accordingly, so
    `t2 = e·sigma + tau` stays statistically hiding.
- MtAwc (paper A.2): the A.3 proof plus `u1 = alpha·G` reusing the SAME
  `alpha` (paper-confirmed — the prover "selects alpha ∈R Z_{q³}" once and
  "computes u = g^alpha") and the verifier equation `g^{s1} == X^e·u1` in
  the curve group (`s1` reduced mod q there only).

**Challenge space:** the paper's verifier "selects a challenge e ∈R Z_q" in
all three proofs, so `Zq` is the challenge space; this module instantiates
Fiat-Shamir over it with SHA-256 + a statistically-uniform wide reduction.

**Verification level (be honest about what the tests prove).** There is NO
cross-implementation KAT for these proofs: the Fiat-Shamir transcript is
implementation-defined (the paper's verifier is INTERACTIVE; tss-lib uses
SHA512/256 over Go big.Int encodings + rejection sampling; this module uses
SHA-256 over the domain-separated length-prefixed `Transcript`), so proofs
are not byte-compatible across implementations and a deterministic reference
KAT is impossible by construction. The test suite is therefore
(a) self-consistency (honest prove → verify accepts; end-to-end checked MtA
yields `α + β ≡ a·b`; codec round-trips re-verify) and (b) the
SECURITY-CRITICAL reject paths (below). What the self-tests do NOT establish:
soundness against an adversarial prover exploring the full malicious-input
space — that rests on the construction matching the paper (reviewed by
transcription against paper + tss-lib) and on the Strong-RSA / Paillier
hardness assumptions — nor side-channel freedom. **An independent
cryptographic review of `zkproofs.zig` against GG18 Appendix A is
recommended before any production signing use — see the "Auditor brief"
section at the end of this file for the itemized questions (A1–A7); it is
deliberately specific, because a bare "needs audit" note is useless to the
reviewer who eventually acts on it.**

**Verifier-vs-prover aux-param ownership.** Every `verifier_aux` parameter
is the `AuxParams` OF WHOEVER VERIFIES that proof, not the prover's own
tuple — Alice's `proveAliceRange` takes BOB's aux params (Bob verifies her
proof); Bob's `proveBobMta`/`proveBobMtaWc` take ALICE's aux params (Alice
verifies his). Getting this backwards breaks the Pedersen commitment's
binding property (soundness requires the PROVER never know `lambda =
log_h1(h2)` for the tuple in play) — see `zkproofs.zig`'s module doc comment
for the full note.

**Why `mtaBobResponseChecked` constructs `c_B` differently than
`mtaBobResponse`.** The semi-honest `mtaBobResponse` folds `β'` into `c_B`
via `paillier.addPlaintext`, whose `g^m` term carries no fresh Paillier
rerandomization — fine for semi-honest correctness, but it leaves Bob with
no randomness of his own to prove knowledge of (Π^MtA's witness needs a
FRESH `r_B` HE chose). `mtaBobResponseChecked` (`mta.zig`) instead composes
`c_B` via `mulPlaintext` + a FRESH `encrypt(β'; r_b)` + `addCiphertexts` —
decrypts to the identical `a·b + β'` (Paillier decryption is randomness-
independent; a dedicated test in `mta.zig` asserts both this AND that the
resulting ciphertext bytes differ from `mtaBobResponse`'s), but now carries
the witness `r_b` the proof needs. Similarly, `mtaAliceInitChecked` retains
`r_A` (the semi-honest `mtaAliceInit` discards it inside
`paillier.encryptRandom`).

**Fail-closed wiring.** `mta.mtaAliceFinalizeChecked` calls
`zkproofs.verifyBobMta` and returns `error.InvalidMtaProof` (never reaching
`mtaAliceFinalize`'s decryption) if it returns `false`. Both the control
flow and the predicate are now real; `mta.zig`'s end-to-end test runs the
full `mtaAliceInitChecked → verifyAliceRange → mtaBobResponseChecked →
proveBobMta → mtaAliceFinalizeChecked` round, asserts `α + β ≡ a·b`, and
asserts a tampered `c_B` / wrong-witness proof is refused with
`error.InvalidMtaProof` before decryption.

**Threat model — why this phase exists at all.** Without Phase 2c, a
malicious party can feed an out-of-range multiplicative input (`a`, `b`, or
`β'`) into MtA and, across the many MtA instances a real signing round runs,
leak bits of the counterparty's secret share. This is the general shape of
the **Alpha-Rays** and **TSSHOCK** failure classes documented against real
threshold-ECDSA implementations — out-of-range/malformed values smuggled
through an under-checked MtA (or key-generation) step, amplified over many
sessions into a full key recovery. The range/MtA proofs' verification
equations are what close this gap; `zkproofs.zig`'s test suite deliberately
weighs its REJECT-path tests (out-of-range `a`/`b`/`β'` driven through the
byte-level inner provers, tampered `c_A`/`c_B`, wrong `b`/`β'` witnesses,
wrong public point `B`, and every single mangled proof field) as the
security-critical assertions — a prove/verify pair that always accepts would
pass every "honest accept" test trivially while leaving the vulnerability
wide open. These reject tests are REAL and passing; they must NOT be
weakened.

**Received-parameter validation — the honesty note (audit F1/F2/F3).** Three
facts this SPEC previously UNDERSTATED as tidy deferred niceties, corrected
here:

- **(F1) Without validation of RECEIVED ring-Pedersen aux params, the
  zero-knowledge (hiding) property COLLAPSES against a malicious verifier,
  and the prover's secret witness LEAKS.** The prover commits to its witness
  as `z = h1^m · h2^ρ mod Ñ` under the counterparty-supplied `(Ñ, h1, h2)`. A
  malicious verifier who broadcasts an `Ñ` with a small factor (or a prime
  `Ñ`, or `h1`/`h2` outside the square subgroup) makes those commitments leak
  bits of `m` (Alice's nonce `k_i` in `runCheckedMtA`, Bob's Lagrange-weighted
  share `w_j` in MtAwc) — the TSSHOCK / Alpha-Rays class, breaking HIDING (not
  soundness). This is now MITIGATED: `root.AuxParams.validate` runs
  fail-closed at every prove entry point (`zkproofs.proveAliceRange`/
  `proveBobMta`/`proveBobMtaWc`) and rejects a received tuple unless `Ñ` is
  odd + composite (Miller-Rabin) + `> q⁷`, `1 < h1,h2 < Ñ`, `gcd(h1,Ñ) =
  gcd(h2,Ñ) = 1`, and `h1,h2` pass the Jacobi-symbol square-subgroup test
  `(h/Ñ) = +1`. **The Jacobi check is NECESSARY but not SUFFICIENT for
  quadratic residuosity** (a non-residue mod BOTH prime factors of `Ñ` also
  has symbol +1) — it is the strongest guarantee available WITHOUT `Ñ`'s
  factorization. The full fix — a CGGMP21 `Πprm`/`Πmod` zero-knowledge
  proof-of-correct-generation broadcast alongside the tuple — is now
  **IMPLEMENTED** (`aux_proofs.zig` — see the dedicated section below): a
  generator proves its tuple well-formed via `proveWellFormed` and a
  validator rejects any tuple whose proof fails via `verifyWellFormed`,
  closing exactly the residuosity gap the Jacobi floor cannot. The
  structural validation (`AuxParams.validate`) remains the always-enforced
  cheap floor beneath it, not a replacement; a malicious-secure per-party-aux
  deployment now runs `verifyWellFormed` on every received tuple IN ADDITION
  to `validate`.
- **(F2) The "closed the unbounded-`β'` freedom" claim is size-conditional**
  and only holds at `N > q⁷` — now enforced (see the Bob's-proof bounds
  section above).
- **(F3) The Fiat-Shamir transcript did not bind the Paillier generator `Γ`
  — a grinding seam. FIXED, and the fix is BREAKING on the wire.** Fiat-
  Shamir is only as sound as the transcript is complete: a public value that
  is not absorbed is a value the prover may still CHANGE after the challenge
  is fixed. `Γ` is part of the statement (`c = Γ^m · r^N mod N²`) and appears
  in verification equation 2 (`u · c^e == Γ^{s1} · s^N`), yet
  `Transcript.appendPaillierPublicKey` absorbed the modulus `N` ONLY. The
  challenge was therefore invariant under a change of generator, so a prover
  could enumerate candidate `Γ` values against ONE fixed challenge, looking
  for a generator under which a false statement's equation closes — a search
  that transcript binding is supposed to make as hard as breaking the Sigma
  protocol itself. Two changes close it, and BOTH are needed:
  - **the binding** — `appendPaillierPublicKey` now absorbs `Γ` as well as
    `N` (each length-prefixed, so the two fields cannot be re-split
    ambiguously). This is the general Fiat-Shamir-completeness fix.
  - **the structural precondition** — `root.paillierGeneratorIsStandard`
    rejects any RECEIVED Paillier key whose `Γ != N+1`, fail-closed at every
    prove AND verify entry point (alongside the F1/F2 gates). Binding alone
    would not help against a *degenerate* `Γ`: a generator of order smaller
    than `N` (`Γ = 1` being the extreme) makes equation 2 stop tying `s1` to
    the ciphertext's plaintext at all, so the `s1 <= q³` range check in
    equation 1 would be guarding a value unrelated to what was encrypted —
    and that is true for every challenge, ground or not. Every key
    `paillier.generate`/`fromPrimes` produces already has `g = n+1`, so this
    rejects only deliberately hand-built keys. Consequence:
    `zkproofs.gammaPowWide`'s non-standard-`g` fallback branch is now DEAD
    from the proof paths (kept only so the helper stays a total function).

  **BREAKING wire change.** Absorbing a new value changes every challenge,
  so a proof minted before this change does not verify after it, and vice
  versa. The three domain tags were bumped `…/v1` → `…/v2`
  (`range_proof_domain`, `mta_proof_domain`, `mta_proof_wc_domain`) to make
  the break explicit rather than silent — a stale proof now fails as a plain
  verification failure. This is acceptable here because the module has no
  deployed peer and these proofs were never byte-compatible with any other
  implementation (see the "Wire codecs" and "Verification level" notes);
  it would NOT be acceptable after a deployment.

  **What proves the binding is load-bearing** (not just that round-trips
  still pass): a test varies ONLY `Γ` — same `N`, same aux tuple, same
  ciphertexts, same commitments — across all three challenge functions and
  requires the challenge to move, with a control asserting that the same `Γ`
  supplied two different ways hashes identically. Fault injection confirms
  the teeth: deleting the `g` append makes exactly that test RED and nothing
  else; neutering `paillierGeneratorIsStandard` makes exactly the F3
  fail-closed test RED and nothing else. The end-to-end form of the test
  (prove under one `Γ`, verify under another) is not writable *because* of
  the second half of the fix — a non-standard `Γ` is now refused before
  either side does any arithmetic — which is why the property is asserted at
  the challenge-function level.

**Signing-safety was never in question.** Neither F1 nor F2 lets this module
emit an INVALID signature: `signing.signWithShares`'s step-6 std-ECDSA
self-check aborts (`error.SigningAborted`) on any arithmetic consequence of a
cheat. F1 is a HIDING (witness-secrecy) property and F2 a range-bound-vacuity
property; both concern what an adversary can LEARN, not what a bad signature
it can force.

## Πprm / Πmod — aux-param proofs-of-correct-generation (`aux_proofs.zig`, IMPLEMENTED — closes audit F1)

**Design.** CGGMP21 (R. Canetti, R. Gennaro, S. Goldfeder, N. Makriyannis, U.
Peled, "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable
Aborts", IACR ePrint 2021/060) Fig.16 ("Πmod", Paillier-Blum-modulus proof)
and Fig.17 ("Πprm", ring-Pedersen-parameter proof) let the GENERATOR of an
`AuxParams` tuple prove it is well-formed — Πmod proves `n_tilde` is a
genuine product of two Blum primes `p̃, q̃ ≡ 3 (mod 4)` with `gcd(n_tilde,
φ(n_tilde)) = 1`; Πprm proves `h1` (paper's `s`) and `h2` (paper's `t`)
generate the same cyclic subgroup, i.e. `h2 = h1^lambda mod n_tilde` for a
KNOWN `lambda` — and let the VALIDATOR verify those proofs, fully closing
audit F1 (the Jacobi check above is necessary-but-not-sufficient; these
proofs are the sufficient fix the F1 write-up always pointed at).

**Status: IMPLEMENTED, `pi_mod_iterations`/`pi_prm_iterations` soundness
parameter `m = 80` (≈2^-80 error) for both.** REAL: the `ModProof`/
`PrmProof` struct shapes and byte codecs, the Fiat-Shamir transcript wiring
(`deriveModChallenge`/`derivePrmChallengeBits`, built on
`zkproofs.Transcript`'s new `finalizeDigest` — the same domain-separated
SHA-256 binding discipline the Phase-2c proofs use, extended with a local
deterministic counter-mode expansion since Πmod/Πprm need `m` independent
per-round challenges rather than one `Zq` scalar), `root.AuxTrapdoor` /
`root.generateAuxParamsWithTrapdoor` (the `p̃`/`q̃`/`lambda`-retaining
variant of `generateAuxParams` a prover needs — ordinary `generateAuxParams`
is UNCHANGED, still discarding the trapdoor), the
`proveWellFormed`/`verifyWellFormed` public-API wiring, AND the two
irreducible number-theory cores, `aux_proofs.Piprm.prove`/`.verify` and
`aux_proofs.Pimod.prove`/`.verify` (the full CGGMP21 construction: Blum-QR
witness search + CRT quadratic-residue classification + 4th roots +
Paillier-shaped `z_i^N` response for Πmod; `phi(n_tilde)`-modular linear
response `z_i = a_i + e_i·lambda` for Πprm). `gate.aux_proofs_core_implemented`
is flipped `true` — the same scaffold-then-implement pattern `bn254`'s
`pairing.zig` and `df-elect`'s `election.decide` followed to completion.

**Soundness note (deterministic-MR is defense-in-depth only).** `Pimod.verify`
has no CSPRNG, so its "n_tilde must be composite" Miller-Rabin step draws
witnesses deterministically from `SHA256(n_tilde)`. That MR check is NOT
load-bearing: it only fast-rejects a genuinely PRIME `n_tilde`. The soundness
against a 3-prime or prime-power `n_tilde` (which MR correctly sees as
composite) is carried entirely by the per-round `z_i^N ≡ y_i` and
`x_i^4 ≡ (−1)^{a_i} w^{b_i} y_i` equations — verified empirically: for the
crafted 3-prime KAT below, MR reports composite (does not reject), the prover
finds a genuine `(w/n_tilde) = −1` witness (Jacobi step does not reject), yet
all 80 rounds fail BOTH per-round equations. Πprm's soundness is likewise
carried by the per-round `s^{z_i} ≡ A_i · t^{e_i}` check.

**KAT harness — the F1-soundness scenarios are the deliverable.** No
official byte-vectors exist for Πprm/Πmod (same posture as every other proof
family in this module) — `aux_proofs.zig`'s tests are UNGATED struct/codec/
transcript-determinism assertions PLUS two crafted-parameter scenarios that
demonstrate the exact gap these proofs close:

- **(a) a 3-prime `n_tilde`** (product of three ~671-bit comptime factors,
  odd, composite, `> q⁷`, with `h1=4`/`h2=16` — both perfect squares, hence
  trivially Jacobi `+1`): `AuxParams.validate` ACCEPTS it (documents the gap)
  but `Pimod.verify` REJECTS it (documents the fix) — and, per the soundness
  note above, rejects it via the per-round `z_i^N`/`x_i^4` equations, not the
  MR check.
- **(b) an `(h1, h2)` pair with `h2` outside `<h1>`** (`h1=4`, `h2=9` mod a
  genuine ~2000-bit two-factor composite — both perfect squares, hence
  trivially Jacobi `+1`, but nothing ties `9` to a power of `4`):
  `AuxParams.validate` ACCEPTS it but `Piprm.verify` REJECTS it (no valid
  proof CAN exist for `h2 ∉ ⟨h1⟩`, so any candidate fails the per-round
  `s^{z_i} ≡ A_i · t^{e_i}` equation).

Plus a tamper suite (flip a byte of `w`/`x_i`/`z_i`(Πmod)/`A_i`/`z_i`(Πprm)
in an honest proof → `verifyWellFormed` rejects) and a completeness test
(honest `generateAuxParamsWithTrapdoor` → `proveWellFormed` →
`verifyWellFormed` accepts) — all now run for real (gate flipped `true`).

**Still deferred within Phase 2c / at the 2c-2d boundary:**

- Independent cryptographic review of the implemented constructions against
  GG18 Appendix A (see the verification-level note above) before production
  use — the self-tests prove self-consistency + the reject contract, not
  soundness against an unbounded malicious prover.
- Exactly which signing-round steps invoke plain MtA vs. MtAwc — that
  wiring belongs to Phase 2d (the signing protocol itself), not this file;
  `zkproofs.zig`/`mta.zig` only provide the primitives.
- `generateAuxParams`'s own correctness proof (Πprm/Πmod, `h2 = h1^lambda`)
  is now DONE. The CHEAP structural validation of received aux tuples (audit
  F1 — composite `Ñ`, in-range square-subgroup `h1`/`h2`, coprimality) is
  enforced fail-closed at the prove entry points (`root.AuxParams.validate`);
  the full zero-knowledge proof-of-correct-generation is IMPLEMENTED
  (`aux_proofs.zig` — struct/codec/transcript AND the two proof cores real,
  `gate.aux_proofs_core_implemented` flipped `true` — see the dedicated
  "Πprm / Πmod" section above). The one residual item is an independent
  cryptographic review of the Fiat-Shamir instantiation before production
  MPC-custody use — question **A4** in the "Auditor brief" section (there is
  no cross-implementation KAT for Πprm/Πmod, same posture as the rest of
  this module's proofs).

## Phase 2d — online signing (`signing.zig`, REAL end to end)

**Design.** GG20's headline result is a ONE-ROUND online signing protocol
(after a preprocessing phase this module folds into the online path, same
simplification tss-lib's "one-round" mode makes) that turns a message plus
a `t`-subset of `KeyShare`s into a standard secp256k1 ECDSA signature. This
module implements it as a single in-process driver,
`signing.signWithShares(allocator, shares, message, random) -> Signature`,
that runs every round over in-memory message passing rather than real
network I/O (documented as a v1 simplification — "good enough to prove
correctness + for the decisive test", per this module's task brief; see
`signing.zig`'s module doc comment for the phase-by-phase construction):

1. Each party samples `k_i, γ_i ← Zq` and computes its Lagrange-weighted
   secret share `w_i = λ_i·x_i` (`λ_i` from `signing.lagrangeCoefficient`,
   the SAME Lagrange-at-zero weights `reconstructSecret` uses internally,
   chosen so `Σ_{i∈S} w_i = x` without ever reconstructing `x`).
2. Each party computes `Γ_i = γ_i·G`, commits to it (SHA-256 hash), and
   proves knowledge of `γ_i` via a standard Fiat-Shamir Schnorr NIZK
   (`signing.SchnorrProof`/`provePoK`/`verifyPoK`) — every other party
   verifies the commitment + proof before trusting `Γ_i`. This closes the
   "last-mover" attack where a rushing party picks its `Γ_i` AFTER seeing
   everyone else's, to bias the aggregated `R`.
3. For every ORDERED pair `(i,j)`, `i≠j`, in the signing subset: the REAL
   Phase-2c CHECKED MtA (`mta.mtaAliceInitChecked`/`mtaBobResponseChecked`/
   `mtaAliceFinalizeChecked` + `zkproofs.proveAliceRange`/`verifyAliceRange`/
   `proveBobMta`, GG18 Appendix A.1/A.3) converts `k_i·γ_j` into additive
   shares, and the REAL CHECKED **MtAwc** (`zkproofs.proveBobMtaWc`/
   `verifyBobMtaWc`, Appendix A.2) converts `k_i·w_j` into additive shares
   bound to `j`'s PUBLIC Lagrange-weighted verifying share `W_j = λ_j·X_j`
   — this is exactly where MtAwc (vs. plain MtA) is invoked, resolving the
   open question the Phase-2c section below used to leave dangling. Summing
   every party's diagonal term (`k_i·γ_i`/`k_i·w_i`) plus every pairwise
   `α`/`β` share yields `δ_i`/`σ_i` with `Σδ_i = k·γ` and `Σσ_i = k·x` (the
   standard telescoping-sum identity: for `Σ_i δ_i` to equal `Σ_{i,j} k_i·γ_j
   = (Σk_i)(Σγ_j) = k·γ`, every ordered pair's `α_{ij} + β_{ij} = k_i·γ_j`
   contribution must appear on exactly one side of exactly one party's sum —
   see `signing.zig`'s module doc comment for the full derivation).
4. `δ = Σδ_i` is revealed in the clear (a sum of already-additive shares,
   no MtA needed to open it) → `δ⁻¹` → `R = (Σ Γ_i)^{δ⁻¹} = k⁻¹·G` →
   `r = R.x mod q` (the SAME wide-reduction `std.crypto.sign.ecdsa`'s own
   `Verifier.init` uses for its `r`/`s` canonicalization, so this module's
   `r` and std's recomputed `r` are bit-for-bit comparable).
5. Each party computes `s_i = m·k_i + r·σ_i` (`m` = the message SHA-256
   digest reduced into `Zq` via the exact same wide-reduction
   `std.crypto.sign.ecdsa`'s `Signer.finalizePrehashed` uses internally —
   `signing.zig`'s local `scalarFromHash32` replicates it byte-for-byte) and
   reveals it; `s = Σs_i`, normalized to the smaller of `{s, q-s}`
   (canonical/low-S, BIP-62 convention).
6. **Fail-closed self-check.** Before returning, `signWithShares` verifies
   its own `(r,s)` against `group_public_key` via
   `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256.Signature.verify` — on any
   failure it returns `error.SigningAborted` rather than an invalid
   signature. This is a HARD invariant, tested directly (the decisive test
   chains keygen → signing → std-ECDSA-verify).

**The decisive test** (`signing.zig`, "decisive test — keygen(2,3) -> sign
over 2 shares -> verifies under std EcdsaSecp256k1Sha256"): runs
`root.keygenTrustedDealer(2, 3, ...)`, signs a message over 2 of the 3
resulting `KeyShare`s via `signWithShares`, and asserts the output
genuinely verifies under `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256
.Signature.verify` against `group_public_key`. This chains the WHOLE arc
(Shamir/Feldman keygen → Paillier/ring-Pedersen aux params → checked
MtA/MtAwc with real GG18 Appendix A proofs → the signing arithmetic) to
real standard-library ECDSA correctness — the same "chain the whole arc to
a real external verifier" pattern this repo's `threshold_bls` uses against
`bls_sig`. It PASSES (does not panic) — Phase 2d is not a scaffold.

**Identifiable-abort scope — the one deliberate, documented cut.** GG20's
distinguishing contribution over GG18 is naming a culprit on failure, not
just aborting. This module implements the weaker **"abort-only v1"**: every
check it performs IS fail-closed (a cheating party can never cause a bad
signature to be returned — only an error), but it does NOT close the
specific residual gap of a party using an INCONSISTENT `k_i`/`γ_i`/`w_i`
across different pairwise MtA sessions (each pairwise range/MtA proof
attests only to that ONE session's witness in isolation — nothing here
proves the SAME `k_i` was used in every session a party participates in).
If that happens, step 6's self-check will (overwhelmingly likely) catch the
resulting bad `(r,s)` and abort — so the "never return an invalid
signature" integrity invariant holds regardless — but honest parties learn
only THAT something was inconsistent, not WHO. Closing this (GG20 §4's
actual "Identifiable Abort" rounds: retaining every pairwise MtA transcript
and, on failure, an opening/decommitment sub-protocol that names a culprit)
is left as `signing.identifyAbortCulprit`, `@panic`-stubbed with the
construction referenced (not transcribed — this scaffold pass did not have
that section of the paper open; see the function's own doc comment).

**Const-time posture.** `k_i`/`γ_i`/`w_i`/`s_i` and every MtA/MtAwc
intermediate are SECRET and flow entirely through already-constant-time
primitives this module established in Phase 2b/2c (`Scalar.add`/`.mul`/
`.invert`, `paillier`'s constant-time `pow`/homomorphic ops, `ff`'s
constant-time `powWithEncodedExponent`) — `signing.zig` introduces no new
secret-touching arithmetic beyond composing those calls and the Schnorr
NIZK's own nonce/response (`k + e·γ`, plain `Scalar` ops). The ONE
variable-time step specific to this file is the rejection-sampling retry
loop in `provePoK` (redraws only on the astronomically-rare `IdentityElement`
case, and the loop's own timing reveals nothing about `γ_i` — same posture
as every other rejection sampler in this module). Inherited variable-time
steps (Paillier's `L`-function division inside `decrypt`, safe-prime
search) are documented in their own sections above, not repeated here.

**Bug found and fixed by this pass:** `mta.zig`'s private
`samplePaillierRandomness` (used by `mtaAliceInitChecked`/
`mtaBobResponseChecked` to sample the fresh Paillier blinding factors
`r_a`/`r_b`) checked canonicality mod `pk.n_sq` only, which is nearly a
no-op (`n_sq` is roughly twice `n`'s bit width, so it accepts almost any
masked `n_bits`-wide draw) — silently violating its own documented `[1,
pk.n)` contract and the "`r_a`/`r_b` < N" witness precondition
`zkproofs.zig`'s `proveAliceRangeInner`/`proveBobInner` rely on via `catch
unreachable`. With small/fixed-seed test keys this rarely fired; `
signing.zig`'s end-to-end driver, which calls this sampler far more often
per test run than any prior caller, hit it reliably (~1 in 10 draws with
real 1024-bit keys) and crashed. Fixed by rejection-sampling against `pk.n`
itself before re-encoding the same (now provably in-range) bytes canonical
mod `pk.n_sq` — see the function's updated doc comment. This is a
correctness fix to already-existing Phase-2c wiring, not new Phase-2d
scope; flagged here since it was surfaced by this pass.

## Phase 2a / 2b / 2c / 2d boundary

- **Phase 2a (done, this module):** trusted-dealer Shamir+Feldman keygen,
  each party's Paillier keypair, each party's ring-Pedersen aux params
  (`generateAuxParams`, real). Output: `KeyShare` per party.
- **Phase 2b (done, this module — `mta.zig`):** MtA, the semi-honest
  multiplicative→additive share conversion the parties' `paillier` homomorphic
  ops exist to support. Output: additive shares `α`/`β` with
  `α + β ≡ a·b (mod q)`.
- **Phase 2c (IMPLEMENTED, this module — `zkproofs.zig` + `mta.zig`'s
  `*Checked` functions):** the GG18 Appendix A zero-knowledge range proofs
  (A.1/A.2/A.3, verified against the paper) and the fail-closed checked-MtA
  wiring that upgrade the semi-honest MtA core to malicious security.
  Structs/transcript/wiring AND the six prove/verify functions are real and
  tested (self-consistency + reject contract; pending external review — see
  the section above).
- **Phase 2d (IMPLEMENTED, this module — `signing.zig`):** the online
  threshold-ECDSA signing protocol — the rounds that turn a message + the
  parties' `KeyShare`s + Phase-2c's CHECKED MtA/MtAwc outputs into a single
  valid ECDSA signature verifiable under `KeyShare.group_public_key` via
  `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`. Round orchestration, the
  MtA/MtAwc wiring (including exactly where MtAwc gets invoked — the `k·x`
  share conversion, bound to each party's public verifying share), and the
  signature arithmetic (`δ`/`R`/`r`/`s_i`/`s`) are all REAL; the
  identifiable-abort CULPRIT-NAMING layer is a documented "abort-only v1"
  scope cut (see the dedicated Phase 2d section above).

## Auditor brief — what actually needs a human cryptographer

This section exists because "needs an audit" is worth nothing to the person
who eventually reads it. Below is what a reviewer is being ASKED, phrased as
a property over a named construction, plus why the code cannot settle it.
Everything NOT listed here is closed, wired fail-closed, and fault-tested —
in particular **audit F1 (received-aux validation), F2 (the `N > q⁷`
key-size floor) and F3 (transcript binding of `Γ` + the standard-generator
precondition) are code work and are DONE**; they are not open audit items
and do not need re-adjudication. Do not re-open them; do check the
questions below, which no amount of testing can answer.

**A1 — Special soundness and HVZK of the two DELIBERATE deviations from
GG18 Appendix A.** This module does not instantiate A.3 exactly. In Bob's
proof it samples `gamma ∈ Z_{q⁷}` where the paper samples `gamma ∈ Z_N^*`,
adds a verifier check `t1 <= q⁷` the paper does not have, and widens
`tau` from `Z_{q·Ñ}` to `Z_{q³·Ñ}` to compensate (both hardenings taken
from tss-lib/GG20 practice; see the "Exact bounds used" section).
*Property to check:* (a) special soundness — that a knowledge extractor
still recovers a witness `(b, β', r_B)` from two accepting transcripts with
the narrowed `gamma`, and that the extracted `β'` really is bounded by the
new `t1 <= q⁷` check in the way the Alpha-Rays mitigation claims; (b)
statistical HVZK — that `t2 = e·sigma + tau` with the widened `tau` still
hides `sigma`, and quantify the statistical distance. *Why the code cannot
settle it:* soundness quantifies over ALL provers; the test suite exercises
honest transcripts plus a finite set of hand-crafted cheats. A passing
reject test shows a specific cheat is caught, never that no cheat exists.

**A2 — Completeness of the Fiat-Shamir transcript (post-F3).** The
challenge now absorbs, in order: a per-proof-kind domain tag, `(Ñ, h1, h2)`,
`(N, Γ)`, `c_A` (and `c_B` for the Bob proofs), every first-message
commitment (`z, u, w` / `z, z1, t, v, w`), and for MtAwc the public point
`B` and the Schnorr commitment `u1`. *Property to check:* that this is the
full public input of the statement being proven for each of A.1/A.2/A.3 —
i.e. that nothing remains that a prover could still vary after the challenge
is fixed — and that the domain separation genuinely prevents transplanting a
transcript between the three proof kinds and between this module and
`aux_proofs.zig`'s Πprm/Πmod. Also: the challenge is SHA-256 reduced into
`Zq` by wide reduction; confirm the resulting bias is irrelevant at the
claimed `~1/q` soundness error. *Why the code cannot settle it:* completeness
of a transcript is a claim about the STATEMENT, not about the program. The
tests can show that each absorbed value changes the challenge (they do); they
cannot show that no unabsorbed value matters.

**A3 — Range-guarantee slack as actually used.** The paper concludes "the
Verifier is convinced that `m ∈ [-q³, q³]`" from `s1 <= q³` with
`alpha ∈ Z_{q³}`. This module's real callers feed `m ∈ Z_q` (`k_i`, the
Lagrange-weighted `w_j`) and `β' ∈ Z_q` — far inside the bounds. *Property to
check:* that the honest completeness error stays at the paper's negligible
`~1/q` with these inputs, and that the gap between "proved `≤ q³`" and
"actually `< q`" does not leave an exploitable window when the same party
runs many MtA instances per signing round. *Why the code cannot settle it:*
this is a statement about the amplification of a per-instance slack across
`O(t²)` instances and many sessions — the exact shape of the Alpha-Rays
failure class — and the module tests one instance at a time.

**A4 — Fiat-Shamir instantiation of Πprm/Πmod (`aux_proofs.zig`).**
CGGMP21 Fig.16/17 need `m = 80` independent per-round challenges. This
module derives them by expanding ONE `zkproofs.Transcript` SHA-256 digest
in a local deterministic counter mode. *Property to check:* that this
expansion is a sound instantiation in the random-oracle model (the 80
challenges must be independent, and the prover must not be able to
influence any of them after committing). Related: `Pimod.verify` draws its
Miller-Rabin witnesses deterministically from `SHA256(n_tilde)` — the code
argues this is defense-in-depth only, because soundness rests on the
per-round `z_i^N ≡ y_i` and `x_i^4 ≡ (−1)^{a_i} w^{b_i} y_i` equations;
confirm that argument. *Why the code cannot settle it:* both are ROM
arguments about an adversary's ability to bias a hash output.

**A5 — Audit F5: is `paillier.decrypt`'s L-function division a real leak
here? (Fix lives in `paillier`, judgment lives here.)** `paillier.decrypt`
computes `L(x) = (x−1)/n` with `std.math.big.int`'s variable-time
`divFloor`. The standing note that this is harmless because the decrypted
plaintext is "masked by Bob's fresh uniform `β'` mod N, hence
information-theoretically independent of the nonce `k`" is **NOT a sound
justification as this module is actually wired, and should not be accepted
at face value**: `mta.mtaBobResponseChecked` samples `β' ← Zq`, not `Z_N`,
so the plaintext `a·b + β'` is `k_i·γ_j + β'` — a value up to `~q²` masked
by a `~q` blind. It is not uniform over `Z_N` and it is not independent of
`k_i`. *Property to check:* whether `divFloor`'s running time on
`(x−1)/n` — where `x = c^λ mod n²` is essentially full-width and the
quotient `L(x) = m·µ⁻¹ mod n` is a bijective image of the plaintext —
actually varies with anything a network adversary can correlate against
`k_i`, and if so, whether repeating it across the `O(t²)` MtA instances per
signature and across sessions accumulates into a usable nonce leak. *Why
the code cannot settle it:* this is a quantitative side-channel question
(does limb-granularity timing carry usable information about a bijective
function of a partially-masked secret?), and there is no dudect-class
harness in this toolchain. Outcome should be either a constant-time exact
division in `paillier`, or a *corrected* written rationale replacing the
`β' mod N` one.

**A6 — Protocol composition: Πprm/Πmod is not auto-exchanged online.**
`aux_proofs.proveWellFormed`/`verifyWellFormed` close audit F1's residuosity
gap, but they are an out-of-band SETUP artifact — the online
`signing.runCheckedMtA` path enforces only the always-on structural floor
`AuxParams.validate`. *Property to check:* whether a deployment that
exchanges Πprm/Πmod once at setup, and thereafter trusts the structural
floor per session, is sound — or whether the proofs must be re-verified
against the tuple used in each signing session. *Why the code cannot settle
it:* it is a question about the deployment's protocol composition, not about
either function in isolation.

**A7 — The documented "abort-only v1" cut.** Nothing here proves a party
used the SAME `k_i`/`γ_i`/`w_i` across the different pairwise MtA sessions
of one signing round; step 6's std-ECDSA self-check turns any inconsistency
into `error.SigningAborted` rather than a bad signature. *Property to
check:* that no cheat exists which is inconsistent across sessions yet still
produces a signature step 6 accepts. *Why the code cannot settle it:* same
"quantifies over all provers" reason as A1. (The culprit-NAMING half is a
scope cut, not an audit question — see the Phase 2d section.)

## Backlog / deferred

- Phase 2c: independent cryptographic review of `zkproofs.zig`'s implemented
  constructions against GG18 Appendix A before production use — see the
  **"Auditor brief"** section above for the itemized questions (A1–A7),
  and the dedicated Phase 2c section for the verification-level breakdown.
  Phase 2d inherits this same residual audit debt, since `signing.zig` is
  built entirely on `zkproofs.zig`'s checked MtA/MtAwc.
- Phase 2d: GG20's full identifiable-abort culprit-naming apparatus
  (`signing.identifyAbortCulprit`, `@panic`-stubbed) — see the dedicated
  Phase 2d section above for the exact boundary of what "abort-only v1"
  does and does not cover.
- Phase 2d's Γ commit-reveal knowledge proof (`signing.SchnorrProof`) is a
  standard textbook Fiat-Shamir Schnorr NIZK, not verified byte-for-byte
  against GG20's own `Πzk` instantiation (this scaffold pass did not have
  that section of the paper open) — flagged for an independent check.
- `generateAuxParams` aux-param-correctness ZK proof (Πprm/Πmod): a
  trapdoor-retaining variant, `root.generateAuxParamsWithTrapdoor`, now
  exists (ordinary `generateAuxParams` is unchanged — still discards
  `lambda`, per its own doc comment's retention decision). Distinct from
  `zkproofs.zig`'s MtA range proofs — this one is about proving the AUX
  PARAMS themselves were generated correctly, not about proving a Paillier
  plaintext's range. **Closed (audit F1): `root.AuxParams
  .validate` enforces the cheap structural preconditions (composite `Ñ`,
  `1 < h1,h2 < Ñ`, coprimality, Jacobi `(h/Ñ)=+1`) fail-closed on every
  received tuple, and the full zero-knowledge `Πprm`/`Πmod` fix — the part
  the Jacobi check is NECESSARY-but-not-SUFFICIENT for — is now IMPLEMENTED
  in `aux_proofs.zig` (CGGMP21 Fig.16/17): struct/codec/Fiat-Shamir-transcript
  wiring AND the two proof cores are real and KAT-tested (including the
  crafted-parameter scenarios — a 3-prime `Ñ` and an `h2 ∉ ⟨h1⟩` pair — that
  both pass `validate` yet are REJECTED by `verifyWellFormed`),
  `gate.aux_proofs_core_implemented` flipped `true` — see the dedicated
  "Πprm / Πmod" section above. The one residual item is an independent
  cryptographic review of the Fiat-Shamir instantiation before production
  MPC-custody use (question **A4** in the "Auditor brief" section).**
- Full Pedersen-style DKG (no single dealer) — a distinct follow-up module,
  not a `splitSecretKey` signature change.
- Minimum-key-size floor: NOW ENFORCED where it matters for security — every
  RECEIVED Paillier `N` and aux `Ñ` on the checked-MtA / zkproofs path must
  clear `N > q⁷ ≈ 2^1792` (`root.paillierNMeetsFloor` / `nTildeMeetsFloor`),
  fail-closed at both prove and verify entry points (audit F2). The generic
  `AuxParams`/`PublicKeys`/`KeyShare`/`paillier` `fromBytes*` CODEC paths
  deliberately do NOT floor (they parse generic wire values, including the
  small toy moduli the serialization tests round-trip); the floor is a
  checked-path security precondition, applied where the params are actually
  consumed by a range proof, not a byte-codec concern. `paillier`'s own
  "minimum-key-size floor on `fromBytes`" backlog item is unaffected —
  `paillier` stays a general-purpose module and does not impose this
  threshold-ECDSA-specific `q⁷` floor.
