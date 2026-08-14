# coconut — SPEC

Auditor/design reference for the `coconut` module. Purpose + API live in
`README.md`; this file is the construction, the reuse map, the anchor/tier
finding, the Fable-vs-mechanical split, and the deferred increments.

## 1. Construction (Coconut, NDSS 2019, §4)

Type-3 pairing over `bls12_381` (`G1`, `G2`, `Gt`, `e: G1×G2→Gt`). `q`
attributes, `t`-of-`n` authorities.

- **Setup(q)** — public params: the curve generators `g1`, `g2` (constants) and
  `q` independent attribute generators `hs = (h₁…h_q) ∈ G1`, derived
  nothing-up-my-sleeve via RFC 9380 `hashToCurveG1` of an index tag. The
  attribute commitment is `cm = Σ [mᵢ] hᵢ`, and the per-credential **common
  base** is `h = hashToCurveG1(cm)` — deterministic, so every authority signs
  under the SAME `h` (this is what makes the partials Lagrange-aggregatable).

- **KeyGen (§4.4 `TTPKeyGen`, trusted dealer)** — master secret
  `sk = (x, y₁…y_q) ∈ Fr^{q+1}`; each component is Shamir-shared with an
  independent degree-`t−1` polynomial, evaluated at authority indices `1..n`.
  Verification key `vk = (α, β₁…β_q) = (g2^x, g2^{yᵢ}) ∈ G2^{q+1}`; each
  authority publishes its own `vk` share; the group `vk` is recovered by
  Lagrange-**in-exponent** over any `t` shares.

- **Sign (§4.2, per authority)** — authority `j` returns the partial credential
  `σⱼ = (h, sⱼ)` with `sⱼ = [x(j) + Σ mᵢ yᵢ(j)] h`.

- **AggCred (§4.4)** — `σ = (h, Σ [lⱼ] sⱼ)` where `lⱼ` is authority `j`'s
  Lagrange coefficient at `x = 0`. By linearity the exponent Lagrange-
  reconstructs to `x + Σ mᵢ yᵢ`, so `σ` is byte-equal to a single-signer PS
  signature under the reconstructed `sk`.

- **ProveCred / Show (§4.2)** — re-randomise `σ → σ' = ([r'] h, [r'] s)`; build
  the ZK commitment `κ = α · Π βᵢ^{mᵢ} · [r] g2` and `ν = [r] σ₁'`; produce a
  Fiat-Shamir NIZK proving knowledge of the **hidden** attributes and the
  blinding `r`. Disclosed attributes are sent in the clear.

- **VerifyCred (§4.2)** — recompute the challenge over the transcript, check the
  NIZK responses, enforce `σ₁' ≠ 1`, and verify `e(σ₁', κ) == e(σ₂' · ν, g2)`.

### 1a. Fiat-Shamir transcript (`showChallenge`)

There is **no external byte-exact vector** for the show proof (§3), so soundness
rests entirely on the challenge binding every commitment. The challenge is
`Fr.reduceWide(SHA-512(‖ transcript))` over these fields, in order; every field
is fixed-width given `q`, so the encoding is injective (no concatenation
ambiguity):

1. `show_challenge_dst` — domain separation (scheme / curve / transcript version);
2. `q` (u64 BE) — attribute count, frames every vector below;
3. `hs[0..q]` (G1, 48 B each) — the attribute generators / parameter set;
4. `vk.alpha` (G2, 96 B) then `vk.betas[0..q]` (G2, 96 B each) — the authority
   key the statement is relative to (a proof must not transplant to another set);
5. `σ₁'`, `σ₂'` (G1, 48 B each) — the re-randomised credential being shown;
6. `κ` (G2, 96 B), `ν` (G1, 48 B) — the statement group elements;
7. **`Aw` (G2, 96 B), `Bw` (G1, 48 B)** — the sigma-protocol commitments. These
   are the strictly, **directly** load-bearing FS binding: omit either and the
   challenge is straight-line forgeable (an attacker solves `Aw := [z_r]g2 +
   Σ[zⱼ]βⱼ − c(κ−A)` for arbitrary responses and every naïve round-trip still
   passes). Owner-verify confirmed this empirically: dropping `Aw` makes a
   tampered-hidden-response forgery WRONGLY verify.
8. `disclosed` mask (q bytes, 0/1) — which indices are claimed revealed;
9. `n_disclosed` (u64 BE), then per disclosed index ascending: `index` (u64 BE) ‖
   `value` (32 B) — the claimed revealed values.

The recompute-commitment verifier (`Aw' = [z_r]g2 + Σ_hidden[zⱼ]βⱼ − [c](κ−A)`,
`A = α·Π_disclosed βᵢ^{vᵢ}`; `Bw' = [z_r]σ₁' − [c]ν`) transitively binds `κ`, `ν`,
`σ₁'`, the responses, the disclosure mask, and the disclosed values into the
challenge, and the final pairing `e(σ₁',κ)==e(σ₂'·ν, g2)` binds `σ₂'` and the
credential-to-attribute correspondence. So `Aw`/`Bw` are directly load-bearing in
the hash; the other elements are additionally, transitively bound (owner-verify:
dropping `σ₂'` from the hash does NOT let a σ₂'-swap through — the pairing rejects
it).

## 2. Reuse map

| Need | Source | How |
|---|---|---|
| `Fr` scalar field, `G1`/`G2` groups, pairing, hash-to-curve | `bls12_381` (imported) | all field/group/pairing/H2C math — this module adds none |
| Lagrange coefficient at 0, Shamir eval | `frost`/`bls12_381.threshold` (**pattern, not import**) | those are over secp256k1 / min-pk BLS; reimplemented over `Fr` in `lagrange.zig` (`coefficientAtZero`) + `keys.zig` (`evalPoly`) |
| selective-disclosure Fiat-Shamir NIZK shape | `bbs` (**design reference**) | `bbs.proofGen/proofVerify`'s transcript/challenge discipline is the closest sibling; Coconut's show proof is the analogous NIZK over PS instead of BBS |
| threshold DKG (dealer-free) | `dkg` (**deferred**) | keygen is trusted-dealer in Phase 1; the `dkg`-style dealer-free wiring is a later increment |

Only `bls12_381` is an actual build dependency; `frost`/`dkg`/`bbs` are sibling
modules in this repo reused as *pattern* references (different curve / deferred),
not third-party source. Clean-room from the NDSS 2019 paper — no third-party
source ported or studied as a design reference, so no `NOTICE` entry (CONVENTIONS
§5, same as `bbs`/`frost`/`dkg`). `asonnino/coconut` + `nymtech/coconut` were
consulted only black-box (the §3 vector question).

## 3. Anchor / tier finding (the decisive call)

**Is there a public byte-exact deterministic test vector?** No. The reference
implementations — `asonnino/coconut` (Python), `nymtech/coconut` (Rust/Go),
`evernym/coconut-rust` — are cross-compatible at the *protocol* level but publish
**no fixed-randomness golden fixtures**, and there is **no IETF draft / RFC / CFRG
ciphersuite** standardising a Coconut wire form. Their tests are randomized
round-trip / property tests (`rand`-seeded ElGamal blinding + Fiat-Shamir
witnesses). Unlike `bbs` — which *does* have official IETF draft fixtures
reproducible under a mocked deterministic RNG — Coconut has nothing to pin the
sub-operations against byte-exact.

**Tier call → genuine Fable.** Per this repo's Fable-tier heuristic
(`CONVENTIONS`-adjacent, memory `feedback_fable_tier_heuristic`): a construction
with **no external byte-exact anchor**, whose self-consistent tests can
pass-while-being-unsound, is genuine Fable. The weight is concentrated in the
**selective-disclosure NIZK** (`proveCredential`/`verifyCredential`) — exactly as
`bbs`' hard core is `proofGen`/`proofVerify`, not `sign`/`verify`. The classic
real-world break (omitting a commitment — `ν`, a disclosed index, or `κ` — from
the Fiat-Shamir challenge) yields a proof that verifies against itself but is
forgeable, and no golden vector would catch it; only the independent soundness
controls do. Coconut is therefore *more* Fable than `bbs` (which at least had the
IETF mocked-RNG fixtures). Honest per-core tiering:

- `signPartial` — Sonnet-tier in isolation (a share-keyed PS scalar-mul).
- `aggregateCredential` — Sonnet/Opus-tier (Lagrange-in-exponent; the mechanical
  helper `lagrange.coefficientAtZero` already exists and is tested; the residual
  is index/threshold bookkeeping + the mutual-consistency contract with the base
  `h`).
- `proveCredential` / `verifyCredential` — **genuine Fable** (Fiat-Shamir
  soundness, correct transcript, re-randomisation tying `κ`/`ν` into the pairing
  equation while binding the hidden attributes).

All four are gated under a single flag because they are mutually dependent: the
NIZK can only be exercised over a valid aggregated credential, which only exists
once the partials do (the same single-flag rationale `bbs`/`bulletproofs`
document).

## 4. Fable-vs-mechanical split

**Mechanical (written here, REAL, tested today):** `params.zig` (Setup,
generators, `commonBase`), `keys.zig` (threshold keygen, `vk` derivation,
Lagrange-in-exponent `vk` aggregation), `lagrange.zig` (`coefficientAtZero`),
all wire codecs, and `credential.zig`'s `psSignWithSecret` (single-signer PS from
known scalars) + `psVerifyPlain` (the `e(h, α·Πβᵢ^{mᵢ}) == e(s, g2)` pairing
verify with the `h ≠ 1` guard).

**Fable core (`gate.fable_core_implemented`, now `true`):** the four functions of
§3 — implemented, with the show-proof NIZK's full Fiat-Shamir transcript (§1a).

## 5. Verification harness (teeth)

- **Positive control (REAL, passes today, no gated code on its path):**
  `harness_test.BrokenCoconut` mechanically produces partial signatures under the
  known Shamir shares and aggregates them two ways — correct Lagrange weights vs
  all-ones weights. `psVerifyPlain` **accepts** the Lagrange aggregation (and it
  byte-matches the `psSignWithSecret` oracle) and **rejects** the Lagrange-
  ignoring one. A second control shows two distinct `t`-quorums aggregate to the
  *same* credential. This proves the pairing-check + Lagrange-in-exponent teeth
  before the core exists — the anti-self-consistency backbone.
- **Mechanical unit tests:** generator distinctness/subgroup, `commonBase`
  determinism + attribute-sensitivity, scalar-field Shamir reconstruction,
  Lagrange-in-exponent `vk` round-trip, `psVerifyPlain` tamper/wrong-attribute/
  identity-`h` rejection, and codec round-trips (incl. a hand-built `ShowProof`).
- **End-to-end anchor + soundness controls (executed, `gate` now `true`):**
  threshold-issue → aggregate → re-randomise + selective-disclosure show → verify
  PASSES; and a wrong disclosed value / mutated Fiat-Shamir challenge /
  too-few-partials / **forged undisclosed attribute** (a fully self-consistent
  proof over a credential the prover holds but lying about a hidden attribute
  value — caught by the PS pairing backstop) all FAIL. This is the anchor — there
  is no external byte-exact vector to pin against (see §3), so it is the internal
  end-to-end property plus the soundness rejections. Owner-verify additionally
  reproduced tampered κ/ν/σ₁'/σ₂'/response/hidden-response, σ₁'=identity, wrong
  vk, disclosure-count mismatch, and a same-cardinality mask-shuffle (all reject),
  and confirmed `Aw`/`Bw` are directly load-bearing in the transcript (§1a).

## 6. Deferred increments (out of Phase-1 scope)

- **Blind issuance (§4.3):** ElGamal-encrypt the *private* attributes + the
  formation NIZK `π_s`, so the issuer never sees them; `blindSign` on the
  ciphertext; `unblind`. Phase 1 does public-attribute issuance (attributes are
  known to the authorities); selective disclosure at SHOW time is fully present
  regardless (it hides attributes from the *verifier*, orthogonally to hiding
  them from the *issuer*). The `params.hs` generators are already carried for
  this path.
- **Dealer-free keygen:** replace `TTPKeyGen` with a `dkg`-style distributed
  protocol (removes the trusted dealer).
- **Multi-authority / cross-credential optimizations, SHAKE ciphersuite,
  aggregated-attribute batching.**

## Public test-only entry points, unguarded

`keygenSeededForTest` and `proveCredentialSeededForTest` are public and carry no
`!builtin.is_test` + `@compileError` guard, so a non-test consumer can call them
and get deterministic keys and proofs. Recorded rather than fixed: the guard is
cheap, but adding it is a breaking API change for anything already importing
them. Do not use either outside a test.


## Anchoring

**Anchor grade:** class B · oracle SELF

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle SELF** — round-trip and/or hand-authored fixtures only — the weakest grade.

**What the tests actually contain.** SPEC.md §3: "no external byte-exact vector" for Coconut, explicit Fable tier

**How it got there.** No external oracle exists for what remains. SPEC §3: no public vector; asonnino/nymtech impls use incompatible serialization
