# dkg — SPEC

Secure Distributed Key Generation (GJKR) for `threshold_ecdsa` over secp256k1.

## Goal

Remove the trusted-dealer assumption from `threshold_ecdsa`. Today
`threshold_ecdsa.keygenTrustedDealer` takes a plaintext secret `x`, Shamir-splits
it, and hands out shares — one party (the dealer) sees `x`. This module lets `n`
parties **jointly** generate the same key material with no party ever holding
`x` and no dealer to trust, closing the standing audit debt recorded in the
`threshold_ecdsa` ZK-audit note ("Pedersen DKG … removes trusted-dealer
assumption").

## New module vs. extend `threshold_ecdsa`

**New module `dkg`**, depending on `threshold_ecdsa` + `paillier`. Rationale:
`threshold_ecdsa` is a large module already (keygen + aux-params + MtA + range
proofs + signing + aux-proofs, ~10k lines). The DKG is a distinct
*multi-round message protocol* with its own message types, adversary model, and
round driver — a different verification shape (adversarial round-sim, not
byte-exact KAT). Keeping it separate keeps `threshold_ecdsa` a
key-material-and-signing library and lets `dkg` own the protocol layer, exactly
as `raft`/`df-elect` are separate from what they coordinate. `dkg` consumes
`threshold_ecdsa`'s public `KeyShare`/`Element`/`Scalar`/`reconstructSecret`
surface and produces `KeyShare`s it can sign with.

## frost-dedup verdict (the tiering call)

**No dedup, and genuinely-new Fable work.** `frost` (RFC 9591) does **not** have
a DKG — it has `trustedDealerKeygen` only, and RFC 9591 / `frost`'s own SPEC
declare distributed key generation *explicitly out of scope* ("RFC 9591 does not
specify one; out of scope by the RFC's own admission"). So there is no existing
in-repo DKG to adapt. Even if there were, FROST's would be Schnorr-shaped
(single-round signing, Feldman-only PoK-of-knowledge keygen); the *secure ECDSA*
DKG here is different in kind: **GJKR's Pedersen-then-Feldman bias-prevention**,
the complaint/QUAL/disqualification machinery, and integration with the
threshold-ECDSA share/`KeyShare` structure.

Against the repo's Fable-tier heuristic: F-DKG is Fable because **(a)** there is
no external byte-exact KAT — GJKR is a randomized interactive protocol with no
published answer vector, so a self-consistent-but-wrong implementation can pass
naive round-trip tests — **and (b)** it is distributed-protocol soundness under a
rushing/Byzantine adversary (nontrivial design space), verified in an adversarial
round-sim like `raft`/`df-elect`, not by transcription against a golden file.
This is the same shape as Raft's Figure-8 or df-elect's partition safety, not the
ECVRF/IBE/DPF "transcribe-to-KAT" shape that was honestly re-tiered to Sonnet.

## The construction (GJKR, secret-key DKG)

Curve secp256k1; `g` = base point; `h` = a nothing-up-my-sleeve second generator
with unknown `log_g h` (`commit.pedersenH`, try-and-increment hash-to-curve).
`t`-of-`n`; sharing polynomials have degree `t − 1`.

- **Round 1 (Pedersen-VSS deal).** Each `P_i` picks two random degree-`(t−1)`
  polynomials `f_i(z) = Σ a_ik z^k`, `f'_i(z) = Σ b_ik z^k` (its contributed
  secret is `a_i0`). It **broadcasts** Pedersen commitments
  `C_ik = g^{a_ik} h^{b_ik}` and **sends** each `P_j` the shares
  `s_ij = f_i(j)`, `s'_ij = f'_i(j)`.
- **Round 2 (complain → QUAL).** Each `P_j` checks every received share against
  the commitment: `g^{s_ij} h^{s'_ij} == Π_k C_ik^{j^k}`. A failure is a
  **complaint**. A dealer is **disqualified** iff it has an undefended complaint
  (cannot reveal a matching opening) or is complained about by more than `t`
  parties. The surviving dealers form **QUAL**. QUAL is fixed here, from Round-2
  data **only**.
- **Extraction (bias-prevention crux).** *Only after QUAL is fixed*, each QUAL
  dealer broadcasts **Feldman** commitments `A_ik = g^{a_ik}`; others check
  accepted shares `g^{s_ij} == Π_k A_ik^{j^k}`. The public key is
  `Q = Π_{i∈QUAL} A_i0 = g^{Σ a_i0}`; each party's share is
  `x_j = Σ_{i∈QUAL} s_ij`, with `Q = g^x` and any `t` shares Lagrange-
  reconstructing `x`. Committing (Pedersen) before revealing (Feldman) is what
  denies a rushing adversary the ability to bias `Q`.

## Fable-vs-mechanical split

**Fable-irreducible core — `core.zig`, five functions (gated `@panic`):**

1. `verifyPedersenShare` — the Round-2 share-vs-commitment equation
   `g^s h^{s'} == Π_k C_k^{j^k}` (the binding property; must catch an
   inconsistent share with probability 1).
2. `verifyFeldmanShare` — the extraction share-vs-Feldman equation
   `g^s == Π_k A_k^{j^k}`.
3. `computeQual` — the complaint/defense/disqualification → QUAL logic, decided
   from Round-2 data **only** (the ordering that prevents bias).
4. `deriveGroupPublicKey` — `Q = Σ_{i∈QUAL} A_i0`, summed over exactly the
   fixed QUAL set.
5. `combineKeyShare` — `x_j = Σ_{i∈QUAL} s_ij`.

**Honest tiering note.** Of the five, the verification *equations* (1, 2) are
individually close to mechanical multi-exponentiation checks; the genuine
Fable content is the **QUAL/disqualification logic (3)** and the **two-phase
Pedersen-then-Feldman ordering discipline** that (3)+(4) enforce — that is where
a rushing/Byzantine adversary must be unable to bias `Q` or learn an honest
share, and where a self-consistent implementation can silently be insecure. The
five are gated together because they form one soundness unit (the driver calls
all five and the invariants only hold if all are correct); the boundary follows
the task's stated Fable line (share-verification + complaint/QUAL + bias-
prevented extraction).

**Mechanical scaffold (real today) — everything else:** polynomial evaluation,
Pedersen/Feldman commitment vectors, the `h` generator, the multi-exponentiation
`Π_k C_k^{j^k}` (`commit.zig`); all wire codecs (`types.zig`); the synchronous
round driver and the `BrokenDkg` positive control (`protocol.zig`); the
invariant checkers (`checks.zig`); the `assembleKeyShares` bridge and the
end-to-end anchor (`root.zig`).

## Verification harness (the teeth)

- **End-to-end anchor (best teeth).** Run the DKG → `assembleKeyShares` (attach
  Paillier/aux) → `threshold_ecdsa.signWithShares` → verify with std ECDSA under
  `Q`. A DKG whose key yields a valid std-verifiable signature is correct and
  usable; this needs no external vector. GATED on the core.
- **Correctness invariants** (`checks.zig`): all honest parties output the same
  `Q` (`allSameQ`); any `t` shares Lagrange-reconstruct `x` with `x·G == Q`
  (`reconstructsToQ`); each `X_j == x_j·G` (`verifyingShareConsistent`).
- **Adversarial (Byzantine) tests.** A dealer that sends a share inconsistent
  with its Pedersen commitment must be detected (complaint), and — if it cannot
  defend — disqualified from QUAL; a defended (transient) bad share is tolerated
  and the receiver adopts the revealed opening. GATED on the core.
- **Positive control (runs today, no gated code).** `BrokenDkg` skips the
  share-vs-commitment verification and naively sums every wire share. Fed a
  Byzantine bad share, it emits an unusable key, and `reconstructsToQ` catches
  it (`x·G != Q`) for any subset including the poisoned party while a clean
  subset still reconstructs — proving the checker discriminates, not blanket-
  fails, before the core exists.

## Why a synchronous round-driver, not `netsim`

`netsim` models *network* faults (crash/partition/reorder/clock-skew) over an
async byte channel — the right tool for `raft`/`df-elect`. GJKR's hard property
is different: cryptographic-content soundness under a **synchronous broadcast**
assumption (the protocol requires it, and reveals Feldman commitments only after
QUAL is fixed). The adversary sends a well-formed message with a
mathematically-inconsistent share, not a late/dropped one. A lockstep in-process
driver models the protocol's own synchrony, injects exactly that content-fault,
and lets the checker read QUAL and every output directly. `netsim` remains the
right host for a future *asynchronous* DKG variant and is deliberately not used
here.

## Out of scope (later increments)

- **CGGMP21 signing-phase identifiable abort** (naming a culprit during signing)
  — a separate increment on top of `threshold_ecdsa` signing.
- **Proactive refresh / re-sharing** (rotate shares without changing `Q`).
- **Distributed aux-parameter generation** (jointly producing the ring-Pedersen
  `(Ñ, h1, h2)` and Paillier moduli). Here those are per-party local key material
  attached by `assembleKeyShares`.
- **Public reconstruction of a QUAL dealer that fails the Feldman check** (GJKR
  Fig.2 step 4's recovery branch) — Phase 1 treats that as a hard protocol error;
  a defended Round-2 complaint is handled.

## Meta

`platform = .any` (pure protocol logic, verified in-process; no OS/network I/O) ·
`role = .util` · `concurrency = .single_owner` · deps `threshold_ecdsa`,
`paillier` · `model_after` GJKR (J. Cryptology 2007).
