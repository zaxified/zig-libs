# groth16 — SPEC

Design, threat model, and the **Fable-vs-Opus tier call** for a Groth16
zk-SNARK prover over BN254. Purpose/API live in [README.md](README.md); this
document answers *how/why it is built and what could go wrong*.

## 1. Construction

Groth16 (Jens Groth, EUROCRYPT 2016, *"On the Size of Pairing-based
Non-interactive Arguments"*) is the smallest, fastest-to-verify pairing-based
zk-SNARK: a constant 3-element proof `(πA ∈ G1, πB ∈ G2, πC ∈ G1)` and a
single multi-pairing verification equation, per circuit-specific trusted setup.
The prover pipeline:

1. **R1CS → QAP.** The circuit is a rank-1 constraint system: `m` constraints
   `(Aᵢ·w)·(Bᵢ·w) = (Cᵢ·w)` over a witness vector `w`. Fixing an evaluation
   domain of `n` roots of unity (`n ≥ m`, a power of two), the columns of the
   `A`/`B`/`C` matrices become polynomials by Lagrange interpolation; the
   witness dot products at each domain point are the sampled values.
2. **FFT over `Fr`.** Interpolation is an inverse NTT; forming the quotient
   `H(x) = (A(x)·B(x) − C(x)) / Z(x)` (where `Z(x) = x^n − 1` is the vanishing
   polynomial of the domain) uses the forward/inverse NTT and polynomial
   multiplication. A satisfying witness makes `A·B−C` vanish on the whole
   domain, hence divisible by `Z`.
3. **MSM in `G1`/`G2`.** The three proof elements are multi-scalar
   multiplications of the witness / `H`-coefficient vectors against the
   proving key's precomputed group elements, plus the zero-knowledge
   randomizers `r, s ∈ Fr`.
4. **Proving key / CRS.** The circuit-specific structured reference string,
   from a (per-circuit) trusted setup.

## 2. Reuse map — the sibling `bn254` module is the whole anchor

This module is pure composition over [`bn254`](../bn254/); it re-implements no
field, curve, or pairing arithmetic.

| Needed | Source in `bn254` |
|---|---|
| Scalar field `Fr` (`add`/`mul`/`inv`/`pow`/`fromBytes`) | `bn254.Fr` (`scalar.zig`) |
| Groups `G1`/`G2` (Jacobian add/double/`scalarMul`, affine codec) | `bn254.G1`/`bn254.G2` |
| Optimal-ate pairing + `pairingCheck` | `bn254.pairing` |
| **Groth16 VERIFIER** — `VerifyingKey`/`Proof` types + `verify` | `bn254.groth16Verify` (`groth16.zig`) |
| A REAL accepting proof (Dark Forest v0.3 snarkjs KAT) | embedded in `bn254/src/groth16.zig` |

The verifier's proof/key types (`{a: G1, b: G2, c: G1}` /
`{alpha_g1, beta_g2, gamma_g2, delta_g2, ic[]}`) are re-exported here as
`prover.Proof` / `prover.VerifyingKey`, so `prove`'s output feeds straight into
`bn254.groth16Verify`. The verifier's own `Fr` scalar has 2-adicity 28 (`r−1`
divisible by `2^28`), which is exactly what the FFT domain needs — no new
root-of-unity machinery, just powers of the known generator `5`.

**No pre-existing FFT-over-`Fr`, MSM helper, or R1CS/QAP type existed** in the
repo to reuse: `bfv`'s NTT is over word-size NTT primes (`Z_q`), not `Fr`;
`falcon`'s FFT is over ℂ; `bn254`'s verifier has only a private public-input
accumulation loop, not an exported MSM. All four (`poly`/`domain`/`fft`/`msm`
+ `r1cs`/`qap`) are new here, built clean-room from the construction.

## 3. Phase-1 scope + sub-split

**Real + ungated (this scaffold):** everything feeding the prover —
`field`, `poly` (incl. exact division by `Z=x^n−1`), `domain` (roots of unity,
vanishing poly), `fft` (radix-2 NTT/INTT + FFT multiply), `msm` (naive `G1`/
`G2`), `r1cs` (constraint system + satisfaction), `qap` (interpolation + the
`A·B−C` divisibility oracle). Plus the deliberately-broken positive control.

**Prover core (Part 2, now shipped — `gate.prover_core_implemented = true`):**
`prover.setup` (toy trusted setup) and `prover.prove` (the proof assembly).
The end-to-end `prove→verify` anchor runs green (see §6).

## 4. CRS approach — toy setup first, snarkjs `.zkey` deferred

Phase 1 designs two anchor paths and scaffolds toward the first:

- **Toy trusted setup (Phase-2 default).** `setup(n, sys, tau)` samples the CRS
  from an explicit, INSECURE toxic-waste `tau` (a real deployment runs an MPC
  ceremony). Fully self-contained — no external files — and deterministic, so
  the end-to-end anchor (`prove → bn254.groth16Verify == true`, plus tamper →
  `false`) needs nothing but this repo. This is the recommended Phase-2 target.
- **snarkjs `.zkey` + witness ingestion (Phase-3, deferred).** The strongest
  external anchor: parse a snarkjs proving key + witness for a known circuit
  (e.g. the same Dark Forest artifacts the `bn254` verifier already pins),
  produce our proof, and confirm it verifies. Under fixed `r, s` this can be
  pushed to a byte-exact match against snarkjs's own proof — the gold-standard
  cross-implementation anchor. Deferred because it needs a `.zkey`/`.wtns`
  binary parser (a mechanical but sizable codec), out of a Phase-1 scaffold.

## 5. The Fable-vs-Opus tier call — **this core is Opus, not Fable**

This is the key deliverable. The matured Fable-tier heuristic
(`~/CML/BACKLOG-todo.md`, `feedback_fable_tier_heuristic`) is: **a complete
deterministic anchor pushes a task toward Opus; Fable is reserved for cores
where self-consistent tests can pass while the code is subtly wrong** (no oracle
catches it) — FHE noise budgets, a NIZK soundness argument with no checking
oracle, a lattice sampler's timing distribution.

For a **Groth16 prover, the `bn254` verifier is a complete deterministic
oracle.** A correct prover's output verifies; ANY error — a wrong QAP
coefficient, a swapped witness index, a wrong sign, a missing `/Z` division, a
mis-placed `r`/`s` randomizer, a wrong CRS element — makes
`bn254.groth16Verify` return `false`. There is **no self-consistent-but-wrong
failure mode** the verifier misses. Every sub-step is additionally
KAT/round-trip anchored (NTT round-trip, FFT==schoolbook, MSM==naive, QAP
divisibility==R1CS satisfaction). Published construction (Groth 2016) + a
complete anchor ⇒ **Opus**.

Assessed piece by piece, honestly:

| Piece | Anchored by | Tier |
|---|---|---|
| FFT / NTT over `Fr` | round-trip + `==` schoolbook | Opus (mechanical) |
| MSM `G1`/`G2` | `==` naive scalar-mul sum | Opus (mechanical) |
| R1CS → QAP interpolation | divisibility `==` R1CS satisfaction | Opus (mechanical) |
| Quotient `H = (A·B−C)/Z` | exact-division oracle + verifier | Opus |
| Toy trusted setup + `prove` assembly | `bn254.groth16Verify` (complete) | **Opus** |

**Is there ANY genuinely-Fable piece?** No. Unlike `fss` (whose correction-word
construction can leak/misreconstruct in ways a self-consistent test misses,
needing an independent KAT) or `bfv` (whose `mul` decrypts to garbage under a
subtly-wrong rescale that only a noise-ledger argument rules out), the Groth16
prover has nowhere to hide: the verifier is the ground truth and it is in-repo.
**F-SNARK de-tiers to Opus, the same way F-FSS's *verifier-anchored* parts did.**
This is a valid, valuable finding — not every "F-vein" task is Fable, and
saying so protects the Fable budget for cores that actually need it.

**Recommendation: Phase 2 (the toy-setup + `prove` core) goes to Opus.** Fable
is not warranted for any part of this module.

### 5a. Correction (2026-08-02) — the "complete oracle" claim had one blind spot

The tier call above is right about the **algebra**: `bn254.groth16Verify` does
catch any wrong QAP coefficient, witness index, sign, or randomizer. But it is
this SAME implementation's own decoder reading this SAME implementation's own
encoder — it cannot see a *serialization* convention (coordinate order,
endianness, a swapped `G2` pair) that both sides silently agreed on, because
such a bug round-trips through our own `Proof`/`VerifyingKey` structs cleanly
forever. That gap needed a genuinely FOREIGN verifier judging our own encoded
bytes, not another reading of the same in-repo types.

Closed: `src/snarkjs_export.zig` renders this module's `Proof`/
`VerifyingKey`/public inputs into the exact JSON shape `snarkjs` parses
(reverse-engineered from `snarkjs@0.7.6`'s own bundled source, not guessed),
and `src/snarkjs_kat_test.zig` freezes a run of the real, independently
-authored `snarkjs@0.7.6` (fetched via `bunx`, Apache-2.0, never vendored)
accepting a proof from this module's own `setup`/`prove` — first try, no
serialization deviation found — and rejecting a one-limb-tampered copy. See
that file's module doc comment for the full transcript (including a Bun
-runtime crash on the literal CLI invocation, worked around without touching
snarkjs's own verification logic) and this module's anchor record (`SPEC.md` § Anchoring) for
the bookkeeping. What remains self-oracle, correctly: the QAP/R1CS layer —
`snarkjs` was only ever shown the final group elements, never our R1CS, so it
has no opinion on whether a proof corresponds to its circuit's intended
semantics. That is a legitimate end state (no external vector exists for a
custom circuit's intermediate polynomials), not remaining anchor debt.

## 6. Verification harness — teeth today

Runs today, no gated code (see `fft.zig`/`msm.zig`/`qap.zig`/`prover.zig`
tests):

- **Sub-anchors.** NTT round-trip identity; `fft.mulViaFFT == poly.mulSchoolbook`;
  `msm` single-term/linearity `==` `G.scalarMul`; `domain` root-of-unity
  primitivity (`ω^n==1 ∧ ω^{n/2}≠1`), points vanish under `Z`.
- **QAP divisibility oracle.** `qap.checkDivisible` `==` `r1cs.isSatisfied`
  over a swept family of witnesses (satisfying and non-satisfying) — the
  self-contained proof that the interpolation/vanishing-division stack is
  correct.
- **Positive control.** `bn254.groth16Verify` REJECTS `prover.brokenProof()`
  (generator points — not a real proof), proving the end-to-end anchor has
  teeth before `prove` exists.

End-to-end (now live — `gate.prover_core_implemented == true`, Part 2):

- **End-to-end.** `prove(setup(…)) → bn254.groth16Verify == true` on a
  non-trivial circuit (4 constraints, 3 public inputs: `out1=x²`, `out2=y²`,
  `out3=(x+y)²`); tampered proof (negated `πA`/`πC`) / wrong public input /
  non-satisfying witness → `false`.

All pass, Debug **and** ReleaseFast.

## 7. Deferred increments (out of Phase 1)

- The prover core itself (`setup` + `prove`) — Phase 2, **Opus**.
- snarkjs `.zkey` / `.wtns` ingestion + byte-exact snarkjs cross-check — Phase 3.
- Pippenger / bucket-method MSM (the naive loop is correct but O(n) group ops;
  a real SNARK-scale prover wants sub-linear MSM).
- A circuit / gadget DSL (hand-built R1CS only, for now).
- Universal / updatable setup, custom gates, **PLONK / Halo2** — deliberate
  scope non-goals: the backlog flags these as the scope-explosion Groth16 was
  chosen to avoid.
- Proof recursion / aggregation.

## 8. Provenance

Pure clean-room-from-spec (Groth 2016) — no third-party source ported, no
implementation studied as a design reference beyond the public construction, so
no `NOTICE` entry is required (CONVENTIONS.md §5, merger doctrine). The one
external datum, the generator `5` and 2-adicity 28, is a property of BN254's
`Fr` re-derived and asserted by this module's own tests (`domain.zig`), not
transcribed. The anchor's KAT (Dark Forest v0.3 proof) lives in and is
accounted for by the `bn254` module, not restated here.

## Anchoring

**Anchor grade:** class B · oracle MIXED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** verifier anchored via bn254 Dark Forest snarkjs KAT; QAP/R1CS layer self-oracle only

**How it got there.** The anchoring work landed. CLOSED 2026-08-02: ran our own setup+prove for the module's existing nt fixture (harness_test.zig's 4-constraint/3-public-input circuit, fixed toxic waste + r,s), exported it through a new snarkjs_export.zig (JSON shape reverse-engineered from snarkjs@0.7.6's own bundled source: decimal-string field elements, G1=[x,y,"1"], G2=[[c0,c1],[c0,c1],["1","0"]] MATH order), and ran a REAL snarkjs@0.7.6 (fetched via bunx, Apache-2.0, never vendored) against it. Literal `bunx snarkjs groth16 verify ...` crashed on THIS host (Bun's web-worker shim SIGILLs spawning ffjavascript's WASM thread pool — a Bun/npm-package interop bug, reproduces for ANY input, confirmed unrelated to our data); invoking the SAME unmodified snarkjs@0.7.6 groth16.verify with its own documented single-thread fallback forced on (process.browser=true; delete globalThis.Worker — a condition its own source already branches on, not a patch) worked: RESULT true, exit 0, on the FIRST correctly-invoked try — no serialization deviation found. A one-limb-tampered copy (pi_a.x+1) got RESULT false, exit 1, confirming the oracle has teeth. Frozen as literals in snarkjs_kat_test.zig (JSON text + transcript), re-derivable (not hand-transcribed) since the fixture's toxic waste/r/s are small fixed integers. What this does NOT anchor: QAP/R1CS correctness (snarkjs never saw our R1CS — only the final group elements) — that layer has no external oracle for a custom circuit and stays self-checked (qap.checkDivisible == r1cs.isSatisfied), which is a legitimate end state, not remaining debt.
