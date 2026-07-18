# tfhe — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives in
`src/root.zig`'s `pub const meta`; this file does not restate either. The
parameter-set noise/failure ledger lives in `src/params.zig` (single source of
truth) and is only summarised here.

## What this module is

A TFHE/FHEW-style **programmable gate bootstrapping** scheme: LWE/GLWE/GGSW
ciphertexts over the discretised torus `T = Z_{2^32}`, with a blind rotation
(CMux over a GGSW bootstrap key) that refreshes a ciphertext's noise through a
programmable LUT. Bootstrapping is the step that makes FHE *unbounded-depth*: the
sibling `bfv` is leveled (bounded multiplicative depth); TFHE resets noise after
every gate.

## Scheme choice — TFHE gate bootstrapping vs BFV/BGV digit-extraction

| | TFHE/FHEW (chosen) | BFV/BGV bootstrap (Halevi–Shoup) |
|---|---|---|
| What it refreshes | one LWE ciphertext per bootstrap (a gate) | a full packed BFV ciphertext |
| Core machinery | blind rotation = CMux/external-product loop | slot-packing + homomorphic digit-extraction polynomials |
| Ring modulus | power-of-two `2^32` ⇒ **exact wrapping `u32`**, no NTT prime, no FFT precision bound | NTT-prime RNS ring (already in `bfv`) |
| Size / verifiability | self-contained; ~one accumulator loop | very large; digit-extraction is hard to get right and to verify |
| Dedup with `bfv` | none — a different scheme family | would extend `bfv` |

TFHE wins decisively for a *first* bootstrapping: it is the canonical
demonstration, it genuinely realises unlimited depth (bootstrap after every
gate), and it is self-contained and std-only. BFV bootstrapping would reuse the
`bfv` ring but is enormously larger (slot-packing + digit-extraction) and much
harder to verify — deferred, and out of scope here.

## Dedup / std-gap

- **std** ships `ml_kem`/`ml_dsa` (lattice KEM/signatures) but **no FHE** of any
  kind — no gap overlap.
- **`bfv`** is *leveled* FHE (add/multiply to bounded depth, no bootstrap); its
  README already lists bootstrapping as the biggest deferred increment. `tfhe`
  is a different scheme family (torus LWE/GLWE/GGSW, not RNS-BFV) and shares no
  code — the correct home for bootstrapping is a new module, not a `bfv`
  extension.
- **`paillier`** is additively homomorphic only. Unrelated.

## The mechanical / Fable cut-line

Everything is mechanical (deterministic, or bounded-noise and independently
testable) EXCEPT four functions in `tfhe.zig`, gated behind
`gate.fable_core_implemented`:

| Function | Why it is the irreducible core |
|---|---|
| `externalProduct` (GGSW ⊠ GLWE) | the noise-growth heart: decompose the input GLWE and dot with the GGSW rows; the pairing/accumulation and its noise are the whole ballgame |
| `cmux` | the encrypted selector `d0 + C ⊠ (d1 − d0)`; a wrong selector (missing subtraction, wrong branch) passes tiny tests but fails |
| `blindRotate` | the accumulator loop; the initial `X^{−b̃}` rotation and the per-step `X^{ã_i}` exponents are the classic off-by-one/sign hazard |
| `bootstrap` | the composition mod-switch → blind-rotate → sample-extract → key-switch that resets noise |

The signatures structurally constrain the core: `externalProduct`/`cmux` return
`Glwe`, `blindRotate` takes the mod-switched `b̃ ∈ [0,2N)` and `ã ∈ [0,2N)^n` and
returns the accumulator `Glwe`, and `bootstrap` returns a fresh `LweN`. The
mechanical helpers the core builds on — `decomposeGlwe` (exact signed
decomposition), `glweMulMonomial` (rotation), `sampleExtract`, `keySwitch`,
`glweAdd`/`glweSub`/`glweTrivial` — are all REAL and tested, so the core is
reduced to the genuinely-hard arithmetic and cannot borrow correctness from a
broken helper.

## Fable boundary + honest tier call

Per the matured heuristic (`feedback_fable_tier_heuristic`: *not Fable* if there
is an external byte-exact KAT and a small fix-space; *Fable* if there is no
external anchor / a self-consistent-but-wrong test can pass, or the design space
is nontrivial):

- **The mechanical layer is Opus/Sonnet, NOT Fable.** The ring, the gadget, mod
  switch, sample extraction, and key switch are deterministic or bounded-noise
  and are pinned by exact/round-trip tests (schoolbook `mul` is byte-exact by
  construction; `decompose`/`recompose` has an exact error bound;
  `sampleExtract`/`keySwitch` decrypt round-trips). Small fix-space, strong
  feedback.
- **The four core functions are genuine Fable.** Two independent triggers fire:
  1. **No external byte-exact KAT.** TFHE-rs, OpenFHE-binfhe and concrete all use
     different parameters, gadget conventions and message encodings, so no
     shared vector set exists. A self-consistent-but-wrong core (wrong CMux
     branch, off-by-one blind-rotation exponent, mishandled decomposition sign,
     under-counted noise) can pass a naive round-trip.
  2. **Nontrivial design space** — the external product's decomposition/​row
     pairing and the blind-rotation exponent algebra, and the *noise* argument
     that ties them to a correct output, are the irreducible skill.
- **Correctness is intrinsically probabilistic** (see the ledger): unlike
  `bfv`'s leveled multiply, there is no deterministic worst-case oracle that
  bounds the hard part — average-case noise is the only real analysis. That
  *is* the "no simple anchor for the hard part" Fable case.

**Verdict: genuinely Fable.** Scaffolding did NOT reveal a byte-exact reference
that collapses the fix-space; if a future pass finds published byte-exact TFHE
vectors for a fixed parameter set, the core should be de-tiered — but none is
known.

## Verification harness (anchors)

No external KAT, so the harness leans on three independent teeth:

1. **Cleartext blind-rotation oracle (`clearBootstrap`).** A NOISELESS
   re-implementation of what blind rotation must compute — modulus-switch the
   input LWE, form the rotation exponent `−b̃ + Σ ã_i s_i`, read
   `(X^exp·lut)_0` — using ONLY the real ring + torus code, no encryption. It
   pins the LUT construction + modulus-switch + rotation indexing (the exact
   place off-by-one/sign bugs live) BEFORE the core exists, and is the reference
   the gated `bootstrap` end-to-end tests decrypt against. Verified today over 64
   random bits for both the identity and NOT LUTs.
2. **Homomorphic property end-to-end (SKIP-gated until the core lands).** A
   programmable gate (`bootstrap(identity)` == in, `bootstrap(NOT)` == ¬in), a
   2-input homomorphic **AND** via LWE sum + LUT, and — the whole point — an
   **unlimited-depth chain**: bootstrap the identity LUT in a chain and confirm
   the message survives every refresh (a leveled scheme fails long before; only
   correct noise-RESET sustains it). Plus a noise-budget assertion (output noise
   `< Δ/4 ≪ Δ/2`).
3. **Deliberately-broken positive controls (PASS today — teeth before the
   core).**
   - *Sign-dropped sample extraction* — omitting the negacyclic sign flip
     `a_ext[j] = −a(X)_{N−j}` decrypts to a different value; the real extraction
     is always correct.
   - *Dropped-level gadget decomposition* — zeroing the least-significant digit
     pushes the recomposition error past `maxError`; the full decomposition
     stays within it.
   - *Wrong-sign rotation exponent* — flipping the phase sign reads the wrong LUT
     slot and misdecodes; the correct rotation is always right. (Directly targets
     the blind-rotation off-by-one bug class.)
   - *(SKIP-gated)* a corrupted bootstrap key must NOT bootstrap correctly —
     proving the CMux/key-switch path is load-bearing (mirrors `bfv`'s
     corrupted-relin-key control).

## Noise / failure-probability ledger

Full arithmetic in `params.zig`. Summary for the `toy` set (`n=64, N=256, k=1,
B_g=2^7, ℓ=4, B_ks=2^4, ℓ_ks=8, err_bound=2^10`, `Δ=q/4`): the blind-rotation
output stddev is `σ_out ≈ √(n·(k+1)·ℓ·N·(B_g²/12)·σ²) ≈ 7.9e6`, so the decision
margin `Δ/2 = q/8 = 2^29` is `≈ 68·σ_out` and the per-bit failure probability is
`erfc(q/8 / (√2·σ_out)) ≈ erfc(48) ≈ 10^{-1000}`. A thousands-long bootstrap
chain is still overwhelmingly correct. **These are toy dimensions with no
security level**; the same `erfc` formula is the sizing tool for a security-grade
set (raise `σ` for a hard LWE problem, re-balance `(ℓ, B_g)` to hold the margin).

## Why exact arithmetic (a design win over `bfv`)

The torus modulus is `q = 2^32`, so modular add/sub/mul are wrapping `u32`
(`+%`/`-%`/`*%`) — natively exact. The negacyclic ring multiply is therefore an
**exact** `O(N²)` integer convolution mod `2^32`, with **no NTT prime and no FFT
precision bound** to reason about (contrast `bfv`, which needs NTT-friendly
primes and CRT). A production TFHE swaps the schoolbook `mul` for a `u64`/complex
NTT for speed; here the exact schoolbook is the correctness oracle and is fine
for the toy dimensions (`N ≤ 512`). The only rounding in the mechanical layer is
the modulus switch's half-ulp, which is deterministic and bounded.

## Threats / caveats (scaffold)

- **No security level claimed.** `toy` is correctness-only; do not encrypt
  anything real until a security-grade parameter set + the core land.
- **Not constant-time.** Samplers and gadget code are public-data-shaped, but the
  secret-dependent paths (keygen/encrypt and the future blind rotation) must be
  audited for timing when the core is implemented — flagged for the Fable pass.
- **Probabilistic correctness.** Bootstrapping correctness is average-case (see
  the ledger); the toy set's `≈68σ` margin makes failure astronomically
  unlikely, but there is no worst-case guarantee — this is intrinsic to TFHE and
  is exactly why the core is Fable.
- **`k = 1` fixed** (standard RLWE TFHE). General `k > 1` GLWE is a deferred
  increment.

## Per-module backlog (mechanical, not Fable)

- Byte codecs for the key/ciphertext types.
- A `u64`/complex-FFT negacyclic multiply (perf) behind the same `Poly` API,
  cross-checked against the exact schoolbook.
- General `k > 1` GLWE; multi-value / larger-precision LUTs.
- Security-grade parameter sets + a parameter-selection helper driven by the
  `erfc` ledger.
