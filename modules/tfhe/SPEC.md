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
| Ring modulus | power-of-two `2^32` ⇒ **exact wrapping `u32`**, no FFT precision bound (the `ntt.zig` fast path uses an auxiliary prime internally but is bit-identical) | NTT-prime RNS ring (already in `bfv`) |
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
  construction and is the differential oracle the NTT path must reproduce bit
  for bit; `decompose`/`recompose` has an exact error bound;
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

## Fable core — done-record (was: gated/TODO)

All four cores (`externalProduct`, `cmux`, `blindRotate`, `bootstrap`) are
implemented in `tfhe.zig`; `gate.fable_core_implemented` is flipped `true`, no
`@panic` remains behind it, and every previously SKIP-gated anchor now runs:
the programmable-gate test, the 2-input homomorphic AND, the unlimited-depth
bootstrap chain, the corrupted-bootstrap-key control, and the noise-budget
assertion all pass, no skips (see README.md's "Verify" section).
This did **not** change the Fable-tier call above, which is a verdict about
*why* the work needed Fable-level skill (no external anchor, nontrivial
design space), not a claim that the work remains undone.

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
2. **Homomorphic property end-to-end (now real, was SKIP-gated until the core
   landed).** A programmable gate (`bootstrap(identity)` == in,
   `bootstrap(NOT)` == ¬in), a 2-input homomorphic **AND** via LWE sum + LUT,
   and — the whole point — an **unlimited-depth chain**: bootstrap the
   identity LUT in a chain and confirm the message survives every refresh (a
   leveled scheme fails long before; only correct noise-RESET sustains it).
   Plus a noise-budget assertion (output noise `< Δ/4 ≪ Δ/2`). All pass today.
3. **Deliberately-broken positive controls (PASS today — teeth independent of
   the core).**
   - *Sign-dropped sample extraction* — omitting the negacyclic sign flip
     `a_ext[j] = −a(X)_{N−j}` decrypts to a different value; the real extraction
     is always correct.
   - *Dropped-level gadget decomposition* — zeroing the least-significant digit
     pushes the recomposition error past `maxError`; the full decomposition
     stays within it.
   - *Wrong-sign rotation exponent* — flipping the phase sign reads the wrong LUT
     slot and misdecodes; the correct rotation is always right. (Directly targets
     the blind-rotation off-by-one bug class.)
   - A corrupted bootstrap key must NOT bootstrap correctly — proving the
     CMux/key-switch path is load-bearing (mirrors `bfv`'s corrupted-relin-key
     control). Also passes today.

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
**exact** integer convolution mod `2^32`, with **no FFT precision bound** to
reason about. The only rounding in the mechanical layer is the modulus switch's
half-ulp, which is deterministic and bounded.

Reference TFHE implementations buy speed with an `f64` complex negacyclic FFT
and pay for it with a rounding-error budget. This module keeps exactness and
still gets the asymptotics: `poly.mul` dispatches to `ntt.zig`, an **integer**
negacyclic NTT over the auxiliary prime `p = 2^64 − 2^32 + 1`, with both
operands split into 16-bit halves so the whole convolution provably fits in
`p` (`|C_k| ≤ N·2^49 < p/2` for every `N ≤ 2^13`) and is reconstructed exactly
mod `2^32`. Four forward transforms and one inverse per product; the `2^16`
weighting and both cross terms are combined inside the transform domain. The
schoolbook convolution is retained as `mulSchoolbook` and is the differential
oracle: `poly.zig`'s tests assert **bit-identical** output for `N = 2 … 1024`,
including saturating and sign-boundary coefficients.

Measured (ReleaseFast, `bench.zig`, schoolbook ÷ NTT on identical inputs in
one binary, min of three alternating passes): `N=16` 0.11×, `32` 0.23×, `64`
0.48×, `128` 0.92×, `256` **1.67×**, `512` 3.36×, `1024` 7.02×, `2048`
12.08×. That crossover is why `ntt_min_degree = 256`. End to end a `toy` gate
bootstrap goes **54.4 ms → 33.3 ms** (1.64×), measured by building
`ntt_min_degree` both ways.

What this does *not* buy: the remaining factor. A bootstrap issues
`n·2·(2ℓ) = 1024` products, and each transforms its GGSW operand from scratch.
Caching the bootstrap key in the transform domain and accumulating the whole
external product there before a single inverse would cut ~80 transforms per
external product to ~18 — the standard TFHE optimisation, and a separate
change with its own bound (`2ℓ·N·2^49.5 < p/2`, i.e. `2ℓ·N < 2^13.5`) and its
own ~4× memory cost for the prepared key.

## Threats / caveats

- **No security level claimed.** `toy` is correctness-only; do not encrypt
  anything real until a security-grade parameter set lands. `Params` is an open
  struct, though — a consumer can instantiate `Tfhe(P)` at whatever dimensions
  it likes — so the entropy seam below is written for the production case, not
  for `toy`.
- **The entropy seam is typed, not documented.** Key generation and encryption
  take `io: std.Io` and draw from `std.Io.random`, which std documents as a
  CSPRNG. They deliberately do NOT take `std.Random`: that is a vtable, its
  quality cannot be read at the call site, and `DefaultPrng.init(0).random()`
  looks exactly like a correct argument. The consequence of getting it wrong is
  not a weakened instance but no instance: with `a` and `e` predictable,
  `b = ⟨a,s⟩ + μ + e` is a linear equation in `s`, and `dim` ciphertexts recover
  the secret key by Gaussian elimination — while the bootstrap and key-switch
  keys, which a deployment *publishes*, are encryptions of that same key. The
  `…ForTest` twins keep `std.Random` so the draw→value KATs and the seeded
  end-to-end tests stay reproducible; the name is the only thing separating them
  from the production path, and `tfhe.zig`'s "RNG seam" tests pin both halves of
  that split at comptime.
- **Source-level constant-time in the key path; not verified codegen.** The
  secret samplers are fixed-cost and branch-free: `sampleBit` takes the top bit
  of one `u32` draw (bit-identical to the `std.Random.uintLessThan(u32, 2)` it
  replaced, but without that routine's rejection branch), `sampleError` is a
  64-bit multiply-shift instead of `intRangeAtMost`'s rejection loop, and
  `clearBootstrap` selects on the secret key bit arithmetically instead of
  branching. `lweKeyGen`/`glweKeyGen` are fixed-trip loops over `sampleBit`.
  What this does **not** claim: the compiler may still reintroduce a branch —
  this is source-level constant time, not verified machine code, and no timing
  measurement was taken. `gadget.decompose` still branches on digit values, but
  it is only ever applied to ciphertext mask/body coefficients, never to key
  material. `sampleError`'s multiply-shift is biased by ≈`2^-53` in statistical
  distance (a rejection-free sampler cannot be exactly uniform on a
  non-power-of-two range); the previous sampler was unbiased but variable-time.
- **Probabilistic correctness.** Bootstrapping correctness is average-case (see
  the ledger); the toy set's `≈68σ` margin makes failure astronomically
  unlikely, but there is no worst-case guarantee — this is intrinsic to TFHE and
  is exactly why the core is Fable.
- **`k = 1` fixed** (standard RLWE TFHE). General `k > 1` GLWE is a deferred
  increment.

## Per-module backlog (mechanical, not Fable)

- Byte codecs for the key/ciphertext types.
- Transform-domain caching of the bootstrap key (a "prepared" GGSW), and
  accumulating a whole external product before one inverse transform — the
  remaining ~4× on top of the `ntt.zig` multiply. See the exactness bound above.
- General `k > 1` GLWE; multi-value / larger-precision LUTs.
- Security-grade parameter sets + a parameter-selection helper driven by the
  `erfc` ledger.
