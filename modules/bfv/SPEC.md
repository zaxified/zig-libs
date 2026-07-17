# bfv — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives
in `src/root.zig`'s `pub const meta`; this file does not restate either.

## What this module is

A leveled **BFV** (Brakerski/Fan–Vercauteren, IACR ePrint 2012/144)
homomorphic-encryption scheme over the RLWE ring `R_q = Z_q[X]/(X^N+1)`, in
Residue-Number-System (RNS) form, following Microsoft SEAL's parameter/NTT
design. *Leveled* = supports a bounded multiplicative depth; **no bootstrapping**
(the depth-refresh step) in this arc. BFV rather than BGV or CKKS: BFV is
exact-integer (no CKKS approximate-rescaling encoding to reason about), the
plaintext/ciphertext scaling is fully specified, and it is Microsoft SEAL's
default — so a byte-exact cross-check target exists. BGV is close but its
modulus-switching noise bookkeeping is a second, orthogonal source of subtlety;
BFV's single `⌊t/q·…⌉` rescale is the cleaner *first* FHE. CKKS (approximate)
and BGV are deferred increments.

## Scheme choice — BFV vs BGV (justification)

| | BFV (chosen) | BGV |
|---|---|---|
| Plaintext placement | scaled by `Δ=⌊q/t⌋` in the high bits | in the low bits (mod `t`) |
| Noise control on mul | one `⌊t/q·…⌉` rescale | modulus-switch chain (extra bookkeeping) |
| Cross-check oracle | **SEAL default** (byte-exact target) | HElib (less canonical as a "default") |
| Encoding | exact integer | exact integer |

Both are exact-integer leveled schemes of the same difficulty class; BFV wins
on *fewest independent noise-management mechanisms to get right first* and on
having SEAL as a canonical KAT oracle.

## Part-1 scope, and the sub-split

FHE is a moonshot **in scale**. A single "full leveled BFV with multiply" is too
large for one clean scaffold, so the arc is split and **Part 1 is scaffolded
cleanly** rather than everything half-built:

- **Part 1 (this commit) — arithmetic backbone (REAL) + scheme scaffold.**
  `modarith` + `ntt` + `rns` + `ring` + `encode` + `params` are real and
  byte-exact-KAT'd; `bfv.Bfv` ships real types/`add`/`sub` with the
  scheme cores gated (byte codecs deferred — see backlog below).
- **Part 2 (Opus) — `keyGen` / `encrypt` / `decrypt` / (observe `add`).**
  Textbook leveled-BFV over the now-real RNS ring; KAT-able byte-exact against
  SEAL. Turns on `gate.scheme_core_implemented`.
- **Part 3 (Fable) — `mul` (tensor + `⌊t/q·…⌉` rescale) + `relinearize`
  (relin-key key-switch) + `noiseBudget`.** The noise-management core. Turns on
  `gate.fable_core_implemented`.

Deferred increments (all out of the whole three-part arc): **bootstrapping**
(the biggest single deferred piece), **CKKS** (approximate arithmetic), **key
rotation / Galois automorphisms** (for batched-slot rotations), full **CRT-slot
SIMD batch encoding** (needs `t ≡ 1 mod 2N`), fast RNS base conversion
(Bajard/Halevi-Polyakov — Part 1 ships the exact O(reconstruct) version),
constant-time secret paths, and **security-grade parameter sets** (`N≥4096`,
~128-bit). **Part 1 claims no security level** — `test_tiny`/`bfv_toy` exist for
correctness testing only.

## Fable boundary + honest tier call

Applying the matured heuristic (CONVENTIONS-adjacent `feedback_fable_tier_heuristic`:
*not Fable* if there is an external byte-exact KAT and the construction is fully
published with a small fix-space; *Fable* if there is no external anchor / a
self-consistent-but-wrong test can pass, or the design space is nontrivial):

- **NTT / RNS / encode — Opus, NOT Fable.** The negacyclic Cooley-Tukey NTT and
  CRT are textbook and *byte-exact-KAT-able*: a forward/inverse NTT on a fixed
  polynomial is fully deterministic and cross-checkable against a re-derivation
  and against an independent schoolbook convolution. Small fix-space, strong
  deterministic feedback → a careful non-Fable pass lands it. (These are done in
  Part 1.)
- **`keyGen`/`encrypt`/`decrypt` — Opus (Part 2).** Textbook, and byte-exact
  against SEAL vectors. The decrypt `⌊t/q·(c0+c1·s)⌉` rounding is the only
  noise-adjacent piece, but it too has an external anchor.
- **`mul` + `relinearize` + `noiseBudget` — genuine Fable (Part 3).** This is
  the "no simple anchor for the hard part" case. Self-consistent tests can pass
  while noise is silently mismanaged: a multiply that "works" for tiny inputs
  but whose noise growth is wrong and fails at depth; a relin key-switch that
  decrypts *subtly* wrong (right for degree-1, wrong after a rescale); a rescale
  that rounds the wrong way. There is no byte-exact vector that bounds the
  noise-budget accounting — the ciphertext noise is randomised, so end-to-end
  correctness at depth is the only real teeth, and getting the growth right is
  the irreducible skill. **The Part-1 gated core (`fable_core_implemented`) is
  genuinely Fable; the `scheme_core_implemented` half is Opus** — hence two
  flags, so Parts 2 and 3 dispatch to the right tier.

## Anchors (verification harness)

Two anchor families, per the plan:

1. **NTT/RNS byte-exact KAT (the deterministic anchor).** `kat_vectors.zig`
   holds vectors from an INDEPENDENT Python re-derivation (a from-scratch
   textbook NTT + CRT, not this module's code — see "External-reference
   anchoring"). `forward_a` pins the forward transform's exact output
   (bit-reversed order); `negamul_ab` pins the canonical negacyclic product
   (order-independent). The Zig NTT must reproduce both, AND must equal the
   in-module independent schoolbook negacyclic convolution over random inputs
   (a fully independent algorithm — the strongest anti-self-consistency check
   for the transform). RNS CRT reconstruction is pinned on primes `{17,97}`.
2. **Homomorphic property end-to-end (the strong anchor).** `Dec(Enc(a)⊕Enc(b))
   == a+b (mod t)`, `Dec(relin(Enc(a)⊗Enc(b))) == a·b (mod t)`, and a
   multiply-DEPTH `a·b·c` that still decrypts (exercises the noise budget) — all
   decrypt against the `encode.mulRef`/`addRef` plaintext-space references.
   These defeat self-consistent-but-wrong; LIVE since Parts 2–3 landed. The
   mul/depth anchors run over random AND boundary (all-`t−1`) plaintexts on
   `params.test_mul` — see "Part-3 multiply" below for why not `test_tiny`.

**Teeth before the core (deliberately-broken positive controls, PASS today):**

- *Cyclic-vs-negacyclic discriminator* — builds the WRONG (`X^N=+1` cyclic)
  ring product with no NTT code, confirms it differs from the negacyclic answer,
  and confirms the real NTT matches the negacyclic (not the cyclic) one. Proves
  the `mulNegacyclic == mulSchoolbook` anchor would have caught a cyclic-NTT
  bug.
- *Wrong-scale "encryptor"* — using ONLY the real ring arithmetic (no gated
  core), constructs a noiseless toy ciphertext with the correct scale
  (`c0+c1·s == Δ·m`) and one with a dropped scale (`Δ'=1`); the structural
  `scaleCheck` ACCEPTS the correct one and REJECTS the wrong one. Proves the
  scaling/noise anchor bites before `encrypt`/`decrypt` exist — this is exactly
  the dropped-`Δ` bug class the Fable core must not commit.

## Part-3 multiply (landed): exact-tensor path + worst-case noise ledger

The Fable core (`mul`/`genRelinKey`/`relinearize`/`noiseBudget`) is REAL.
Design decisions and the noise argument, for audit:

- **Exact integer tensor (the correctness crux).** `mul` CRT-reconstructs the
  four input components to centered integer polynomials, computes the tensor
  `(c0d0, c0d1+c1d0, c1d1)` EXACTLY over `Z[X]/(X^N+1)` (i256 schoolbook), and
  only then applies the per-component `⌊t/q·T_i⌉` rescale. This is forced: the
  rescale does not commute with mod-`q` reduction (`⌊t/q·[T]_q⌉` differs from
  `[⌊t/q·T⌉]_q` by `t·k ≢ 0 (mod q)`), so a "stay in RNS, multiply in the
  ring, then rescale" shortcut decrypts to garbage. Verified by fault
  injection: that exact variant, and a dropped-rescale (`Δ²`) variant, and a
  wrong-gadget-base relin variant were each injected and each turns the two
  mul anchors red deterministically. The security-grade fast path (BEHZ/HPS
  RNS base extension to an auxiliary basis, never materialising the integer)
  is the deferred increment; the exact path is O(reconstruct + N²) and fine
  for the toy/test moduli (guarded by a comptime width check).
- **Why the rescale keeps the scale at `Δ`.** With `ct_i(s) = Δm_i + v_i +
  q·r_i` over the integers and `tΔ = q − r_t`: `(t/q)·ct1(s)ct2(s) ≡
  Δ[m1m2]_t + (m1v2+m2v1) + t(r1v2+r2v1) − r_t(…small…) + ⌊·⌉-error (mod q)`
  — one `Δ` is cancelled by `t/q`, the `q·[…]` cross terms collapse to
  `t·(r_i·v_j)` (the dominant growth), and `q²r1r2` vanishes mod `q`.
- **Relin correctness.** `rlk_i = (−(a_i·s+e_i) + w^i·s², a_i)`, `w = 2^8`;
  `relinearize` digit-decomposes `c2 = Σ w^i d_i` exactly and adds
  `Σ d_i·rlk_i`, so the phase gains `Σ d_i(w^i s² − e_i) + Σ d_i a_i s −
  Σ d_i a_i s = c2·s² − Σ d_i e_i` — the `c2·s²` term is replaced by the same
  value under `s`, up to key-switch noise `≤ relin_digits·N·(w−1)`.
- **Depth-2 is a worst-case guarantee, not a probabilistic pass.** The mul
  anchors run on `params.test_mul` (`N=16`, `t=16`, `q ≈ 2^35.6`) because
  `test_tiny`'s `q = 1649` cannot hold even one multiply (worst-case cross
  term alone exceeds `q`). On `test_mul` the full ledger (params.zig) bounds
  depth-2 noise at `≈ 5.7e8 < Δ/2 ≈ 1.61e9` (≈2.8× margin) for ANY seed and
  ANY plaintexts including all-`(t−1)` — which resolves the Part-1
  "verifiability risk" flag below for these parameters: the depth anchor is
  deterministic teeth, not a lucky seed.

## External-reference anchoring

The NTT/RNS KAT vectors were produced by a standalone Python script that
re-implements the textbook negacyclic NTT (Cooley-Tukey forward with
`zetas[k]=psi^bitrev(k)`, Gentleman-Sande inverse + `N^-1`) and CRT from
scratch, self-checking `intt(ntt(x))==x` and `ntt_mul==schoolbook` before
emitting the Zig arrays now in `kat_vectors.zig`. It shares no code with this
module. Matching it byte-exact defeats "self-consistent but nonstandard": a NTT
that reconstructs but transforms in a different convention cannot match
`forward_a`. Per CONVENTIONS.md §5 this needs no `NOTICE` entry (a public
paper/spec is not a copyrightable work; no third-party source was ported).

## Reuse map (dedup)

- **`std.crypto` NTT (ML-KEM/ML-DSA):** NOT reusable — hardwired to `q=3329`
  (`i16`), no exported generic ring/NTT. BFV needs word-size (~30–60-bit) RNS
  primes, so a fresh `u128`-product NTT was built (mirroring the in-repo
  `falcon` negacyclic NTT structure, which is likewise degree-generic mod a
  fixed 12289 — the *shape* was followed, not the modulus).
- **`std.crypto.ff.Modulus`** (used by `paillier`/`rsa`/`vdf`): a fixed-width
  constant-time Montgomery type aimed at big RSA-class moduli — heavier than the
  single-word NTT-prime arithmetic here; `modarith.zig` stays word-sized `u64`.
- **`paillier`** is additively homomorphic only (no ciphertext multiply); BFV is
  a different scheme, not an extension of it.
- Net: FHE is largely self-contained (RLWE over `Z_q[X]/(X^N+1)`), so this
  module is **std-only** with its own `modarith`/`ntt`/`rns`.

## Threats / caveats (Part 1)

- **No security level claimed.** `test_tiny`/`bfv_toy` are correctness-only
  toy parameters; do not encrypt anything real until a security-grade parameter
  set + Part 2/3 land.
- **Not constant-time.** `powMod`/`primitive2NthRoot`/table setup are public-data
  only, but the future secret paths (`keyGen`/`encrypt`/`decrypt`) must be
  audited for timing when implemented — flagged for Parts 2–3.
- **Exact CRT reconstruction uses `u128`** — fine for KAT/toy moduli (product
  fits in 128 bits); production RNS never materialises the integer (stays in
  residues). Fast base conversion is the deferred increment.
- **Verifiability risk (flagged in Part 1, addressed in Part 3):** BFV
  ciphertext noise is randomised, so the Part-3 multiply's correctness at depth
  has no byte-exact external KAT — the noise-budget accounting is exactly the
  piece with no external deterministic anchor. This is why Part 3 was tiered
  Fable. Part 3 answers it by SIZING the mul-anchor parameters so that the
  worst-case noise ledger (params.zig `test_mul`) guarantees depth-2
  correctness for every seed — turning the probabilistic property back into a
  deterministic test (see "Part-3 multiply" above).

## Per-module backlog (mechanical, not Fable)

- Byte codecs for `SecretKey`/`PublicKey`/`RelinKey`/`Ciphertext` (shape fixed,
  serialisation to fill in with Part 2).
- Fast RNS base conversion (Halevi–Polyakov) replacing `convertExact`.
- CRT-slot batch encoding (`encode.zig`), needs `t ≡ 1 mod 2N`.
- Security-grade parameter sets + a parameter-selection helper.
