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
| Cross-check oracle | **SEAL default** (byte-exact target *in principle* — see below) | HElib (less canonical as a "default") |
| Encoding | exact integer | exact integer |

Both are exact-integer leveled schemes of the same difficulty class; BFV wins
on *fewest independent noise-management mechanisms to get right first* and on
SEAL being available as a canonical KAT oracle **for tiering purposes** — this
row is a *could-be-anchored* argument for why BFV is not Fable-tier, not a
claim that a SEAL KAT has been run. No SEAL vectors exist in this repo; see
"Anchors (verification harness)" below for what is actually checked.

## Part-1 scope, and the sub-split

FHE is a moonshot **in scale**. A single "full leveled BFV with multiply" is too
large for one clean scaffold, so the arc is split and **Part 1 is scaffolded
cleanly** rather than everything half-built:

- **Part 1 (this commit) — arithmetic backbone (REAL) + scheme scaffold.**
  `modarith` + `ntt` + `rns` + `ring` + `encode` + `params` are real and
  byte-exact-KAT'd; `bfv.Bfv` ships real types/`add`/`sub` with the
  scheme cores gated (byte codecs deferred — see backlog below).
- **Part 2 (Opus) — `keyGen` / `encrypt` / `decrypt` / (observe `add`).**
  Textbook leveled-BFV over the now-real RNS ring; a construction that a
  SEAL KAT *could* validate byte-exact, which is why it is tiered Opus and
  not Fable — but no SEAL KAT has actually been produced (see "Anchors"
  below for what validates it today: `Dec(Enc(·))` round-trips against this
  module's own reference). Turns on `gate.scheme_core_implemented`.
- **Part 3 (Fable) — `mul` (tensor + `⌊t/q·…⌉` rescale) + `relinearize`
  (relin-key key-switch) + `noiseBudget`.** The noise-management core. Turns on
  `gate.fable_core_implemented`.

Deferred increments (all out of the whole three-part arc): **bootstrapping**
(the biggest single deferred piece), **CKKS** (approximate arithmetic), **key
rotation / Galois automorphisms** (for batched-slot rotations), full **CRT-slot
SIMD batch encoding** (needs `t ≡ 1 mod 2N`), and byte codecs. Since landed:
constant-time secret paths (see "Threats / caveats"), fast RNS base conversion
(BEHZ/HPS — `mulBehz`), and a **security-grade parameter set**
(`params.sec_n8192_logq218`, `N = 8192` / `log q = 218`). The `rns.Basis`
helpers still ship only the exact O(reconstruct) base conversion; the fast one
lives with the scheme layer, where its bounds are checkable against `P`.

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
- **`keyGen`/`encrypt`/`decrypt` — Opus (Part 2).** Textbook, and a
  construction *for which* byte-exact SEAL vectors would exist to check
  against — that possibility, not an actual SEAL cross-check, is the basis
  for the Opus/not-Fable call. **No SEAL vectors have been produced or run**
  (`modules/bfv/data/` is empty); what actually validates this layer is
  `Dec(Enc(·))` round-trips against `encode.addRef`/`mulRef`. The decrypt
  `⌊t/q·(c0+c1·s)⌉` rounding is the only noise-adjacent piece, and it too has
  no external anchor in place — only the same round-trip check.
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

- **Exact integer tensor (the correctness crux).** The tensor
  `(c0d0, c0d1+c1d0, c1d1)` must be the EXACT integer product of fixed
  representatives (centered here, to halve the noise constants) before the
  per-component `⌊t/q·T_i⌉` rescale. This is forced: the rescale does not
  commute with mod-`q` reduction (`⌊t/q·[T]_q⌉` differs from `[⌊t/q·T⌉]_q` by
  `t·k ≢ 0 (mod q)`), so a "stay in RNS, multiply in the ring, then rescale"
  shortcut decrypts to garbage. Verified by fault injection: that exact
  variant, and a dropped-rescale (`Δ²`) variant, and a wrong-gadget-base relin
  variant were each injected and each turns the two mul anchors red
  deterministically.
- **How the exact tensor is obtained — three paths, one value.** `mulExactRef`
  is the `O(N²)` schoolbook over an exact integer (the ORACLE). `mulRnsNtt`
  computes it in an auxiliary RNS basis sized so the centered CRT lift is exact
  (`O(num_aux·N log N)`), then still rescales by big-integer division.
  **`mulBehz`** is the BEHZ/HPS path: the tensor stays in residues (main basis,
  an auxiliary sub-basis, and one redundant modulus `m̃`) and the rescale is an
  exact RNS division chain followed by a Shenoy–Kumaresan base extension — the
  exact integer is never materialised and no big-integer division happens. It
  is EXACT, not approximate: the only inequalities it rests on are
  `∏p > 2·div_shift` and `num_rs < m̃`, both comptime-checked, and the
  differential test asserts bit-identity with `mulExactRef` at
  `log q ∈ {11, 36, 120, 300}` including saturating inputs. `mul` picks the
  path by a MEASURED rule (`Bfv.behz_min_tensor_bits`): BEHZ as soon as
  `TensorI` outgrows a native 128-bit integer, which is exactly where LLVM
  stops lowering the constant-divisor division to a multiply.
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

- **Security status.** `test_tiny` / `test_mul` / `bfv_toy` remain
  correctness-only toy parameters and claim nothing.
  `params.sec_n8192_logq218` is the one set with a security claim: `N = 8192`,
  four NTT primes totalling `log2 q = 218.000`, `t = 65537`, ternary secret —
  the shape the HomomorphicEncryption.org tables give for ~128-bit classical
  security. What is VERIFIED here is correctness at those parameters (a depth-2
  evaluation over boundary + random plaintexts decrypts exactly, and the
  worst-case ledger in `params.zig` guarantees depth 4); the ~128-bit figure is
  a citation of the standard tables, **not** a lattice estimate run in this
  repo. There is also no side-channel hardening beyond the boundary in
  "Partially constant-time" below, and no byte codecs — so this is a set to
  benchmark and reason about, not one to deploy behind.
- **The entropy seam is typed, not documented.** `keyGen`, `encrypt` and
  `genRelinKey` take `io: std.Io` and draw through `entropy.SecureSource`
  (`modules/entropy`), the fail-closed `std.Random` adapter over
  `std.Io.randomSecure` — not `std.Random.IoSource`, which binds the
  silently-degrading `std.Io.random`. They deliberately do NOT take
  `std.Random` directly: that is a vtable, its quality cannot be read at the
  call site, and `DefaultPrng.init(0).random()` looks exactly like a correct
  argument. The consequence of getting it wrong is not a weaker instance —
  with `u,e0,e1` predictable an attacker computes `c0 − p0·u − e0 = Δ·m` and reads the
  plaintext **without the secret key**, and `genRelinKey` publishes `s²` to the
  evaluator under masks the evaluator can reproduce. The `…ForTest` twins keep
  `std.Random` so the KATs (including the scripted-word test that pins which
  draws `keyGen` makes, in order) stay reproducible; the name is the only thing
  separating them from the production path, and `bfv.zig`'s "RNG seam" tests pin
  both halves of that split at comptime.
- **Partially constant-time — read the boundary, do not round it up.**
  What IS source-level constant time now: the ternary sampler (`sampleTernary`
  draws with the fixed-cost `uintLessThanBiased` instead of a rejection loop and
  selects the trit with an arithmetic mask, so neither the draw nor the store
  branches on the secret), and the word-arithmetic leaves every secret-bearing
  product routes through (`addMod`/`subMod`/`Modulus.mul`/`Shoup.mul` end in a
  masked conditional subtract, `modarith.csub`, and the `%q` division that had
  data-dependent latency on some µarch is gone).
  What is NOT, and is not claimed to be: `powMod`/`invMod`/`primitive2NthRoot`/
  the auxiliary-prime search are public-data setup and remain variable-time;
  `sampleUniform` still uses the rejection-based `uintLessThan` (its output is
  a public mask, not a secret); `decrypt`/`noiseBudget`/`centerRaw`/
  `auxResidues` branch on reconstructed coefficient values; `relinearize`'s
  digit decomposition is value-shaped; and the entropy source behind
  `std.Io.randomSecure` is the host's, so its timing is outside our control
  (as is a `std.Random` handed to one of the `…ForTest` twins). Above all this is
  **source-level** CT — the compiler may
  rematerialise a branch from a mask, and nothing here is verified codegen or a
  microarchitectural claim.
- **No fixed integer width remains.** `Bfv.QU` (the `[0,q)` value and CRT
  accumulator) and `Bfv.TensorI` are both derived from the parameter set; the
  `u128` ceiling that used to cap `log q` at 127 is gone, and so is the older
  `i256` tensor guard. `params.sec_n8192_logq218` (`N = 8192`, `log q = 218`,
  `t = 65537`) builds and evaluates a depth-2 circuit exactly — see "Security
  status" above. `decrypt`/`noiseBudget` still reconstruct a wide integer per
  coefficient (that is inherent to `⌊t/q·…⌉` at decrypt time); the MULTIPLY no
  longer does.
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
- A parameter-selection helper (`sec_n8192_logq218` is hand-derived; there is
  no function that picks a chain for a target `N`/`log q`/depth).

## Anchoring

**Anchor grade:** class B · oracle REDERIVED

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle REDERIVED** — an in-house oracle re-deriving the answer by a different route. Catches implementation typos; does NOT catch a shared misreading of the spec.

**What the tests actually contain.** NTT/RNS/BFV KAT vectors from independent Python re-derivation (SPEC.md)

**How it got there.** No external oracle exists for what remains. SEAL/OpenFHE ciphertext layout is implementation-defined; no portable vector exists
