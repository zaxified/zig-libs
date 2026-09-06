# poseidon — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-06** — Provenance, not arithmetic: the circomlibjs known answers in
  `src/vectors_test.zig` are now **produced by running circomlibjs**, not read out
  of its test suite. `iden3/circomlibjs` is GPL-3.0, so values transcribed from its
  sources were copyleft-licensed data sitting in an MIT tree; values obtained by
  executing it are this repository's own measurement of a black box (root NOTICE
  §0). The recipe stopped being a comment and became an instrument: new
  `tools/gen_vectors.mjs` (CONVENTIONS.md §9) imports circomlibjs from a
  disposable clone, computes every circomlibjs-derived value in the test file
  twice — `poseidon_reference.js` and `poseidon_opt.js`, whose MDS storage and
  round folding differ — and requires the two to agree. Run against circomlibjs
  0.1.8 (`48b3ab3`): all 29 distinct values identical to what was committed, which
  is the expected result and the reason this is a provenance change and not a
  vector change. No test name, input or assertion moved. `NOTICE` corrected while
  here: circomlibjs is GPL-3.0, not LGPL-3.0 — LGPL-3.0 is `iden3/circomlib`, the
  circom circuits, from which this module takes nothing at all.

- **2026-08-06** — Security audit: two findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Verified: byte-exact against the
  Poseidon authors' own `hadeshash` test vectors, all four published GF(p) instances.
- **2026-07-29** — New module: the Poseidon ZK-friendly hash over `bn254` (circomlib's
  parameters, `t = 2..17`) and `bls12_381` (the authors'
  `poseidonperm_x5_255_{3,5}`). The sibling `groth16` and `bulletproofs`
  modules had no hash that is cheap *inside* a circuit, which left the ZK
  domain half-covered: SHA-256 costs tens of thousands of constraints
  where Poseidon costs a few hundred. Field arithmetic is reused
  unchanged from the sibling curve modules. Round constants and MDS
  matrices are **derived** by a port of the authors' Grain-LFSR generator
  rather than embedded (~700 KB of hex avoided), and pinned by SHA-256
  digests over the upstream constant files so a generator drift is
  distinguishable from a permutation bug. Anchored byte-exactly against
  the authors' own `hadeshash` `test_vectors.txt` (all four GF(p)
  instances, every output word), circomlibjs's published known answers,
  and a full `t = 2..17` sweep produced by *executing* circomlibjs's
  reference and optimized implementations and requiring them to agree.
  Two deployment realities are followed over the paper and documented:
  circomlib rounds `R_P` up to a multiple of `t`, and it ships Poseidon
  twice (a folded/optimized form storing the MDS transposed, and the
  reference form) — this implements the reference form, byte-compatible
  with both. The generator's MDS subspace-trail security checks
  (`algorithm_1/2/3` + `check_minpoly_condition`,
  Grassi-Rechberger-Schofnegger) and the rejection loop around them are
  now implemented too, on a small `GF(p)` linear-algebra + polynomial
  layer built for the purpose (`src/linalg.zig`: echelon/rank/kernel,
  characteristic and order polynomials, pseudo-remainder gcd, Rabin
  irreducibility, base-field root isolation — all division-free on the
  hot path, because a field inversion here is ~380 multiplications).
  This **removes the boundary** the module used to carry: `grain.derive`
  no longer needs a sage run alongside to be trusted on a new
  `(n, t, R_F, R_P)`. No shipped table changed — all 18 accept their
  first candidate, now an assertion rather than prose. A rejection is not
  a no-op (it consumes another `2t` Grain draws, shifting everything
  after it), and since a 254-bit field rejects with probability
  ~`2^-236` — zero rejections in a sweep of 816 BN254 parameter sets —
  that path is exercised over a small prime, where a third of candidates
  are rejected, and cross-checked against an independent sympy port of
  the same sage source on the verdict, the sub-code and the failing
  round. Two provable `O(t^5)` → `O(t^3)` rewrites make it affordable;
  both ship next to the literal transcription they are tested against.
  The permutation is constant-time (fixed bounds, no data-dependent
  branch or index) but not disassembly-verified, unlike the sibling
  `k256`/`montint` modules; parameter derivation is not constant-time and
  consumes only public inputs. On BLS12-381 only the permutation is
  anchored — the `hash`/`compress` framing has no deployed counterpart on
  that field and differs from `neptune`/dusk/arkworks, which is flagged
  at the call site. Variable-length sponge, Poseidon2 and Rescue/
  Rescue-Prime are out of scope; Rescue (the sibling `rescue` module) is
  named as the follow-up.
