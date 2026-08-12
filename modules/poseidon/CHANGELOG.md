# poseidon — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- New module: the Poseidon ZK-friendly hash over `bn254` (circomlib's
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
