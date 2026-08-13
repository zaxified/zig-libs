# montint — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — **Timing fix — neither breaking nor behavioural.** `condSubTop` (the final
  conditional subtract of every `montMulCios`, `montSqrCios`, `add` and
  `doubleMod`) and `sub`'s masked add-back were compiled by ReleaseFast into a
  branch on the secret-derived borrow — the classic Montgomery
  final-subtraction leak, revealing per multiply whether the pre-reduction value
  was `≥ m`. It sat on the portable CIOS path, which `asm_min_limbs = 32` makes
  the default for every modulus below 2048 bits on amd64 and for every non-amd64
  target: RSA-2048 CRT sign/decrypt with secret `dP`/`dQ` (L=16), `paillier`,
  and `threshold_ecdsa`'s `powCt`. Both masks are now laundered through the
  module's `blackBox` optimization barrier, and `scripts/ctgrind.sh montint`
  measures 0 in-file contexts at all three dispatch sizes, down from 7 (L=4) and
  5 (L=16). Classified as **neither BREAKING nor BEHAVIOURAL**: no signature,
  error set or field changes, and no computed value changes — every input maps
  to the same output it did before, verified by the KAT/differential suite. What
  changes is only the instruction schedule. Callers who were relying on the
  documented constant-time contract were getting something weaker than the
  contract said; they now get what it said. `condSubTop` was also rewritten into
  the sibling asm core's two-pass masked form, which drops an `Elem` of stack —
  measurement says that rewrite is NOT what fixed the leak (see SPEC.md).
- **2026-08-13** — Test coverage for the conditional subtract's boundary behaviour: the existing
  smoke test could never produce a carry word, so the `top = 1` half of the
  borrow chain was untested, as was the outgoing-borrow term that only fires on
  a limb where `v[i] == m[i]` — dropping that term left the whole suite green.
  Covered now in **both** copies of the routine, `montint.condSubTop` and
  `asm_core.condSub` (the latter at `n = 32`, the smallest width the dispatch
  routes there); each is caught only by its own constructed case.
- **2026-07-18** — Performance: gained an asm/Montgomery core (part of a collection-wide
  performance campaign that also covered the sibling `k256`/`p256`
  modules; the root changelog records no further detail than this).
