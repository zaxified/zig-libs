# rescue — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: three findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Verified: byte-exact against three
  independently-verified upstream vector sources (each pinned by commit hash and file
  SHA-256).
- **2026-07-29** — New module: Rescue-Prime Optimized (RPO) over Goldilocks
  `p = 2^64 - 2^32 + 1`, at both published instances (`m = 12`, `m = 16`),
  both sponge framings that exist upstream, and the paper's round order
  as a separate permutation. The sibling to `poseidon`: same motivation
  (cheap inside a circuit), opposite trade — Rescue alternates `x^α` with
  `x^(1/α)`, which is far more expensive in software and cheaper to
  prove. Measured here: the inverse S-box layer is **15x the forward one
  and 76% of the whole permutation**; hashing 512 bytes costs 61x
  SHA-256. The field lives inside the module (~240 lines, canonical,
  branch-free) rather than becoming a new general-purpose module.
  **The variant was chosen on anchoring, not deployment**: plain
  Rescue-Prime's reference implementation publishes **no** test vectors,
  while RPO publishes 38. Constants are derived (SHAKE256) and pinned
  element-by-element against miden-crypto's embedded values; `1/α` is
  computed and checked three ways, including replaying its 72-multiply
  addition chain symbolically over exponents. Three upstream divergences
  are documented rather than smoothed over: miden-crypto changed its
  state layout in a breaking PR so every digest changed (a single-value
  test tells the corpora apart); the two RPO sponges disagree on padding,
  capacity placement and the empty input, so both ship with a test
  asserting they never collide; and **Winterfell's Rescue-XLIX round
  constants could not be re-derived** from the generator its own comment
  cites, so that one table is an honestly-labelled embedded blob pinned
  by file digest plus the published KAT — while the same generator
  reproduces miden's RPO tables exactly. Constant-time throughout (the
  inverse S-box is a fixed addition chain, not a ladder), not
  disassembly-verified. Byte-level hashing is grade-2 anchored: no
  upstream byte KAT exists anywhere in miden-crypto.
