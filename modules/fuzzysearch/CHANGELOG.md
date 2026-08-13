# fuzzysearch — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: no findings. Modeled on Hanov trie+DP / Lucene
  `FuzzyQuery` / Schulz–Mihov (design reference, not a test anchor).
- **2026-07-24** — New module: Bounded-edit-distance typo-tolerant lookup over a static
  string set — DoS-bounded, the typo-tolerant sibling of `trie`.
