# spf-ect — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-15** — New module: Deterministic symmetric shortest-path (Dijkstra) with a
  reversal-invariant ECT tie-break (`path(A→B) == reverse(path(B→A))`, RFC 6329 idea
  generalized) + maximally-disjoint second tree (PRP mode).
