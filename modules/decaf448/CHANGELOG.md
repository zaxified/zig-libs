# decaf448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9496 Appendix B's
  published test vectors.
- **2026-07-16** — New module: decaf448 prime-order group (RFC 9496, "The ristretto255
  and decaf448 Groups", §5) over `ed448`'s edwards448 curve.
