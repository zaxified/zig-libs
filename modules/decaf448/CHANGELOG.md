# decaf448 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Licensing: added `NOTICE` (kind `third-party attribution`). No code
  changed. `src/kat_vectors.zig` reproduces RFC 9496 Appendix B's test vectors, which the
  module's `Provenance:` statement never mentioned — it answers for the code. The record
  rests on the IETF Trust's written grant, TLP 5.0 §4.c Revised BSD, reproduced in the new
  file, rather than on the merger doctrine.
- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9496 Appendix B's
  published test vectors.
- **2026-07-16** — New module: decaf448 prime-order group (RFC 9496, "The ristretto255
  and decaf448 Groups", §5) over `ed448`'s edwards448 curve.
