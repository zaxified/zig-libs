# voprf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9497 Appendix
  A.1's published test vectors.
- **2026-07-12** — New module: (V)OPRF — Oblivious Pseudorandom Functions (RFC 9497),
  ristretto255-SHA-512 ciphersuite, all three modes: OPRF (base), VOPRF (verifiable) +
  POPRF (partially-oblivious).
