# opaque — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9807 Appendix
  C.1's published test vectors.
- **2026-07-12** — New module: OPAQUE — an asymmetric PAKE (RFC 9807),
  ristretto255-SHA-512 + 3DH + internal envelope (Identity KSF).
