# spake2plus — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Byte-exact against RFC 9383
  Appendix C's published test vectors.
- **2026-07-12** — New module: SPAKE2+ — an augmented (asymmetric) PAKE (RFC 9383),
  P-256/SHA-256/HKDF/HMAC ciphersuite (the Matter/Thread commissioning PAKE) —
  `proverStart`/`verifierStart`.
