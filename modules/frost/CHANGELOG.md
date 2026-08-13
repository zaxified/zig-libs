# frost — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9591 Appendix
  E.5's published test vectors.
- **2026-07-12** — New module: FROST — Flexible Round-Optimized Schnorr Threshold
  signatures (RFC 9591), secp256k1/SHA-256 ciphersuite — a t-of-n threshold Schnorr
  scheme: trusted-dealer keygen (Shamir + Feldman VSS), 2-round.
