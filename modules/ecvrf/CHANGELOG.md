# ecvrf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9381 Appendix
  B.3's published test vectors.
- **2026-07-16** — New module: ECVRF-EDWARDS25519-SHA512-TAI — RFC 9381 Verifiable
  Random Function (suite_string `0x03`) over `std.crypto.ecc.Edwards25519` + SHA-512 — a
  VRF is the public-key analogue of a keyed hash.
