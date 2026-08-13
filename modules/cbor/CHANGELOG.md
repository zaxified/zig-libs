# cbor — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8949 Appendix A's published test vectors.
- **2026-07-21** — New module: CBOR (RFC 8949) codec — decode/encode all 8 major types,
  definite + indefinite length, a `canonical` deterministic-encoding option (§4.2.1
  bytewise map-key sort); untrusted-input hardened.
