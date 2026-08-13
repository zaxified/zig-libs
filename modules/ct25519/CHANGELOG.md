# ct25519 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-10** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  8032 §7.1's published test vectors.
- **2026-08-09** — New module: Constant-time-on-secrets scalar multiplication for
  Edwards25519 / Ristretto255.
