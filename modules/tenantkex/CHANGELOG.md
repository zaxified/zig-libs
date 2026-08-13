# tenantkex — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-24** — New module: Per-tenant key exchange — a Noise_IK handshake (via
  `noise`) between two provider edges with the I-SID bound into the prologue, deriving
  the two directional channel keys that feed `aeadframe`; pure.
