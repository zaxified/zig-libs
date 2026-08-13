# aeskw — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: two findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 3394 §4.1's
  published test vectors.
- **2026-07-22** — New module: RFC 3394 AES Key Wrap (AES-128/256 KEK) — constant-time
  integrity check + scratch zeroization, byte-exact vs RFC 3394 §4.
