# ripemd160 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: one finding fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Byte-exact against the
  official RIPEMD-160 test set (Dobbertin/Bosselaers/Preneel appendix, also ISO/IEC
  10118-3).
- **2026-07-21** — New module: RIPEMD-160 (ISO/IEC 10118-3) — std-crypto-style
  `init`/`update`/`final` streaming hash (little-endian length padding, unlike SHA-2's
  BE) + `hash160`.
