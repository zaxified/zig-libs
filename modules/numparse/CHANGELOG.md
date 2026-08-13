# numparse — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on ICU `NumberFormat` parse
  (design reference, not a test anchor).
- **2026-07-09** — New module: Locale-aware grouped-number parsing (thousands/decimal
  separators) into an exact `decimal.Decimal`.
