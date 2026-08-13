# whois — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on GNU `whois`
  (Debian), BSD `whois` (design reference, not a test anchor).
- **2026-07-07** — New module: RFC 3912 whois client — query format + referral chasing
  (IANA→registrar) + field extraction, transport-agnostic seam.
