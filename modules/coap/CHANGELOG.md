# coap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against RFC 7252.
- **2026-07-08** — New module: CoAP (RFC 7252) — a full client/server stack: message
  codec (header/token/delta-encoded options/payload), `options` (registry, CoAP uint,
  URI ↔ options §6), `reliability`.
