# isis-dis — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on FRRouting `isisd` (DIS
  election, `isis_events.c` / `isis_dr.c`) (design reference, not a test anchor).
- **2026-07-24** — New module: IS-IS LAN Designated-IS election (ISO 10589 §8.4.5).
