# isis-dis — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — Tests: first mutation run (28 mutants, 28 killed); added tests for big-endian SNPA / system-id comparison (difference in the first octet) and for a local DIS that changes only its pseudonode id (no became/resigned). SPEC §5.2: change is keyed on `lan_id`.

- **2026-08-06** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on FRRouting `isisd` (DIS
  election, `isis_events.c` / `isis_dr.c`) (design reference, not a test anchor).
- **2026-07-24** — New module: IS-IS LAN Designated-IS election (ISO 10589 §8.4.5).
