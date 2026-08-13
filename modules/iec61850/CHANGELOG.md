# iec61850 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  `libiec61850` (C, MZ Automation).
- **2026-07-23** — New module: IEC 61850 substation automation — MMS (ISO 9506) client
  over ISO-on-TCP with the ACSI object model, plus GOOSE publish/subscribe encoding and
  SV sampled values.
