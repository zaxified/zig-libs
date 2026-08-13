# procnet — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: three findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  gopsutil (Go) / procps-ng.
- **2026-07-09** — New module: Linux `/proc`+`/sys` parsers — ARP/routes/TCP+UDP
  sockets/conntrack/process stats/device health, typed.
