# metrics — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Licensing correction, no code change. `NOTICE` said the reproduced
  Prometheus exposition-format excerpt "adds no condition beyond MIT's own". It is
  Apache-2.0 material, so that was untrue when written: §4(a) asks that a copy of the
  License travel with it, and — uniquely among this repository's Apache upstreams —
  `prometheus/docs` ships a `NOTICE` (388 B), so §4(d) genuinely applies. The License is
  now reproduced in full, upstream's NOTICE is propagated verbatim, and the two omitted
  sections of the excerpt are stated as the §4(b) notice of change. The obligation has
  been in force since the excerpt was committed; only the record was wrong.
- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Prometheus `client_golang`
  (registry/instrument semantics) + text exposition format 0.0.4 (design reference, not
  a test anchor).
- **2026-07-02** — New module: Prometheus registry (counter/gauge/histogram) +
  `/metrics` + request middleware + access-log writer (combined/JSON).
