# metrics — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `RequestMetrics`'s
  `.status = .code` granularity and any registry with many unrelated metric
  families are both cheaper — `getOrRegister`'s family lookup was O(registry
  size) per call (measured: 8000 families, 50.47us -> 0.03us, 1802x); a scrape's
  transient exposition buffer now pre-sizes from the previous scrape instead of
  growing from zero (measured: 20000-series registry, peak transient 1.17x ->
  1.00x the exposition size). No output changed, no API changed — `Registry`
  gained two internal fields (a name->family index, a size hint), both purely
  additive. Also: three false doc claims corrected (lock-free-hot-path and
  "still bounded" language now distinguish `.status = .class`/`.code`; UTF-8
  and escaping doc comments no longer overclaim what the code enforces), and
  three previously-untested code paths (an `.identity`-framed response's byte
  count, a backwards-moving clock, and JSON range-control-byte escaping) now
  have regression tests — the code in all three cases was already correct.
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
