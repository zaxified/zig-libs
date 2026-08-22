# rdap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `HttpFetcher.fetchFn` no longer folds a canceled body read into
  `error.FetchFailed`: `FetchError` gained a `Canceled` variant, and the request +
  both `readSliceShort` sites now consult `http.Client.Response.readFailure()`
  (added in `2c03d99` for exactly this) via a new `mapFetchError` widener. Public
  API addition — a caller matching exhaustively on `FetchError`, `QueryError`, or
  any error set built from them needs a new arm. Proven by mutation: reverting the
  widener to always return `FetchFailed` fails the new cancellation test.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on ICANN RDAP
  tooling, `python-whois`/`rdap` libs, ARIN/RIPE RDAP servers (design reference, not a
  test anchor).
- **2026-07-07** — New module: RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois
  successor: query URLs, typed response model, IANA bootstrap, fetch seam.
