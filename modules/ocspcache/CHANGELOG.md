# ocspcache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  nginx `ngx_ssl_stapling` / Apache `mod_ssl` stapling cache.
- **2026-07-22** — New module: OCSP-stapling fetch + cache on top of `ocsp`.
