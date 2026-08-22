# ocspcache — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `FetchError`/`RefreshError` gain `error.Canceled`, and `httpFetch`
  (the production `Transport` behind `httpTransport`) no longer folds a canceled
  `http.Client` call into `error.TransportFailed`. Both of its `catch` sites named
  the variant explicitly: the initial `client.request`, and the `readAllAlloc` body
  read one call later (the second only became fixable once `http`'s own root cause —
  `Response.readAllAlloc`'s blind `else` arm — was fixed; see `http`'s
  `CHANGELOG.md`). `Cache.refresh`'s own `self.transport.fetch(...)` switch was
  exhaustive over `FetchError`'s old three variants and needed the fourth arm added
  to keep compiling. **BREAKING (narrow):** an exhaustive `switch` over `FetchError`
  or `RefreshError` stops compiling until it handles `error.Canceled`; a
  `catch |e| switch (e) { ... else => }` (every in-repo caller, including the
  `example/`) is unaffected. Two new loopback tests, one per fixed `catch` site (a
  peer that never answers, and a peer that answers a `Content-Length: 5` head and
  then no body), each confirmed to fail with its own fix reverted
  (`expected error.Canceled, found error.TransportFailed`) and to pass restored,
  without disturbing the other. `zig build test-ocspcache` — 34/34.
- **2026-08-06** — Security audit: six findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified against a live capture from
  nginx `ngx_ssl_stapling` / Apache `mod_ssl` stapling cache.
- **2026-07-22** — New module: OCSP-stapling fetch + cache on top of `ocsp`.
