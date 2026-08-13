# staticfiles — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — **BEHAVIOURAL, not breaking** — a representation header that cannot be set
  now answers 500 instead of serving the body without it. `Content-Type` (both
  the file path and the directory index) and a configured `Cache-Control` were
  set with a bare `catch {}`, so once the response writer's 4 KiB copy store
  was spent — by middleware ahead of this handler — the file went out looking
  fine and silently unlabelled. An unlabelled body is MIME-sniffed by the
  browser, which is how an uploaded .txt or .jpg becomes stored XSS; a dropped
  `Cache-Control` puts content in a shared cache the operator meant to keep out
  of one. Both now discard the half-composed response and answer 500.
  **What changes for a consumer:** a response that used to be a 200 missing its
  Content-Type or Cache-Control is now a 500. Nothing within the budget
  changes. `Last-Modified`, `Accept-Ranges` and the 405's `Allow` stay
  best-effort and now say why at the call site: the first two cost only a
  conditional-request round trip or resumable downloads, and answering 500 in
  place of a 405 would throw away the more useful answer.
- **2026-08-06** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Verified against RFC 9110
  §13.1.2.
- **2026-07-22** — New module: path-traversal-safe static file handler over `http`.
