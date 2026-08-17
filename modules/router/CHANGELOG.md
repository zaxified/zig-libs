# router — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — New opt-in `normalize_path: NormalizePath` (default `.remove_dot_segments`,
  unchanged behavior). `http.Server` already runs RFC 3986 §5.2.4 dot-segment removal on the
  request path before `dispatch` ever sees it, silently and unconditionally — invisible, and wrong
  for an API whose path segments are caller data (a blob store keyed by device/backup name) rather
  than route structure, since a `..` segment then silently reroutes to a different, valid route
  instead of erroring. `.reject_non_canonical` answers 400 for a target whose path isn't already
  canonical, before any route matches; `.off` dispatches on — and hands the handler — the raw,
  un-rewritten path. New overridable `Router.bad_request` handler (used only by
  `.reject_non_canonical`, mirrors `not_found`/`method_not_allowed`). Also documented in README: a
  root `OPTIONS /*path` route does not catch `OPTIONS` on a path that has other methods registered
  (no backtracking across methods, only across segments) — a worked example, not new behavior.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — the trailing-slash redirect no longer forces
  an early `ResponseWriter.end()`. The `Location` value is built in a stack
  buffer and the early `end()` existed only to put the head on the wire before
  that frame died; `http`'s `setHeader` copies those bytes now. **What changes
  for a consumer:** a 301/308 from `trailing_slash = .redirect` is completed by
  the serving loop instead of inside `tryRedirect`, so anything wrapped around
  the router can still touch the head after `dispatch` returns. Nothing inside
  the router could: the redirect is answered *outside* the middleware chain,
  so no `next.run` post-step was ever watching. The bytes on the wire are
  unchanged.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on Go chi /
  julienschmidt/httprouter (design reference, not a test anchor).
