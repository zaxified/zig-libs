# router — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-11** — **NO CONSUMER-VISIBLE CHANGE (performance fix):** A1/router.md F4 closed.
  `matchRecDepth`'s backtracking search used to cost O(#nodes reachable within the query's
  length) rather than O(query length) — a route table with the same static segment name
  repeated at many depths, each with a `:param` sibling, is quadratic in table size (measured:
  ~2.01 ms/call for a 250-route adversarial table, reproducing the audit's own ~2 ms figure). A
  same-day memoization attempt measured 20-25x SLOWER (that construction's `:param` subtrees
  are disjoint, so backtracking never revisits a node — nothing to cache). Fixed instead with
  `Node.min_reach`: an admissible, incrementally-maintained lower bound on how many more
  segments a query needs from a given node to reach any endpoint in its subtree, checked in
  O(1) before descending into a child. Measured RED (bound removed) -> GREEN (bound restored):
  2,011,872 ns/call -> 296 ns/call on the audit's exact construction, ~6,800x. All 46 existing
  tests unchanged (`Node` is a private type; the check is a strictly necessary condition, so it
  can never reject a reachable match) plus 1 new permanent regression test. All 18 in-repo
  consumers re-verified unchanged (`scripts/modtest <m>` on each).
- **2026-09-10** — **BEHAVIOURAL, security-relevant fix (user-approved, changes observable behavior
  for all 18 in-repo consumers)** — 404, 405, auto-`OPTIONS`, `.reject_non_canonical`'s 400, and the
  trailing-slash redirect now run the middleware chain of whichever `group()`'s prefix the request
  path falls under (router-level `use` alone when it falls under none), instead of only the
  router-level chain (audit findings router-F1 HIGH, router-F2 HIGH). Before this, a gate registered
  via `group("/api").use(requireAuth)` — exactly what README's own usage example showed — never ran
  on a 405/auto-`OPTIONS`/404 inside `/api`, and the trailing-slash redirect skipped middleware
  entirely (answered straight from `dispatch`, outside any chain), so an unauthenticated caller could
  enumerate the protected route table via the 301-vs-404 difference and the canonical path it leaked
  in `Location`. New `Router.groupFor`/`fallbackChain` compute this from a per-group chain cached
  once at registration time (the first route anywhere under a group), so `dispatch` remains
  allocation-free. Also fixes `.remove_dot_segments`/`.reject_non_canonical` for a caller driving
  `Router` directly, without `http.Server` in front (audit finding router-F3 HIGH): both now
  recompute from `req.target` using `http.Server`'s own `checkOriginPath`/`pathHasDotSegments`/
  `normalizePathInto`, instead of trusting `req.path` was already normalized by something upstream —
  which for a direct caller had never happened, silently turning `.remove_dot_segments` into a no-op
  and `.reject_non_canonical` into a check that could never fire. Corrected three stale citations of
  the server's path-length cap (2 KiB / ~1024 frames, not 8 KiB / ~4096) picked up along the way.
  Consumers: run your own test suite if you register group middleware as an authorization boundary —
  a 405/404/redirect inside that group now reaches it, where it previously did not.
- **2026-08-18** — Security audit: README now states, next to `.reject_non_canonical` itself
  (not only in SPEC.md's threat model), that the option does not decode percent-encoding —
  `/v1/blob/%2e%2e/other` is already "canonical" by its raw-byte comparison and dispatches with
  the literal bytes `%2e%2e` in the wildcard capture, instead of the 400 a literal `..` gets. Not
  a code change: SPEC.md already disclosed "no percent-decoding … ever, regardless of
  `normalize_path`" — the gap was that README marketed `.reject_non_canonical` as the right
  posture for a key-in-path API without repeating the limit where that choice is made. Added a
  test pinning the current dispatch-not-reject behavior so it is a documented decision, not an
  accident that could silently change.
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
