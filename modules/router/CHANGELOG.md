# router — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-22** — `RouteDoc.Response` gains `schema: ?[]const u8 = null` (JSON Schema text of
  the response body) and `media_type = "application/json"`, for `openapi` to describe response
  bodies. Defaults keep every existing `RouteDoc` literal meaning what it meant.

- **2026-09-22** — `router.Static(routes, options)`: a route table built at compile time over the
  same matcher as `Router` — `match(method, path, *Params)` returns `.found` (route index),
  `.method_not_allowed` (an `Allow`) or `.not_found`; `trailingSlashVariant` is the redirect probe
  as a pure function. Pattern errors are compile errors. New public helpers: `Allow` (`has`,
  `write`), `validatePattern` (the per-pattern grammar `Router.add` and `Static` share), `rawPath`.
  `Router`'s API and behaviour are unchanged; a differential test compares the two on generated
  tables, every method, both `MethodPrecedence` postures.
- **2026-09-22** — **NO CONSUMER-VISIBLE CHANGE:** the matcher (`matchRecDepth` → `matchIn`) is
  now generic over a tree's node accessors, so a comptime route table can reuse it; the runtime
  trie is its first implementation and every existing router test passes unchanged.
- **2026-09-11** — **BEHAVIOURAL + API change (user-approved, Q7/Q8 — `QUESTIONS-ROUND-2.md`),
  changes observable behavior for all 18 in-repo consumers** — A1/router.md F5, F6, F8, F11 closed.
  - **F5 (405/method precedence, HIGH-adjacent footgun):** new `method_precedence` (default
    `.backtrack`) makes the matcher keep trying sibling candidates — static, then `:param`, then
    `*wildcard` — until one serves the request's method, instead of committing to the first
    candidate with ANY endpoint regardless of method. Before this, registering `POST /users/new`
    could silently turn a working `GET /users/new` (served by `GET /users/:id`) into a 405, with
    nothing in that diff mentioning `/users/:id`. RFC 9110 §15.5.6 also required a 405's `Allow` to
    list every method the target *path*, not one trie node, supports — `Allow` is now the union of
    every candidate the search actually visited, via a new per-node method bitset
    (`Node.allow_bits`). `method_precedence = .first_match` restores the exact old behavior and its
    performance characteristics, including that a root `*wildcard` OPTIONS route never backtracks
    into a node some other method already claimed. Measured RED (`.first_match` default) → GREEN
    (`.backtrack` default): the audit's own repro (`GET /users/:id` + `POST /users/new`) went from
    405 to 200 for `GET /users/new`; 2 permanent regression tests fail under the reverted default,
    pass under the fixed one.
  - **F6 (stack footprint, no behavior change beyond the type/cap below):** `Ctx.params` is now
    `*const Params` (was a 520 B-`@sizeOf` value, copied twice per dispatch — once into the local
    that built it, once into `Ctx`); `max_params` is now 8, not 16 (no in-repo pattern or consumer
    ever used more than 2), shrinking `Params` itself from 520 B to 264 B. `tryRedirect` is now
    `noinline`, so its 4 KiB `Location` scratch buffer is no longer part of every dispatch's stack
    frame regardless of whether a redirect is ever attempted (audit measured this costing the SAME
    ~13 KiB whether or not a request redirects, or even whether `trailing_slash == .strict`).
    Measured: `@sizeOf(Ctx)` 576 B → 64 B, `@sizeOf(Params)` 520 B → 264 B (comptime facts, old
    values from a literal reconstruction of the pre-fix layout). One in-repo consumer needed a
    one-line fix: `modules/validate`'s `PathParams` middleware passed `&ctx.params` (now already a
    pointer) to `validateParams`.
  - **F8 (open param-name footgun):** `add`/`addDoc` now reject a pattern that reuses one
    `:name`/`*name` capture twice (`/:a/:a`) with `error.DuplicateParamName`. Before this such a
    pattern was accepted and `params.get("a")` silently returned only the first value forever — a
    typo (`/:id/:id` instead of `/:id/:sub_id`) that would otherwise never surface. Closes
    `modules/openapi`'s own Š2 seam (`A1/openapi.md`): its `writePathParameters` dedup, added to
    keep a duplicate-named pattern from producing a document OAS 3.1 §4.8.10 forbids, is no longer
    reachable through any live `router.add` caller (kept as defense in depth, now unit-tested
    directly instead of through `Router`).
  - **F11 (open redirect footgun):** `add`/`addDoc` now reject a pattern containing an empty
    segment anywhere but a single trailing one (`error.InvalidPattern` — `//evil.example/x`, `/a//b`
    are now refused; `/x/`, one trailing empty segment, is still the documented distinct
    trailing-slash route). Before this, a leading/interior empty segment was silently accepted into
    the trie, and a trailing-slash redirect for a path under it emitted a protocol-relative
    `Location` (`//evil.example/x`) a browser reads as `http://evil.example/x`.
  - All 18 in-repo consumers re-verified unchanged (`scripts/modtest <m>`), `example-apps/http-service`
    checked by hand (registers no pattern these two new `AddError` variants would reject, and its
    only `ctx.params` use is `.get(...)`, unaffected by the pointer type) — pending `check-examples`.
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
