# router — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Precomputed trie, allocation-free dispatch:** the matcher is a per-segment trie built at `add`
  time; `dispatch` is read-only, lock-free, and allocation-free (captured params live on the stack)
  — one built `Router` safely serves all of `http.Server`'s connection threads at once. Original
  work of the zig-libs authors (MIT); the trie matcher and middleware chain are clean-room, modeled
  after Go `chi` / `julienschmidt/httprouter` (segment trie, deterministic precedence, 404/405 +
  `Allow`, trailing-slash redirect) — see NOTICE.
- **Frozen middleware chains:** outer→inner = registration order (router `use` → group → nested
  group → handler), computed per route at `add` time. `use` after any route has been registered is
  `error.RoutesAlreadyRegistered` (chi's rule, surfaced as a typed error, not a footgun). A fallback
  — 404, 405, auto-`OPTIONS`, `.reject_non_canonical`'s 400, and a trailing-slash redirect — runs
  the middleware chain of whichever group's prefix the request path falls under (`Router.groupFor`,
  cached per group the first time a route anywhere under it registers — see "Fallback middleware
  scoping" below), router-level `use` alone when it falls under none. So `group("/api").use(gate)`
  wraps every response for `/api`, not only the ones a route actually served (audit findings
  router-F1/F2: before this, a 405/auto-`OPTIONS`/404 inside a group skipped the group's own
  middleware entirely, and a trailing-slash redirect skipped the FULL chain including router-level
  `use` — answered straight from `dispatch`, letting an unauthenticated caller enumerate the route
  table via the 301-vs-404 difference).
- **Deterministic precedence:** static > `:param` > `*wildcard` per segment, with chi-style
  backtracking (an endpoint-less static prefix falls back to a param sibling). Raw byte matching —
  no percent-decoding, no case folding; `:param` never matches empty, `*wildcard` must be last and
  captures the remainder (possibly `""`).
- **Method precedence (`method_precedence`, default `.backtrack`):** when more than one candidate
  produces the same path shape and they serve different methods, the matcher keeps trying siblings
  (static, then `:param`, then `*wildcard`, at every level) until one serves the request's method,
  instead of committing to the first candidate with ANY endpoint (audit finding router-F5 — before
  this, registering `POST /users/new` could silently turn a working `GET /users/new` — served by
  `GET /users/:id` — into a 405, because `new` (static) matches before `:id` (param) regardless of
  method). `Allow` on a genuine 405 is the union of every candidate the search actually visited
  (RFC 9110 §15.5.6: the header must list every method the *target resource* — the path, not one
  particular trie node — supports), tracked via a per-node method bitset (`Node.allow_bits`) unioned
  at request time; `min_reach` still prunes subtrees that cannot reach ANY endpoint, but not by
  method, so an adversarial table (`Node.min_reach`'s own doc comment, audit finding router-F4) can
  make a 405 visit every same-shaped candidate. `method_precedence = .first_match` restores the pre-2026-09-11 behavior (and its
  performance characteristics) verbatim, including that a root wildcard never backtracks into a
  node some OTHER method already claimed — see README's two worked examples.
- **Registration-time pattern validation:** a pattern must not reuse the same `:name`/`*name`
  capture at two different positions (`error.DuplicateParamName` — audit finding router-F8; before
  this, `/:a/:a` was accepted and `params.get("a")` silently returned only the first value forever)
  and must not contain an empty segment anywhere but a single trailing one (`error.InvalidPattern`
  — audit finding router-F11; before this, `//evil.example/x` was accepted, and a trailing-slash
  redirect under it emitted a protocol-relative `Location` a browser reads as
  `http://evil.example/x`, an open redirect). A single trailing empty segment — `/x/` — is still the
  documented, distinct trailing-slash route.
- **Documented edge policies:** HEAD auto-routes to GET when no explicit HEAD exists; 405 sets
  `Allow` (registered methods in `http.Method` order, HEAD implied by GET) before the handler runs;
  trailing slash is `.redirect` (default: 301 GET/HEAD, 308 otherwise, query preserved) or `.strict`
  (404) — `/x` and `/x/` are always independently registrable; auto-`OPTIONS` is opt-in.
- **Concurrency:** building (`add`/`use`/`group`) is single-owner; a built `Router` is immutable —
  reentrant. `Ctx.params` is a pointer into the dispatching call's own stack frame (audit finding
  router-F6, alongside halving `max_params` 16 → 8 — together these roughly halve the per-dispatch
  stack cost of `Params`/`Ctx`), valid strictly for that call, same as the `[]const u8` values it
  hands out; `tryRedirect` is `noinline` so its 4 KiB `Location` buffer is no longer part of every
  dispatch's stack frame regardless of whether a redirect is ever attempted.

## Threat model / out of scope

Not a security primitive: raw byte matching means no percent-decoding and no case folding — ever,
regardless of `normalize_path` — so anything relying on either for safety must handle it itself (or
ahead of the router). `router` does not authenticate or authorize — identity attaches via a
`Ctx.data` slot middleware (e.g. an auth layer) points at, not via router state. Handler/middleware
errors propagate to `http.Server`, which produces a plain 500 when nothing was sent; the router does
not catch or classify errors itself.

**`normalize_path` (dot-segment posture) — what this module can and cannot control.** `http.Server`
runs the same RFC 3986 §5.2.4 rewrite in `serveOne`, upstream of `dispatch`, unconditionally. `router`
does not rely on that having happened, though: `req.target` is preserved raw specifically so a
private copy can be normalized independently, which is what makes all three `normalize_path`
postures implementable entirely inside `router`, correct for a caller driving `Router` directly
(without `http.Server` in front, a supported use) and not only one sitting behind it.
`.remove_dot_segments` (default) recomputes `rawPath(req.target)` and, using `http.Server`'s own
`checkOriginPath`/`pathHasDotSegments`/`normalizePathInto` (the same building blocks `serveOne`
itself uses), rewrites `req.path` to the canonical form before matching — redundant work when
`http.Server` already did this (the result is byte-identical), but no longer a no-op for a direct
caller, which it silently was before (audit finding router-F3: the option's name and doc promised
this, `remove_dot_segments => {}` did not deliver it). `.reject_non_canonical` runs the same
`checkOriginPath`/`pathHasDotSegments` check directly against `rawPath(req.target)` and 400s before
`matchRec` ever runs when it finds a dot segment — no longer a byte-comparison against `req.path`
(which, for that same direct caller, started out equal to the raw target and so never fired at all).
`.off` overwrites `req.path` with that same raw recomputation before matching, so both the matcher
and the handler see the un-rewritten bytes. None of this reaches into `http`'s private state — the
three helpers it calls are already `pub`, used the same way `serveOne` uses them, and it is otherwise
all a consequence of `req.target`/`req.path` already being two separate, mutable fields on a
`Request` the router receives by pointer.

**Match depth is bounded by this module.** `matchRec` descends one frame per path segment, and
`max_path_segments` (256) refuses anything deeper — a 404, since nothing that deep is routable.
The bound used to be inherited from the server's own path-length cap (2 KiB, i.e. ~1024 frames for
`/a/a/…`): safe on a default stack, but by an argument living in another module, and not applying
at all to a caller driving `Router` directly, which is a supported use. The regression test goes at
`matchRec` rather than through the wire for exactly that reason.

**Fallback middleware scoping (`Router.groupFor`/`fallbackChain`).** Every `Group` a route is ever
registered under (directly, or via a nested subgroup) gets its own chain — router-level `use` plus
every ancestor's `use` root→leaf plus its own — cached exactly once, in `addRoute`, the first time
`routes_added` transitions true for it. That transition point is the one safe moment: `routes_added`
already gates `use()` on that group and, by walking every ancestor to the same true value, on every
ancestor too, so by the time `own_chain` is read the `mws` lists it was built from can never change
again. A fallback then picks the deepest registered group whose prefix is a segment-boundary prefix
of the request path (`"/api"` matches `"/api/x"` and itself, not `"/apix"`) and runs that group's
cached chain, or router-level `use` alone when the path falls under no group. All of this happens at
registration time, not per request — `dispatch` remains allocation-free and lock-free.

## Verification

Offline: the full matrix (matching, precedence, backtracking, params, 404/405 + `Allow`,
HEAD→GET, both trailing-slash policies, middleware order/short-circuit/state, groups, keep-alive)
driven through the socket-free `http.Server.serveStream`. In-process integration: `http.Server` +
this router on `127.0.0.1:0`, exercised with the Phase-1 `http.Client` (dispatch, params, middleware
header, 404/405 + `Allow` over a real TCP connection). Run: `zig build test-router`.

## Backlog / deferred

None found in the module README.

## Status

`extract · any · server · reentrant` + deps: `http` — canonical source is `pub const meta` in
src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** path trie + middleware dispatch, in-process; wire parsing is sibling http
