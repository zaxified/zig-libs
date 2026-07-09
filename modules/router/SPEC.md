# router — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Precomputed trie, allocation-free dispatch:** the matcher is a per-segment trie built at `add`
  time; `dispatch` is read-only, lock-free, and allocation-free (captured params live on the stack)
  — one built `Router` safely serves all of `http.Server`'s connection threads at once. Dispatch
  shape extracted from axp `axp-central/src/rest.zig` (same authors, Apache-2.0, relicensed MIT);
  the trie matcher and middleware chain are clean-room, modeled after Go `chi` /
  `julienschmidt/httprouter` (segment trie, deterministic precedence, 404/405 + `Allow`,
  trailing-slash redirect) — see NOTICE.
- **Frozen middleware chains:** outer→inner = registration order (router `use` → group → nested
  group → handler), computed per route at `add` time. `use` after any route has been registered is
  `error.RoutesAlreadyRegistered` (chi's rule, surfaced as a typed error, not a footgun).
  Router-level middleware also wraps the 404/405 fallbacks, so cross-cutting middleware sees misses
  too.
- **Deterministic precedence:** static > `:param` > `*wildcard` per segment, with chi-style
  backtracking (an endpoint-less static prefix falls back to a param sibling). Raw byte matching —
  no percent-decoding, no case folding; `:param` never matches empty, `*wildcard` must be last and
  captures the remainder (possibly `""`).
- **Documented edge policies:** HEAD auto-routes to GET when no explicit HEAD exists; 405 sets
  `Allow` (registered methods in `http.Method` order, HEAD implied by GET) before the handler runs;
  trailing slash is `.redirect` (default: 301 GET/HEAD, 308 otherwise, query preserved) or `.strict`
  (404) — `/x` and `/x/` are always independently registrable; auto-`OPTIONS` is opt-in.
- **Concurrency:** building (`add`/`use`/`group`) is single-owner; a built `Router` is immutable —
  reentrant.

## Threat model / out of scope

Not a security primitive: raw byte matching means no path normalization, so anything relying on
percent-decoding or case-insensitive routing for safety must handle it itself (or ahead of the
router). `router` does not authenticate or authorize — identity attaches via a `Ctx.data` slot
middleware (e.g. an auth layer) points at, not via router state. Handler/middleware errors
propagate to `http.Server`, which produces a plain 500 when nothing was sent; the router does not
catch or classify errors itself.

## Verification

33 tests. Offline: the full matrix (matching, precedence, backtracking, params, 404/405 + `Allow`,
HEAD→GET, both trailing-slash policies, middleware order/short-circuit/state, groups, keep-alive)
driven through the socket-free `http.Server.serveStream`. In-process integration: `http.Server` +
this router on `127.0.0.1:0`, exercised with the Phase-1 `http.Client` (dispatch, params, middleware
header, 404/405 + `Allow` over a real TCP connection). Run: `zig build test-router`.

## Backlog / deferred

None found in PLAN.md or the module README.

## Status

`extract · any · server · reentrant` + deps: `http` — canonical source is `pub const meta` in
src/root.zig.
