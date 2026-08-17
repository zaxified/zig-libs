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

Not a security primitive: raw byte matching means no percent-decoding and no case folding — ever,
regardless of `normalize_path` — so anything relying on either for safety must handle it itself (or
ahead of the router). `router` does not authenticate or authorize — identity attaches via a
`Ctx.data` slot middleware (e.g. an auth layer) points at, not via router state. Handler/middleware
errors propagate to `http.Server`, which produces a plain 500 when nothing was sent; the router does
not catch or classify errors itself.

**`normalize_path` (dot-segment posture) — what this module can and cannot control.** The actual
RFC 3986 §5.2.4 rewrite runs in `http.Server.serveOne`, upstream of `dispatch`, unconditionally —
that call site is off-limits to this module. `req.target` is preserved raw there specifically so a
private copy could be normalized without losing it, which is what makes all three `normalize_path`
postures implementable entirely inside `router`: `.remove_dot_segments` (default) does nothing —
`req.path` already carries the rewrite, unchanged from before this option existed.
`.reject_non_canonical` recomputes the raw path from `req.target` (strip anything from `?` on) and
byte-compares it against `req.path`; a mismatch means `removeDotSegments` changed something, so the
request 400s before `matchRec` ever runs. `.off` overwrites `req.path` with that same raw
recomputation before matching, so both the matcher and the handler see the un-rewritten bytes. None
of this reaches into `http` — it is all a consequence of `req.target`/`req.path` already being two
separate, mutable fields on a `Request` the router receives by pointer.

**Match depth is bounded by this module.** `matchRec` descends one frame per path segment, and
`max_path_segments` (256) refuses anything deeper — a 404, since nothing that deep is routable.
The bound used to be inherited from `http.Server.max_normalized_path` (8 KiB, i.e. ~4096 frames for
`/a/a/…`): safe on a default stack, but by an argument living in another module, and not applying
at all to a caller driving `Router` directly, which is a supported use. The regression test goes at
`matchRec` rather than through the wire for exactly that reason.

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
