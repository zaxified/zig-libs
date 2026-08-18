# router

REST routing on top of `http.Server` — method + path patterns with params
and wildcards, a middleware chain, route groups, and 404/405 defaults.
First module of the Web service / API cluster: `ratelimit`, `abuseguard`,
`throttle`, `openapi`, `cors`, `validate` and `metrics` plug in here as
middleware.

- A segment-trie matcher + middleware chain over
  `http.Server`.
- **Model after:** Go `chi` / `julienschmidt/httprouter` (segment trie,
  deterministic precedence, 404/405 + `Allow`, trailing-slash redirect).
- **Platform:** any. **Role:** server. **Concurrency:** reentrant —
  building (`add`/`use`/`group`) is single-owner; a built Router is
  immutable and `dispatch` is read-only + allocation-free, safe from all
  of `http.Server`'s connection threads at once.
- **Deps:** `http`.

Provenance: original work of the zig-libs authors (MIT); the trie matcher +
middleware chain are clean-room, modeled after Go `go-chi/chi` (MIT) and
`julienschmidt/httprouter` (BSD-3-Clause) — segment trie, deterministic
precedence, 404/405 + `Allow`, trailing-slash redirect. Design references only,
no source consulted or copied.

## Usage

```zig
const std = @import("std");
const http = @import("http");
const router = @import("router");

fn hello(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("hello");
}

fn user(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll(ctx.params.get("id").?); // "/users/:id"
}

fn logger(_: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    try next.run(ctx); // wrap: code before/after = outer→inner order
}

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(.{ .run = logger });          // middleware BEFORE routes (chi rule)
try r.get("/hello", hello);
try r.get("/users/:id", user);
try r.get("/static/*path", serveFile);  // trailing wildcard
const api = try r.group("/api");        // prefix + per-group middleware
try api.use(.{ .run = requireAuth });
try api.get("/things/:id", thing);

var server = http.Server.init(io, gpa, .{
    .handler = r.handler(),
    .context = &r,                       // MUST be the Router
});
try server.listen();
```

Handlers get a `*Ctx`: the parsed `req` (`http.Server.Request`, including
`query`), the `res` writer, `params.get("name")`, the app-wide `state`
pointer (`Router.state`), a per-request `data` slot middleware can
point at request-scoped values (how `aaa-gate` will attach an identity),
and `matchedPattern()` — the matched route's pattern (e.g. `"/users/:id"`,
null in the 404/405 fallbacks), the bounded-cardinality label
`metrics`/`openapi` need. Stateful middleware carry their own
`Middleware.state` (how `ratelimit` carries its buckets) — no globals
anywhere.

Introspection: `Router.routes()` enumerates the registered table in
registration order as `{ method, pattern, doc }` (router-owned slice, valid
until `deinit`); `addDoc(method, pattern, handler, RouteDoc)` — on Router
and Group — attaches optional plain-data documentation (`summary`,
`description`, `tags`, `request_schema`, `responses`, `deprecated`;
deep-copied, stack temporaries safe) that `openapi` renders into an
OpenAPI 3.1 document.

## Semantics (documented choices)

| Topic | Behavior |
|---|---|
| Precedence | static > `:param` > `*wildcard` per segment, with chi-style backtracking (an endpoint-less static prefix falls back to a param sibling) |
| Params | `:param` never matches an empty segment; `*wildcard` must be the last segment and captures the remainder without the leading slash (may be `""`) |
| Matching | raw bytes — no percent-decoding, no case folding |
| Middleware | outer→inner = registration order: router `use` → group → nested group → handler; chains are frozen into routes at add time, so `use` after any route ⇒ `error.RoutesAlreadyRegistered`; router-level middleware also wraps 404/405 |
| 404 / 405 | overridable `not_found` / `method_not_allowed` handlers; on 405 the router sets `Allow` (registered methods in `http.Method` order, HEAD implied by GET) before the handler runs |
| HEAD | auto-routes to GET when no explicit HEAD route (the `ResponseWriter` suppresses the body and keeps GET framing) |
| Trailing slash | `.redirect` (default, httprouter): 301 for GET/HEAD, 308 otherwise, toward the slash variant that has the route, query preserved; `.strict` (chi): 404. `/x` and `/x/` are always registrable as two distinct routes |
| Path normalization | `normalize_path`, see below. Default `.remove_dot_segments`: today's behavior, unchanged |
| Auto OPTIONS | `auto_options` (default off), see the worked example below |
| Errors | handler/middleware errors propagate to `http.Server` → clean 500 when nothing was sent |

## Auto OPTIONS — a worked precedence example

`auto_options` (default `false`) answers an `OPTIONS` request `204 No Content`
with `Allow` set, but only on a path that already has *other* routes and no
explicit `OPTIONS` handler. It is **not** a catch-all, and a root wildcard
registered for `OPTIONS` is not one either — both share the same precedence
rule above the table (static > param > wildcard, with backtracking only
when the matched node has *no* endpoint at all, for any method). Concretely:

```zig
try r.get("/thing", getThing);
try r.options("/*catchall", corsPreflight); // meant as "catch every OPTIONS"

// OPTIONS /thing       -> 405 (Allow: GET, HEAD) — corsPreflight NEVER runs
// OPTIONS /nope/at/all -> corsPreflight runs (no other route exists there)
```

Why: `matchRec` finds `/thing` via its static child, which already has a GET
endpoint — so it returns that node immediately, *without ever looking at the
request's method*. Backtracking to the wildcard sibling only happens when
the matched node has no endpoint for *any* method, and `/thing` has one
(GET). So a root `OPTIONS /*path` route never intercepts `OPTIONS` on a path
that has other methods registered — set `auto_options = true` (or register
an explicit `OPTIONS` route per path) instead of relying on a wildcard
catch-all for CORS-style preflight handling.

## Path normalization (`normalize_path`)

`http.Server` runs RFC 3986 §5.2.4 dot-segment removal on the request path
**before** this module (or any handler) ever sees it, silently and
unconditionally — `/a/../b` arrives at `dispatch` already rewritten to `/b`.
That is invisible, and for most APIs exactly right. It is wrong for an API
where a path segment is caller data rather than route structure — a blob
store keyed by device/backup name, say — because a `..` segment then
silently becomes a *different, valid route* instead of an error.
`normalize_path` picks the posture:

```zig
var r = router.Router.init(gpa);
r.normalize_path = .reject_non_canonical; // or .off — see below
```

| Value | Behavior |
|---|---|
| `.remove_dot_segments` (default) | Trust `http.Server`'s rewrite — today's behavior, unchanged |
| `.reject_non_canonical` | 400, before any route matches, whenever the raw target's path isn't already canonical (`..`/`.`/`/..` etc. would have changed it) |
| `.off` | Bypass the rewrite for routing: dispatch on — and hand the handler — the raw, un-rewritten path (`ctx.req.path` reads the same raw value) |

`.reject_non_canonical` is the right choice for a key-in-path API: it turns
the silent reroute into a 400 instead. `.off` is for a caller that wants to
interpret the raw bytes itself (e.g. reject `..` as an invalid key, rather
than as an invalid *path*).

**`.reject_non_canonical` does not decode percent-encoding — same as every
other posture (see "Matching" above).** It compares the raw target against
`removeDotSegments`'s *literal-byte* rewrite, so a percent-encoded traversal
such as `/v1/blob/%2e%2e/other` is already "canonical" by that comparison —
`%2e%2e` never becomes `..` — and passes straight through to `matchRec`,
landing in a wildcard capture as the literal bytes `%2e%2e`. This option
closes the silent-reroute case (`..`), not the percent-encoding case; a
handler that percent-decodes a captured segment before using it as a key
(e.g. as a filesystem path or object-store key) must still treat the decoded
result as untrusted and re-validate it (see `filestore`'s `segmentSafe`
allowlist for one way to do that).

## Verification

- Offline: the full matrix (matching, precedence, backtracking, params,
  404/405 + `Allow`, HEAD→GET, both trailing-slash policies, middleware
  order/short-circuit/state, groups, keep-alive) driven through the
  socket-free `http.Server.serveStream` — no sockets, golden responses.
- In-process integration: `http.Server` + this router on `127.0.0.1:0`,
  exercised with the Phase-1 `http.Client` (dispatch, params, middleware
  header, 404/405 + `Allow` over a real TCP connection).

`zig build test-router`
