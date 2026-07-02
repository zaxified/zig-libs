# router

REST routing on top of `http.Server` — method + path patterns with params
and wildcards, a middleware chain, route groups, and 404/405 defaults.
First module of the Web service / API cluster: `ratelimit`, `abuseguard`,
`throttle`, `openapi`, `cors`, `validate` and `metrics` plug in here as
middleware.

- **Status:** `extract` — the dispatch shape is seeded in axp
  (`axp-central/src/rest.zig`); the trie matcher + middleware chain are
  built here.
- **Model after:** Go `chi` / `julienschmidt/httprouter` (segment trie,
  deterministic precedence, 404/405 + `Allow`, trailing-slash redirect).
- **Platform:** any. **Role:** server. **Concurrency:** reentrant —
  building (`add`/`use`/`group`) is single-owner; a built Router is
  immutable and `dispatch` is read-only + allocation-free, safe from all
  of `http.Server`'s connection threads at once.
- **Deps:** `http`.

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
pointer (`Router.state`), and a per-request `data` slot middleware can
point at request-scoped values (how `aaa-gate` will attach an identity).
Stateful middleware carry their own `Middleware.state` (how `ratelimit`
carries its buckets) — no globals anywhere.

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
| Errors | handler/middleware errors propagate to `http.Server` → clean 500 when nothing was sent |

## Verification

- Offline: the full matrix (matching, precedence, backtracking, params,
  404/405 + `Allow`, HEAD→GET, both trailing-slash policies, middleware
  order/short-circuit/state, groups, keep-alive) driven through the
  socket-free `http.Server.serveStream` — no sockets, golden responses.
- In-process integration: `http.Server` + this router on `127.0.0.1:0`,
  exercised with the Phase-1 `http.Client` (dispatch, params, middleware
  header, 404/405 + `Allow` over a real TCP connection).

`zig build test-router`
