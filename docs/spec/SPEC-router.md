# SPEC — `router`

REST routing on top of `http.Server`. First module of the Web service / API cluster (T5).
`extract · any · server · reent`. Model after: Go `chi` / `julienschmidt/httprouter` (radix/trie
matcher). Seed: `~/workspace/axp/axp-central/src/rest.zig` (hand-rolled route dispatch to learn
from). Deps: `http`. New `build.zig` entry `.{ .name = "router", .deps = &.{"http"} }`.

## Why

`http.Server` gives you one handler for all requests. Every REST API needs to map
method + path patterns to handlers, extract path params, and compose middleware
(auth/ratelimit/cors/logging). This is the integration point the rest of the cluster
(`ratelimit`, `abuseguard`, `throttle`, `openapi`, `cors`, `validate`, `metrics`) plugs into.

## Scope

1. **Route table:** register `(method, pattern) → handler`. Patterns support static segments,
   **named params** (`/users/:id`), and a trailing **wildcard** (`/static/*path`). Deterministic
   precedence (static > param > wildcard), matched via a radix/trie or a clear ordered matcher.
2. **Param extraction:** expose matched params to the handler (`params.get("id")`), plus the query
   already parsed by `http.Server.Request`.
3. **Middleware chain:** `use(mw)` composition where a middleware wraps `fn(*Request, *ResponseWriter, next)`.
   Order is outer→inner, deterministic. This is how `ratelimit`/`cors`/`aaa-gate`/`metrics` attach.
   Support route-group prefixes with their own middleware (`group("/api", ...)`).
4. **Defaults:** 404 (no route) and 405 (path matches, method doesn't — set `Allow` header) handled
   with overridable handlers. HEAD auto-routes to GET when no explicit HEAD. Optional trailing-slash
   policy (redirect or strict) — pick one, document it.
5. **Wiring:** a `Router` is itself an `http.Server` handler — `Server.init(.{ .handler = router.handler, .context = &router })`
   (or an adapter). Keep the router usable against the socket-free `serveStream` path too (for tests).

## Public API sketch (final shape your call; keep it small)

```zig
pub const Router = struct {
    pub fn init(gpa) Router;
    pub fn deinit(*Router) void;
    pub fn add(self, method: http.Method, pattern: []const u8, h: Handler) !void;   // + get/post/put/delete/patch helpers
    pub fn use(self, mw: Middleware) !void;                 // global middleware
    pub fn group(self, prefix: []const u8) *Group;          // prefixed sub-router w/ own middleware
    pub fn handler(self) http.Server.Handler;               // plug into http.Server
};
pub const Params = struct { pub fn get(name) ?[]const u8; };
pub const Ctx = struct { req: *http.Server.Request, res: *http.Server.ResponseWriter, params: Params, ... };
pub const Handler = *const fn (*Ctx) anyerror!void;
pub const Middleware = *const fn (*Ctx, next: Handler) anyerror!void;
```

## Acceptance / verification

- **Offline unit tests:** matcher — static/param/wildcard matching + precedence, 404 vs 405
  (with correct `Allow`), param extraction, trailing-slash policy, HEAD→GET fallback; middleware
  order (record call order in a global-free way, e.g. via ctx/context), group prefixes + per-group
  middleware. Drive these through the socket-free `http.Server.serveStream` (no socket needed).
- **In-process integration (must NOT skip normally):** start `http.Server` with the router on
  `127.0.0.1:0`, hit several routes with the Phase-1 `http.Client` — assert dispatch, path params,
  a middleware that sets a header ran, and 404/405 behavior.
- `zig build test-router` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered in `build.zig` (`deps = &.{"http"}`).

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 std APIs. Reuse `http.Server`'s Request/ResponseWriter and its
  socket-free `serveStream` for tests. Do NOT reimplement HTTP.
- Look at the axp `rest.zig` seed for the shape of a real hand-rolled dispatcher, but build a proper
  pattern matcher (params/wildcards) — that's the value over a giant if/else.
- Keep allocation explicit and bounded; the matcher can precompute at `add` time. No hidden globals
  (middleware order must be testable without touching process state).
- This is the base the whole cluster builds on — keep the middleware interface clean and stable.
