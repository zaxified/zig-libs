# health

Liveness + readiness probe endpoints as a `router` middleware — the
Kubernetes / load-balancer health-check contract.

- **Liveness** (`/healthz`, configurable): always **200** ("the process is up
  and answering HTTP"). A liveness failure means *restart me*; a process that
  can run this handler is alive, so an orchestrator restarts only on *no
  response*.
- **Readiness** (`/readyz`): **200** when every registered `Check` passes, else
  **503** with one `not ready: <name>` line per failing check. A readiness
  failure means *remove me from the LB rotation but do not restart* — use it
  for recoverable dependencies (database reconnecting, cache warming, load
  shedding).

It is a middleware (not handlers) because `router.Handler` carries no
per-instance state: the middleware owns the config and intercepts the two probe
paths, passing everything else through. **Register it before auth/rate-limit
middleware** so an orchestrator's probe (which cannot present a token) is never
gated.

```zig
fn dbReady(ctx: ?*anyopaque) bool {
    return @as(*App, @ptrCast(@alignCast(ctx.?))).db_connected.load(.acquire);
}
var checks = [_]health.Check{ .{ .name = "database", .checkFn = dbReady, .ctx = &app } };
var h = health.Health{ .checks = &checks };
try r.use(h.middleware());
```

- **Status:** `gap`. **Role:** util. **Platform:** any. **Deps:** `router`,
  `http`. **Concurrency:** threadsafe — the config is immutable; readiness is as
  thread-safe as your `Check` callbacks (run on the connection thread; make
  them non-blocking atomic-flag loads).

Provenance: clean-room from the documented Kubernetes liveness/readiness probe
model and the conventional `/healthz`–`/readyz` endpoints. No third-party
source consulted or copied.

## Verification

`zig build test-health` — 4 offline tests through `http.Server.serveStream`
(liveness always-200 + pass-through, readiness 200/503 with the failing-check
listing, empty-checks default, custom paths), green in Debug + ReleaseFast.
