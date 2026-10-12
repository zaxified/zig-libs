# health

Liveness + readiness probe endpoints as a `router` middleware — the
Kubernetes / load-balancer health-check contract.

- **Liveness** (`/healthz`, configurable): always **200** ("the process is up
  and answering HTTP"). A liveness failure means *restart me*; a process that
  can run this handler is alive, so an orchestrator restarts only on *no
  response*.
- **Readiness** (`/readyz`): **200** when every registered `Check` passes, else
  **503** with one `not ready: <name>` line per failing check (set
  `detail = false` to keep the status but drop the names when the probe is
  reachable from outside the cluster — dependency names are internal
  topology). Every check runs exactly once per probe, so the body always
  matches the status. A readiness failure means *remove me from the LB
  rotation but do not restart* — use it for recoverable dependencies
  (database reconnecting, cache warming, load shedding).
- **Startup** (opt-in: `.startup = .{ .started = &flag }`, path `/startupz`):
  **503** until the application sets its flag (`flag.store(true, .release)`),
  then **200**. The flag is yours, so `Health` itself stays immutable.
- **JSON body** (opt-in, `json = true`): all probes answer
  `application/json; charset=utf-8` with `{"status":"up"|"down"}`; readiness adds
  `"details":{"<check>":{"status":"up"|"down"}}` unless `detail = false`
  (the shape of alexliesenfeld/health, without its timestamps).

It is a middleware (not handlers) because `router.Handler` carries no
per-instance state: the middleware owns the config and intercepts the probe
paths (liveness, readiness, and the opt-in startup path), passing everything else through. **Register it before auth/rate-limit
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

- **Role:** util. **Platform:** any. **Deps:** `router`,
  `http`. **Concurrency:** threadsafe — the config is immutable; readiness is as
  thread-safe as your `Check` callbacks (run on the connection thread; make
  them non-blocking atomic-flag loads).

Provenance: clean-room from the documented Kubernetes liveness/readiness probe
model and the conventional `/healthz`–`/readyz` endpoints. The opt-in JSON
body (2026-10-11) takes its *shape* from alexliesenfeld/health v0.8.1 (MIT),
read for its output format only; no code copied. The comparative benchmark
under `tools/` (`bench.zig` and its `go_bench/` reference side, 2026-10-11) is
our own tooling; it drives the reference only through its public API.

## Verification

`zig build test-health` — offline tests through `http.Server.serveStream`
(liveness always-200 + pass-through, readiness 200/503 with the failing-check
listing, empty-checks default, custom paths, startup latch, JSON body), green in Debug + ReleaseFast.
