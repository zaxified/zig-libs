# SPEC — `metrics`

Metrics registry (counter/gauge/histogram) + Prometheus text exposition + a request-metrics
`router` middleware. Web/API cluster (T5.8). `gap · any · util · tsafe`. Model after: Prometheus
`client_golang` + the OpenMetrics / Prometheus text exposition format. Deps: `router`, `http`.
New `build.zig` entry `.{ .name = "metrics", .deps = &.{ "router", "http" } }`.

## Why

Anything internet-facing needs observability. This gives a thread-safe metrics registry, an HTTP
`/metrics` endpoint in the standard Prometheus text format (so Prometheus/Grafana/Alertmanager just
work), and a middleware that records the golden request signals (rate, errors, duration, in-flight).

## Scope

1. **Registry + instruments (thread-safe):** `Counter` (monotonic), `Gauge` (up/down/set),
   `Histogram` (configurable `le` buckets → cumulative bucket counts + `_sum` + `_count`). Each
   instrument has a name, help text, and an optional fixed **label set** (small, fixed cardinality —
   document the cardinality caution). A `Registry` owns them; thread-safe via atomics (counters/gauges)
   and a documented lock for histogram observe / label lookup.
2. **Exposition:** `Registry.writeText(writer)` emits the **Prometheus text format** (`# HELP`,
   `# TYPE`, samples with labels, histogram `_bucket{le=…}`/`_sum`/`_count`). Provide a ready
   `router.Handler` (`metrics.handler(registry)`) to serve `GET /metrics`.
3. **Request middleware:** `metrics.middleware(registry, opts)` records per request — a request
   **counter** (labels: method, status class or code, and route pattern if available — keep
   cardinality bounded; status as a small class like 2xx/3xx/4xx/5xx by default), a **latency
   histogram**, and an **in-flight gauge** (inc on entry, dec via defer). Runs around `next`.
4. **Optional structured access log:** an optional per-request callback with `{method, path, status,
   duration_ns, bytes}` for a caller to log — keep it a hook, not a logger.

## Public API sketch (final shape your call)

```zig
pub const Registry = struct {
    pub fn init(gpa) Registry;  pub fn deinit(*Registry) void;
    pub fn counter(self, name, help, labels) *Counter;   // register/get
    pub fn gauge(self, name, help, labels) *Gauge;
    pub fn histogram(self, name, help, labels, buckets) *Histogram;
    pub fn writeText(self, w: *std.Io.Writer) !void;     // Prometheus exposition
    pub fn handler(self) router.Handler;                 // GET /metrics
};
pub fn middleware(reg: *Registry, opts: MwOptions) router.Middleware;
```

## Acceptance / verification

- **Offline unit tests:** counter inc/add (monotonic, never negative), gauge set/inc/dec, histogram
  observe → correct cumulative buckets + `_sum` + `_count`; label handling; `writeText` **golden**
  output for a known registry (exact bytes: HELP/TYPE lines, sample ordering, histogram bucket lines
  incl. `le="+Inf"`); a multi-thread stress (N threads incrementing a shared counter/histogram → exact
  totals, no lost updates).
- **In-process integration (must NOT skip normally):** router+`http.Server`+`http.Client` with the
  request middleware + `/metrics` route — drive several requests (mix of statuses), then `GET /metrics`
  and assert the exposition contains the request counter with the right counts, a latency histogram,
  and the in-flight gauge back at 0.
- `zig build test-metrics` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with `deps = &.{"router","http"}`.

## Notes for the implementer

- Use the **zig skill** (atomics, the repo's documented spinlock, std.Io.Writer for exposition). Reuse
  `router.Middleware {state,run}`, `router.Handler`, `Ctx`, and `ctx.res`.
- Prometheus text format must be exact (Prometheus is strict): escape `\`, `\n`, `"` in label values
  and help text; UTF-8; each metric family's HELP/TYPE once; histogram buckets cumulative + `+Inf`.
- Keep label cardinality bounded (status as a class by default) and document the footgun.
- SPDX header + a `Provenance:` line (clean-room; design ref Prometheus client_golang Apache-2.0,
  OpenMetrics spec — behavior/format only, no code copied).
