# metrics

Thread-safe metrics registry (Counter / Gauge / Histogram), Prometheus text
exposition (`GET /metrics`), and a `router` middleware recording the golden
request signals — rate, errors, duration, in-flight. T5.8 of the Web/API
cluster.

Provenance: clean-room — original work of the zig-libs authors (MIT), no
third-party code. Design
references: Prometheus client_golang (Apache-2.0 — registry and instrument
semantics: get-or-register per (name, label values), lazy series creation,
`le`-inclusive buckets, NaN handling) and the Prometheus text exposition
format 0.0.4 / OpenMetrics spec (format only). Behavior and format modeled,
no source copied.

- **Model after:** Prometheus client_golang + text exposition format 0.0.4.
- **Platform:** posix — the default latency clock is the posix
  `clock_gettime` errno form (CLOCK_MONOTONIC); everything else is
  platform-free, and the clock is injectable.
- **Role:** util. **Concurrency:** threadsafe — counters/gauges are single
  atomics (`.monotonic`); registration lookups and `Histogram.observe` take
  a documented spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std
  SmpAllocator pattern — Zig 0.16 std has no io-less blocking mutex) with
  string-compare-sized critical sections. `writeText` holds the registry
  lock for the whole scrape; the middleware's steady-state hot path is
  lock-free (atomic per-method/class caches).
- **Deps:** `router` (Middleware/Ctx/Next), `http` (`Server.ResponseWriter`,
  `Method`).

## Usage

```zig
const metrics = @import("metrics");
const router = @import("router");

var reg = metrics.Registry.init(gpa);
defer reg.deinit();

// Custom metrics anywhere in the app — get-or-register, stable pointers:
const jobs = try reg.counter("jobs_total", "Jobs processed.", &.{
    .{ .name = "kind", .value = "import" },
});
jobs.inc();

// The request middleware + the /metrics endpoint:
var rm = try metrics.RequestMetrics.init(&reg, .{});
var ep = metrics.Endpoint{ .registry = &reg }; // .path defaults to "/metrics"

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(ep.middleware()); // outermost: scrapes are not counted as traffic
try r.use(rm.middleware());
try r.get("/api/thing", handler);
```

`Registry`, `RequestMetrics` and `Endpoint` must outlive the Router, at
stable addresses (middleware `state` points at them). Everything passed to
`counter`/`gauge`/`histogram` (names, help, labels, buckets) is copied into
the registry arena — stack temporaries are fine.

## The cardinality footgun (read this)

Every distinct label-value combination is a separate time series that lives
for the life of the registry and is scraped forever. Label values must come
from a **small, fixed set** (method, status class, route pattern) — never
from request data (raw path, user id, query values, IPs). A high-cardinality
label turns the registry into an unbounded memory leak and blows up
Prometheus's index. This is why the middleware:

- labels status as a **class** (`code="2xx"`…) by default —
  `.status = .code` opts into exact codes (still bounded, ~×10 series);
- does **not** label by path. A route-pattern label (`/users/:id`, bounded)
  is planned once `router` exposes the matched pattern to `Ctx` (route
  enumeration is a tracked router follow-up); labeling by raw path would be
  the footgun above.

Instruments cap at `max_labels` (8) label pairs.

## What the middleware records

Registered around `next`, so 404/405 fallbacks and inner short-circuits
(429/503) are measured too. A handler error is recorded as the status the
server sends (the already-sent status when the head is on the wire, else
500), and the in-flight decrement runs via `defer` even then. Series appear
lazily on first use (client_golang `WithLabelValues` behavior). Failure to
create a series (OOM) skips recording but never fails the request.

| Metric (default name) | Type | Labels |
|---|---|---|
| `http_requests_total` | counter | `method` (lowercase), `code` (`2xx`… or exact) |
| `http_request_duration_seconds` | histogram | `method`; buckets = client_golang `DefBuckets` |
| `http_requests_in_flight` | gauge | — |

Names, help, buckets, status granularity and the clock are configurable via
`RequestMetrics.Options`; bad names/buckets fail at `init`, not mid-request.

**Access-log hook:** `on_request` (+ `on_request_ctx`) gets an
`AccessEntry{ method, path, status, duration_ns, bytes }` per request — a
hook, not a logger: format/ship it yourself, keep it fast and thread-safe.
`path` is borrowed (copy to retain); `bytes` is the response body size when
knowable (exact for buffered bodies, declared Content-Length for identity
streams, 0 for HEAD/204/304, null for chunked streams).

## Exposition format

`Registry.writeText(writer)` emits exact Prometheus text format 0.0.4:
`# HELP` (backslash/newline escaped) and `# TYPE` once per family, then
every series: counters/gauges as one sample, histograms as **cumulative**
`_bucket{le="…"}` lines ending in `le="+Inf"`, then `_sum` and `_count`.
Label values escape `\`, `"` and newline. Specials render as `+Inf` /
`-Inf` / `NaN`. `Endpoint` serves it with
`Content-Type: text/plain; version=0.0.4; charset=utf-8` on `GET`/`HEAD`
(anything else on the path → 405 + `Allow`), other paths pass through.

Deviations from client_golang (noted in doc comments):

- **Counters are integer-valued** (`u64` `inc`/`add`) — monotonic and never
  negative by construction; float `Add` is out of scope for event counts.
- **Emission order** is registration order for families and series;
  client_golang sorts by name/labels. Both are deterministic and Prometheus
  does not require sorted input.
- **Floats** render as decimal shortest-round-trip (`{d}`), not Go `%g`
  (which switches to exponent notation at extreme magnitudes) — both parse
  identically on the Prometheus side.
- **Bucket validation errors** (`error.InvalidBuckets`) instead of
  client_golang's silent trailing-`+Inf` strip / panic on unsorted.
- The SPEC's `metrics.handler(registry) → router.Handler` is not
  implementable — `router.Handler` is a stateless fn pointer and cannot
  close over a Registry. `Endpoint` (an intercepting middleware, the `cors`
  pattern) is the ready-made replacement; `Registry.respond(res)` covers
  hand-written handlers that reach the Registry via their own `ctx.state`.

## Verification

`zig build test-metrics` — offline unit tests (counter monotonicity +
get-or-register identity; gauge set/inc/dec/add/sub; histogram cumulative
buckets with inclusive `le`, `_sum`/`_count`, empty bucket list, NaN;
name/label/bucket validation + type/help/label/bucket mismatch errors;
input-copy proof; **golden exact-bytes exposition** incl. escaping and
`le="+Inf"`; 8-thread stress on shared instruments with exact totals and a
concurrent get-or-register convergence stress), middleware tests over the
socket-free `http.Server.serveStream` (per-method/class counts incl. 404/
405/handler-error 500, injected-clock deterministic latency buckets,
in-flight observed mid-request, `.code` granularity, custom names/buckets,
access-log hook fields, scrape-not-counted proof, endpoint goldens + HEAD +
405 + pass-through + custom path), plus an in-process integration run
(`router` + `http.Server` + `http.Client` over loopback: mixed 2xx/3xx/4xx/
5xx traffic → scrape asserts exact counter values, histogram presence with
correct `_count`s, in-flight back at 0, one TYPE line per family) that only
skips when loopback binding is unavailable.
