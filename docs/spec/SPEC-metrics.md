# SPEC — `metrics`

**Purpose** — Observability for anything internet-facing: a thread-safe
metrics registry (Counter/Gauge/Histogram), a `GET /metrics` endpoint in the
standard Prometheus text format, and a `router` middleware recording the
golden request signals (rate, errors, duration, in-flight) — so Prometheus/
Grafana/Alertmanager just work.

**Model after / Seed** — Clean-room; no seed project. Design references:
Prometheus client_golang (Apache-2.0 — registry/instrument semantics:
get-or-register per (name, label values), lazy series creation, inclusive
`le` buckets, NaN handling) and the Prometheus text exposition format 0.0.4 /
OpenMetrics spec (format only). Behavior and wire format modeled, no source
copied (NOTICE).

**Design & invariants**
- **`Registry`** owns metric families; `counter`/`gauge`/`histogram` are
  *get-or-register* — the first call with a given (name, label values) creates
  the instrument, later calls return the same stable pointer. Names/help/
  label/bucket values are copied into the registry's arena (callers may pass
  stack temporaries); `deinit` frees everything at once.
- **Instruments:** `Counter` is a monotonic `u64` (deviation from
  client_golang: integer-valued, not float — sufficient for event counts).
  `Gauge` is `f64` with `set`/`inc`/`dec`/`add`/`sub`. `Histogram` has
  configurable `le` upper bounds, cumulative bucket counts, `_sum`/`_count`
  and the implicit `le="+Inf"` bucket. Instruments cap at `max_labels` (8)
  label pairs.
- **Thread-safety:** counters/gauges are single atomics (`.monotonic` — no
  cross-metric ordering needed; a scrape is never a consistent
  cross-instrument snapshot anyway, same as client_golang). Registration
  lookups and `Histogram.observe` take a documented spinlock
  (`std.atomic.Mutex` + `spinLoopHint`, the std `SmpAllocator` pattern — Zig
  0.16 std has no io-less blocking mutex) with string-compare-sized critical
  sections; `writeText` holds the lock for the whole scrape, but steady-state
  request paths only read (get-or-register means registration is rare).
- **`RequestMetrics` middleware:** a request counter (`method` + status
  *class* `2xx`/…/`5xx` by default — `.status = .code` opts into exact codes),
  a latency histogram in seconds (`method`), an in-flight gauge (inc on
  entry, dec via `defer`, including on handler error), and an optional
  `on_request` access-log hook (`{method, path, status, duration_ns, bytes}`,
  `path` borrowed). Registered around `next` so 404/405/429/503
  short-circuits are measured; series creation failure (OOM) skips recording
  but never fails the request.
- **Exposition deviations from client_golang** (all documented, all still
  valid to scrape): emission order is registration order, not sorted by
  name/labels; floats render shortest-round-trip decimal, not Go `%g`;
  invalid bucket config is a typed `error.InvalidBuckets`, not a silent strip
  or panic. `metrics.handler(registry) → router.Handler` from the original
  brief is not implementable (`router.Handler` is a stateless fn pointer that
  cannot close over a `Registry`); `Endpoint` (an intercepting middleware) is
  the replacement.

**Threat model / out of scope** — Not a security primitive; it does not
authenticate scrapers (front `Endpoint` with your own auth/network policy if
`/metrics` must be gated). **The cardinality footgun is the real hazard**:
every distinct label-value combination is a permanent time series. Label
values must come from a small, fixed set (method, status class, route
pattern) — never from request data (raw path, user id, query values, IPs), or
the registry becomes an unbounded memory leak and the scrape melts
Prometheus. This is why the middleware defaults to status *classes* and does
not label by raw path (a bounded route-pattern label is planned once `router`
exposes the matched pattern). No push-gateway / remote-write support — text
exposition only.

**Verification** — `zig build test-metrics`, 20 tests: counter monotonicity +
get-or-register identity, gauge set/inc/dec/add/sub, histogram cumulative
buckets with inclusive `le` + `_sum`/`_count` + empty-bucket-list + NaN,
name/label/bucket validation errors, input-copy proof, golden exact-bytes
exposition (incl. escaping and `le="+Inf"`), an 8-thread stress on shared
instruments with exact totals plus a concurrent get-or-register convergence
stress; middleware tests over the socket-free `http.Server.serveStream`
(per-method/class counts incl. 404/405/handler-error-500, injected-clock
deterministic latency buckets, in-flight observed mid-request, `.code`
granularity, custom names/buckets, access-log hook fields, scrape-not-counted
proof, endpoint goldens + HEAD + 405 + pass-through + custom path); an
in-process `router`+`http.Server`+`http.Client` loopback integration run
(mixed 2xx/3xx/4xx/5xx traffic → scrape asserts exact counter values,
histogram `_count`s, in-flight back at 0, one TYPE line per family).

**Status** — `gap · posix · util · threadsafe` · deps: `router`, `http`.
