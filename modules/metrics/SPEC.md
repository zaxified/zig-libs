# metrics — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
`Registry` owns metric families; `counter`/`gauge`/`histogram` are get-or-register — first call
with a given (name, label values) creates the instrument in the registry's arena, later calls
return the same stable pointer; `deinit` frees everything at once. `Counter` = monotonic `u64`
(deviation from Prometheus client_golang: integer not float). `Gauge` = `f64`. `Histogram` has
configurable `le` upper bounds, cumulative counts, `_sum`/`_count`, implicit `+Inf` bucket.
Instruments cap at `max_labels` (8) pairs. Modeled after Prometheus client_golang registry/instrument
semantics + the Prometheus text exposition format 0.0.4 — see NOTICE. Thread-safety: counters/gauges
are single atomics (`.monotonic`, no cross-instrument ordering needed); registration lookups and
`Histogram.observe` take a documented spinlock (`std.atomic.Mutex` + `spinLoopHint`) with
string-compare-sized critical sections; `writeText` holds the lock for the whole scrape.
`RequestMetrics` middleware (request counter by method+status-class, latency histogram, in-flight
gauge, optional `on_request` access-log hook) wraps `next` so 404/405/429/503 short-circuits are
measured; series-creation OOM skips recording but never fails the request. Exposition deviations
from client_golang (documented, all still valid to scrape): registration-order emission, not
sorted; shortest-round-trip float rendering; `error.InvalidBuckets` instead of silent strip/panic.

## Threat model / out of scope
Not a security primitive — does not authenticate scrapers; front `Endpoint` with your own
auth/network policy if `/metrics` must be gated. The cardinality footgun is the real hazard: every
distinct label-value combination is a permanent time series, so label values must come from a
small fixed set (method, status class, route pattern) — never raw path/user id/query/IP, or the
registry becomes an unbounded memory leak. This is why the middleware defaults to status classes,
not raw path. No push-gateway / remote-write — text exposition only.

## Verification
`zig build test-metrics` covers: counter monotonicity + get-or-register identity, gauge
set/inc/dec/add/sub, histogram cumulative buckets (inclusive `le`, `_sum`/`_count`,
empty-bucket-list, NaN), name/label/bucket validation errors, input-copy proof, golden exact-bytes
exposition (escaping, `le="+Inf"`), an 8-thread stress on shared instruments with exact totals plus
a concurrent get-or-register convergence stress; middleware tests over socket-free
`http.Server.serveStream`; an in-process `router`+`http.Server`+`http.Client` loopback integration
run (mixed 2xx/3xx/4xx/5xx traffic → scrape asserts exact values).

### External-anchor investigation: `prometheus_client` (2026-08-01, done)

The in-house grammar checker (`validateExpositionText`) and the frozen published-example
excerpt (both above) close the "is this syntactically valid exposition format" gap but were,
until now, the only oracle — self-consistency, not independent verification. A real
independent parser is now available: `prometheus_client`'s
`parser.text_string_to_metric_families`, the same reader library code that talks to a
Prometheus server, run in a throwaway venv (`~/.cache/zig-libs-metrics`). It was run once,
offline, feeding it the exact byte string this module's own `writeText` produces for a
representative registry (counter + gauge + histogram, covering backslash/quote/newline
escaping and cumulative buckets) — see `src/root.zig`, "external anchor: exposition text
independently parsed by prometheus_client", for the full quoted parse and the frozen text.
**No disagreement was found**; every value, label and escape was extracted correctly. One
finding, not a bug: `prometheus_client` strips the `_total` counter suffix at the *family*
level (`api_requests`, not `api_requests_total`) while samples keep it — a real client-library
convention this module's own checker has no notion of either way, confirmed rather than
assumed. Per the governing rule the tool was run once and its verdict frozen as a permanent
offline test; no `/NOTICE` entry (black-box parsing oracle, root NOTICE §0 — the module's
existing NOTICE for the vendored documentation excerpt is unrelated and unaffected).

## Backlog / deferred
A bounded route-pattern label for the request middleware, once `router` exposes the matched
pattern (currently deliberately not labeled by raw path — cardinality risk). `metrics.handler(registry)
→ router.Handler` from the original brief is not implementable (a stateless fn pointer cannot close
over a `Registry`); `Endpoint` is the shipped replacement. No push-gateway/remote-write planned.

## Status
`gap · posix · util · threadsafe` + deps: `router`, `http` — canonical source is `pub const meta`
in src/root.zig.
