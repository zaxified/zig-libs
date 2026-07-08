# upstream

A **load-balanced upstream pool with health** — the piece an API gateway
needs to route calls across a backend fleet with failover. Register
upstreams (`id`, `host:port`, `weight`), then `pick()` the next healthy one
per a pluggable load-balancing strategy, `report()` outcomes back (passive
health via a per-upstream `resilience.CircuitBreaker`), run caller-driven
active health checks (`healthTick`) through `probe`'s connector seam, and
route with automatic failover via `call()`.

Provenance: clean-room — no seed project and no third-party code. Design
references (behavior only, no source consulted or copied): Envoy
(Apache-2.0) and HAProxy (documented behavior only) upstream-cluster
semantics — health-checked member set, pluggable LB policy, per-member
circuit breaking and concurrency caps; resilience4j (Apache-2.0) Bulkhead
for the per-upstream concurrency cap (via the `resilience` sibling).
Round-robin, smooth weighted round-robin (the nginx algorithm),
least-connections and EWMA latency balancing are public, decades-old
techniques. See ../../NOTICE.

- **Status:** `gap`.
- **Model after:** Envoy/HAProxy upstream cluster + resilience4j Bulkhead.
- **Platform:** any — pure logic; active-health I/O goes through the
  injected `HealthChecker`/`probe.Connector` seam. **Role:** client.
  **Concurrency:** threadsafe — `pick`/`report`/`call`/`healthTick`/stats
  are internally synchronized (pool spinlock + atomics; breaker/bulkhead
  synchronize themselves); registration (`add`) and `deinit` are
  single-owner setup/teardown.
- **Deps:** `resilience` (breaker + bulkhead), `probe` (`Target` address
  model + `Connector` health seam).

## Layers

| Layer | What | Needs |
|---|---|---|
| `Pool.add(spec)` | register `{ id, "host:port", weight }`; builds breaker + optional bulkhead | nothing (typed errors, bounded fleet) |
| `pick()` | next healthy upstream per `Strategy`, skipping down / breaker-open / bulkhead-full; null when none | a matching `report()` per pick |
| `report(u, ok, rtt)` | passive health: feeds the breaker, frees the slot, folds latency/EWMA | — |
| `healthTick(now)` | active health: mark up/down + breaker recovery probe, at most once per interval | an injected `HealthChecker`, caller-supplied `now` |
| `call(op, .{.max_tries})` | route + failover: pick → run → report → next healthy on failure | an op with `call(self, u: *Upstream) E!T` |
| `upstreamStats(u)` / `stats()` | health, breaker state, in-flight, picks, failures, latency min/avg/max | — |

## Strategies

- `round_robin` — strict rotation over the healthy set (default).
- `random` — uniform over the healthy set, from a **seeded** PRNG
  (`Options.seed`; Zig 0.16 std has no ambient entropy, no hidden globals).
- `weighted_round_robin` — smooth WRR (the nginx algorithm): over any
  window of `sum(weights)` picks each healthy upstream is chosen exactly
  `weight` times, interleaved rather than bursty.
- `least_connections` — fewest in-flight calls.
- `ewma_latency` — lowest EWMA of reported RTTs (`ewma_alpha`);
  never-measured upstreams score 0 and get tried first (warm-up).

## Usage

```zig
const upstream = @import("upstream");

var pool: upstream.Pool = .init(gpa, .{
    .strategy = .least_connections,
    .breaker = .{ .failure_threshold = 5, .cooldown_ms = 30_000 },
    .max_per_upstream = 64, // per-upstream Bulkhead; 0 = uncapped
    .seed = boot_entropy,   // for .random
});
defer pool.deinit();
_ = try pool.add(.{ .id = "api-1", .address = "10.0.0.1:8080" });
_ = try pool.add(.{ .id = "api-2", .address = "10.0.0.2:8080", .weight = 2 });

// The gateway's route-+-failover primitive: the op receives the chosen
// upstream; failures are reported and the next healthy one is tried.
const Fetch = struct {
    pub fn call(_: *@This(), u: *upstream.Upstream) !u16 {
        return doRequest(u.address); // classify 5xx as an error
    }
};
var op: Fetch = .{};
const status = try pool.call(&op, .{ .max_tries = 3 });

// Active health (e.g. from the accept/event loop, real clock in hand):
var lc: probe.LiveConnector = .{ .io = io };
var hc: upstream.ConnectorHealthChecker = .{ .conn = lc.connector() };
// … set Options.health_checker = hc.healthChecker() at init, then:
pool.healthTick(now_ns);
```

## Semantics notes

- **Pick is a full admission.** A non-null `pick()` has taken the
  upstream's bulkhead slot and its breaker admission and bumped in-flight —
  follow every successful pick with **exactly one** `report()` (`call()`
  does this for you). A lost report leaks the slot and, in a half-open
  breaker, the probe budget.
- **Passive vs active health.** `report(ok=false)` feeds the breaker —
  `failure_threshold` consecutive failures trip it and `pick` skips the
  upstream until the cooldown admits a probe. `healthTick` is orthogonal:
  a failing check sets a down mark (skipped regardless of breaker state);
  a passing check clears it and doubles as the breaker's recovery probe,
  walking `open → half_open → closed` across ticks without risking a live
  request.
- **No hidden clock.** `healthTick(now_ns)` is caller-driven; the breaker's
  clock is injected via `Options.breaker.clock`; the RTT stopwatch used by
  `call()` is `Options.clock`. Tests drive everything with a virtual clock.
- **`call()` failover** returns the first success, the last operation error
  once picks are exhausted (`max_tries` bound), or
  `error.NoHealthyUpstream` when nothing was pickable and no attempt ran.
  Retried attempts may repeat side effects — only idempotent work.
- **Borrowed strings.** `id` and the parsed `address` host are slices into
  the caller's storage — keep it alive for the pool's lifetime.
- **Bounded, no panics.** The fleet is capped (`max_upstreams`); a bad
  `host:port` is a typed error; empty/exhausted pools return null/typed
  errors.

## Verification

`zig build test-upstream` — fully offline and deterministic (scripted fake
operation + fake `HealthChecker` + virtual clock; no sockets anywhere):
registration bounds/duplicate/parse errors; round-robin cycles healthy
upstreams; a failing upstream trips its breaker, is skipped, and is
re-admitted after the cooldown; bulkhead-full upstreams are skipped and
`pick` returns null when all are full; least-connections and EWMA pick the
least-loaded/fastest; smooth-WRR distributes exactly by weight (and never
bursts); seeded random is reproducible and never picks a down upstream;
failover `call` tries the next healthy upstream, honors `max_tries`,
returns the last error when exhausted and `NoHealthyUpstream` when nothing
was pickable; `healthTick` marks down/up, gates on the interval, and walks
a recovered breaker `open → half_open → closed`; per-upstream + pool stats;
plus a 4-thread `call()` hammer asserting the per-upstream bulkhead cap is
never exceeded and no slot leaks.
