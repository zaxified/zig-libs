# SPEC — `upstream`

**Purpose** — A load-balanced upstream pool with health: the piece an API gateway needs to route
calls across a backend fleet with failover. Register upstreams (`id`, `host:port`, `weight`), then
`pick()` the next healthy one per a pluggable strategy, `report()` outcomes back for passive health,
run caller-driven active health checks (`healthTick`), and route with automatic failover via
`call()`. Composes two siblings rather than reimplementing them: a per-upstream
`resilience.CircuitBreaker` (passive health) and optional per-upstream `resilience.Bulkhead`
(concurrency cap), plus `probe`'s `Connector` seam for active checks.

**Model after / Seed** — Clean-room; no seed project, no third-party code. Design references
(behavior only, no source consulted or copied, per `NOTICE`): Envoy (Apache-2.0) and HAProxy
(documented behavior only) upstream-cluster semantics — health-checked member set, pluggable LB
policy, per-member circuit breaking and concurrency caps; resilience4j's Bulkhead for the
per-upstream concurrency cap (via the `resilience` sibling). Round-robin, smooth weighted
round-robin (the nginx algorithm), least-connections and EWMA latency balancing are public,
decades-old techniques, not attributed to a single source.

**Design & invariants**
- **Pick is a full admission.** A non-null `pick()` has already taken the upstream's bulkhead slot
  and breaker admission and bumped in-flight — every successful pick must be followed by exactly one
  `report()` (`call()` does this automatically); a lost report leaks the slot and, under a half-open
  breaker, the probe budget.
- **Passive vs. active health are orthogonal.** `report(u, ok, rtt_ns)` feeds the breaker only
  (`failure_threshold` consecutive failures trip it, `pick` skips until cooldown admits a probe).
  `healthTick(now_ns)` is caller-driven and separate: a failing check sets a down mark (skipped
  regardless of breaker state); a passing check clears the mark and doubles as the breaker's
  recovery probe, walking `open → half_open → closed` across ticks without risking a live request.
- **Five strategies** (`Strategy` enum): `round_robin` (default, strict rotation), `random` (uniform,
  seeded `std.Random` from `Options.seed` — no ambient entropy, no hidden globals),
  `weighted_round_robin` (smooth WRR, the nginx algorithm — each healthy upstream chosen exactly
  `weight` times per window of `sum(weights)`, interleaved not bursty), `least_connections` (fewest
  in-flight), `ewma_latency` (lowest EWMA of reported RTTs; never-measured upstreams score 0 and are
  tried first for warm-up).
- **No hidden clock.** `healthTick(now_ns)` is caller-driven; the breaker's clock is injected via
  `Options.breaker.clock`; the RTT stopwatch inside `call()` uses `Options.clock`. Tests drive
  everything with a virtual clock, no real sleeps.
- **Concurrency:** `pick`/`report`/`call`/`healthTick`/stats are internally synchronized (a pool
  spinlock for strategy state — cursor, PRNG, smooth-WRR credits, latency — plus atomic counters);
  the breaker/bulkhead synchronize themselves independently. `add` (registration) and `deinit` are
  single-owner setup/teardown, not meant to race with pool use. The injected `HealthChecker` runs
  outside the pool lock since it may perform I/O.
- **Bounded, typed-error, no panics.** The fleet is capped by `max_upstreams`; a malformed
  `host:port` is a typed error; `call()` returns the first success, the last operation error once
  `max_tries` picks are exhausted, or `error.NoHealthyUpstream` when nothing was pickable at all.
  `id` and the parsed address host are borrowed slices into caller storage — must outlive the pool.

**Threat model / out of scope** — Not a security primitive: it does not authenticate upstreams, does
not encrypt/verify traffic, and trusts whatever health signal (`HealthChecker`, `report(ok=...)`) the
caller feeds it — a caller reporting false health defeats both passive and active health without any
detection here. Retried attempts inside `call()`'s failover may repeat side effects; only idempotent
operations are safe to route this way (the same caveat the `resilience` sibling documents for its
own retry). No congestion control or backpressure signaling to callers beyond the per-upstream
bulkhead cap and `NoHealthyUpstream`/`BulkheadFull` errors. Active health I/O correctness (e.g. TCP
connect semantics) is `probe`'s responsibility, not this module's — `upstream` only decides when to
call the checker and how to fold its result into pick eligibility.

**Verification** — `zig build test-upstream`, 17 tests, fully offline and deterministic (scripted
fake operation + fake `HealthChecker` + virtual clock, no real sockets): registration
bounds/duplicate/parse errors; round-robin cycles the healthy set; a failing upstream trips its
breaker, is skipped, and is re-admitted after cooldown; bulkhead-full upstreams are skipped and
`pick` returns null when all are full; least-connections and EWMA pick the least-loaded/fastest;
smooth-WRR distributes exactly by weight without bursting; seeded random is reproducible and never
picks a down upstream; failover `call` tries the next healthy upstream, honors `max_tries`, returns
the last error when exhausted and `NoHealthyUpstream` when nothing was pickable; `healthTick` marks
down/up, gates on the interval, and walks a recovered breaker `open → half_open → closed`;
per-upstream and pool-wide stats; a 4-thread `call()` hammer asserting the per-upstream bulkhead cap
is never exceeded and no slot leaks.

**Status** — `gap · any (pure logic; active-health I/O via the injected seam) · client · threadsafe`
· deps: `resilience` (breaker + bulkhead), `probe` (`Target` address model + `Connector` health
seam).
