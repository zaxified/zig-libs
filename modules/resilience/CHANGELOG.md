# resilience — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-17** — Scope core → parity (grade 3 → 2). **BREAKING:** `Policy.breaker` is a `?BreakerHandle` (was `?*CircuitBreaker`): `.breaker = &cb` → `.breaker = cb.handle()`; `RunResult` adds `error.BulkheadFull` (for `Policy.bulkhead`); the state enum is `BreakerState` (`CircuitBreaker.State` still names it). New: `RateCircuitBreaker(n)` (failure-rate and slow-call-rate trip over the last n calls or n time buckets, `minimum_calls`); on every breaker `forceOpen`/`disable`/`reset`/`mode`, `record(outcome, duration)` with `Outcome.ignore`, `half_open_required_successes`, `slow_call_duration_ms`, `Options.listener` (state changes), `counts()`; `Policy.bulkhead`, `Policy.classify`, `Policy.on_retry`; operation hooks `retryOnResult` and `retryAfterMs`; `Retry.max_elapsed_ms`, `Jitter.proportional` + `jitter_factor`, `Retry.nextDelayFrom(attempt, bits)`. Speed: spinlock and bulkhead CAS back off exponentially (8 threads on one breaker 11× faster); factor-2 schedules skip `pow`; one random draw per jittered delay (the draw maps differently, so a seeded jittered sequence differs from before). Evidence: model-fuzz harnesses `resilience-breaker`/`-retry`/`-run` (`RESILIENCE_FUZZ`). Bench `zig build bench-resilience` vs gobreaker/failsafe-go/cenkalti: 0.03–0.60×.
- **2026-10-04** — **Tests:** mutation run (34 schemata mutants, 33 killed, 1 equivalent). New
  tests pin the half-open counters across a re-open, the reclaim anchor on the latest probe
  admission, `abandonProbe` while open, and a non-waiting bulkhead never reading its clock.
  No code change.

- **2026-07-19** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on resilience4j (composition +
  breaker states + semaphore Bulkhead) + Polly (consecutive-failure trip) + AWS
  full-jitter backoff (design reference, not a test anchor).
- **2026-07-02** — New module: Circuit breaker + retry/backoff + timeout + bulkhead
  (concurrency limiter) for calling upstreams (generic).
