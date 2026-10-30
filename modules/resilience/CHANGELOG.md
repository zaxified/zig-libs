# resilience — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-30** — **CONSUMER-VISIBLE (fixes only):** no-panic sweep + blind review (§ GO). Invalid breaker/Bulkhead options were `std.debug.assert`s (UB in ReleaseFast — `bucket_ms = 0` divided by zero) and are now checked panics in every build mode, rejecting exactly the same values; a time-bucket divisor is also clamped for a breaker built without `init`. `Bulkhead.release` without an acquire is a no-op in every mode (was an assert). `Retry.nextDelayFrom` reads `attempt` 0 as 1, panics with a message on a NaN/negative/infinite `factor` or a `jitter_factor` outside [0, 1] (was UB in ReleaseFast), and `base_delay_ms = 0` gives 0 at every attempt (a huge attempt returned `max_delay_ms`). `RateCircuitBreaker` time-mode counters are u64 (u32 overflowed after 2^32 calls in one bucket; a slot is 32 B), `counts()` saturates them. `Bulkhead.acquire` also sums its sleeps, so a stuck clock no longer waits forever. `Clock` documents that it runs under the breaker's spinlock. Tests: `src/sweep_test.zig`.
- **2026-10-19** — **Fix:** `Retry.nextDelayFrom` with `Jitter.proportional`, `jitter_factor = 1` and a `max_delay_ms` near `maxInt(u64)` (a "no cap" spelling) rounded `delay × factor` to 2^64 and `@intFromFloat` trapped (UB in ReleaseFast); the conversion now saturates (NaN and negative give 0). Test: "Retry.nextDelayFrom: proportional jitter with an uncapped (maxInt) ceiling…". Found by the 2026-10-19 consumer audit; the rest of the module (breaker states, window roll, bulkhead, `run`) was read and found sound.
- **2026-10-18** — Zig 0.17.0: `@hasDecl` sees only `pub` declarations, so an operation type's hooks must be `pub`: a non-`pub` `call` is a compile error, while a non-`pub` `setDeadline`, `retryOnResult` or `retryAfterMs` is silently ignored (the hook is treated as absent). No code change; README notes it.
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
