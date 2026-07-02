# SPEC — `resilience`

Client-side fault tolerance for calling flaky upstreams: **circuit breaker + retry-with-backoff +
timeout**, generic over any fallible operation. Web/API cluster (T5.10). `gap · any · util · tsafe`.
Model after: resilience4j + Polly + `failsafe-go`. Deps: **none (std only)** — it wraps an arbitrary
operation; the caller composes it with `http.Client`. New `build.zig` entry
`.{ .name = "resilience" }` (no deps).

## Why

When the API calls other services (upstreams), a flaky/slow dependency shouldn't cascade into our
failure. This is the generic control logic — breaker, retry, timeout — that wraps such calls. Keeping
it dependency-free makes it reusable well beyond HTTP.

## Scope

1. **CircuitBreaker (clock-injected):** states `closed → open → half_open`. Trip to `open` when
   failures cross a threshold (count-based OR failure-rate over a rolling window — pick one primary,
   note the other). While `open`, calls **fast-fail** (return an error immediately) until the
   cooldown elapses, then `half_open` admits a limited number of probe calls; a probe success closes
   the breaker, a failure re-opens it. Thread-safe (atomics/documented lock). Time via an injected
   clock (posix `clock_gettime` errno form as elsewhere) so tests are deterministic.
2. **Retry with backoff:** `max_attempts`, base delay, exponential factor, max delay, **jitter**
   (full/equal — pick, document), and a `retryable(err)` predicate (only retry the errors/results the
   caller marks retryable). Sleep between attempts is done via an injected delay fn (tests inject a
   no-op/virtual sleep — do NOT hardcode a real sleep in the tested path).
3. **Timeout:** bound an operation's duration (a deadline the operation checks, or a best-effort
   wrapper) — document what it can and can't interrupt (a blocking syscall may not be interruptible;
   be honest, like the http connect-timeout caveat already in the repo).
4. **Compose:** `run(operation, policy)` (or a small builder) that applies breaker → retry → timeout
   around a generic `operation` (a fn/closure-struct returning success or a typed error). Generic over
   the operation's result type. Document the ordering (breaker wraps retry wraps the call, resilience4j
   style — note it).

## Public API sketch (final shape your call)

```zig
pub const CircuitBreaker = struct {
    pub fn init(Options) CircuitBreaker;   // failure_threshold, cooldown_ms, half_open_max, window, clock
    pub fn allow(self) bool;               // false = fast-fail (open)
    pub fn onSuccess(self) void;  pub fn onFailure(self) void;
    pub fn state(self) State;
};
pub const Retry = struct { max_attempts, base_delay_ms, factor, max_delay_ms, jitter, ... ;
    pub fn nextDelay(self, attempt: u32, rng) u64; };
// One-call composition (operation = a struct with a `call()` method or a fn ptr + ctx):
pub fn run(op: anytype, policy: Policy) !Result;   // applies breaker+retry+timeout
```

## Acceptance / verification

- **Offline unit tests (deterministic: injected clock + injected delay + a fail-scripted operation):**
  breaker trips to `open` after N failures → `allow()` false while open → after cooldown goes
  `half_open` → a probe success closes, a probe failure re-opens; retry runs exactly `max_attempts`,
  computes the right backoff delays (exponential + capped + jitter bounds), and honors `retryable`
  (non-retryable error → no retry); timeout fires on a slow op; **composition**: an operation that
  fails M<threshold times then succeeds is retried and eventually succeeds without tripping; one that
  keeps failing trips the breaker and then fast-fails subsequent calls. A small multi-thread check on
  the breaker counters.
- (No HTTP integration required — this is control logic. Optionally show a doc example wrapping
  `http.Client` in a comment, but tests use a synthetic operation.)
- `zig build test-resilience` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with no deps.

## Notes for the implementer

- Use the **zig skill** (atomics, the posix clock_gettime errno form for the injectable clock;
  `Math`-free — no `Date.now`/`Math.random`, use a seeded/injected RNG for jitter so tests are
  deterministic). Keep every timed path clock/delay-injected — NO real sleeps in tests.
- Keep breaker/retry/timeout usable independently AND composed via `run`. Generic over the operation.
- Be honest in docs about what `timeout` can actually interrupt.
- SPDX header + a `Provenance:` line (clean-room; design refs resilience4j Apache-2.0 / Polly BSD-3 /
  failsafe-go — behavior only, no code copied).
