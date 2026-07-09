# resilience — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Four independent layers + one composition:** `CircuitBreaker` (`closed → open → half_open`,
  trips on `failure_threshold` **consecutive** failures — Polly's classic breaker, not
  resilience4j's failure-rate window), `Bulkhead` (semaphore-style, ≤ `max_concurrent` in flight,
  `error.BulkheadFull` or a bounded poll-wait), `Retry` (pure `nextDelay(attempt, random)` math —
  exponential + cap + jitter, no I/O), `Deadline` (cooperative `expired()`/`remainingMs()`).
  `run(op, policy)` composes `breaker → retry → timeout` per attempt. Clean-room; design references
  only (behavior, no source consulted or copied — see NOTICE): resilience4j (breaker state machine,
  composition order, retry/Bulkhead semantics), Polly (consecutive-failure breaker), failsafe-go
  (delay/jitter shapes), AWS's "Exponential Backoff And Jitter" (Brooker 2015; full/equal jitter).
- **Allocation:** none — all four types are value types with fixed fields; no allocator anywhere in
  the module.
- **Concurrency:** `CircuitBreaker` is internally synchronized (documented spinlock, O(1) critical
  sections); `Bulkhead` is lock-free (CAS loop on one atomic counter); `Retry`/`Deadline` are
  immutable values, safe to share by copy.
- **Clock/delay/random seams:** every timed path takes an injected `Clock` (posix `clock_gettime`
  default, swappable) and `Delay` (posix `nanosleep` default, or `.none`, or a recording no-op for
  tests); jitter takes a caller-seeded `std.Random` (Zig 0.16 std has no ambient entropy — no hidden
  globals). Tests never sleep for real.
- **Error policy:** typed errors (`error.CircuitOpen`, `error.BulkheadFull`, `error.Timeout`), never
  panics; a breaker denial is never retried within one `run` — fast-fail is the point.
- **Composition ordering deviation from resilience4j:** the breaker gates *every* attempt inside one
  `run` (denial ends the run immediately, no retry-around-a-denial), whereas resilience4j's default
  decorator nesting would let retry re-ask the breaker per attempt too — short-circuited here
  deliberately.

## Threat model / out of scope

Not a security primitive; it is control logic for availability, not confidentiality/integrity. It
does **not** provide cancellation: `Policy.timeout_ms` is observational/cooperative only — a
`call()` blocked in a syscall is not preempted, the same caveat as this repo's own `http` client
connect-timeout; hard cancellation needs preemptible work plus its own timeout. It does not
deduplicate or make retried side effects idempotent — retried attempts may repeat effects; only
wrap idempotent operations. The breaker is count-based (consecutive failures), not rate-based over a
sliding window — bursty-but-rare failures behind a high-volume success stream will not trip it. No
global/shared state: multiple upstreams need their own `CircuitBreaker`/`Bulkhead` instances (see
`upstream`, which does exactly this per-member).

## Verification

26 tests, fully deterministic and offline (injected clock + injected recording delay + fail-scripted
synthetic operations, no real sleeps): breaker trips after N consecutive failures, success resets
the streak, fast-fail while open, half-open after cooldown with fresh-cooldown re-open, probe budget
honored; exponential backoff progression + cap + overflow safety; full/equal jitter bounds and
same-seed reproducibility; retry runs exactly `max_attempts` with the exact delay sequence;
non-retryable errors return immediately; timeout fires on slow attempts including slow *successes*
and is retryable by default; cooperative deadline reaches the operation; composition cases (recovers
under threshold, trips mid-run then fast-fails without invoking the op, recovers after cooldown); an
8-thread breaker check (no lost failure counts, exact half-open probe admission). Bulkhead: N
acquires then immediate N+1 rejection; `run` returns the slot on both success and error paths and
fast-fails a full bulkhead without invoking the op; bounded wait succeeds within a virtual-time
budget and times out poll-by-poll otherwise; a real cross-thread handover; an 8-thread `run()`
hammer asserting in-flight never exceeds `max_concurrent` and no slot leaks. Run:
`zig build test-resilience`.

## Backlog / deferred

- **Rate-based (sliding-window) breaker variant** — v1 trips on consecutive failures only; a
  failure-rate-over-a-window mode (resilience4j-style) is noted in the module's own threat model as
  a possible future extension, not built.

## Status

`gap · posix (clock/delay defaults; injectable) · util · threadsafe` + deps: none (std only) —
canonical source is `pub const meta` in src/root.zig.
