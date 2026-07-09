# resilience

Client-side fault tolerance for calling flaky upstreams: **circuit breaker +
retry-with-backoff + timeout + bulkhead**, generic over any fallible
operation. When the
API calls other services, a flaky/slow dependency shouldn't cascade into our
failure — this is the generic control logic that wraps such calls. std-only
and dependency-free, so it is reusable well beyond HTTP (the caller composes
it with `http.Client` or anything else that can fail).

Provenance: original work of the zig-libs authors (MIT); modeled after
resilience4j (Apache-2.0; breaker state machine, composition order, retry
`maxAttempts`/interval semantics, semaphore Bulkhead —
`maxConcurrentCalls`/`maxWaitDuration`), Polly (BSD-3-Clause; consecutive-failure
count breaker), and failsafe-go (Apache-2.0; delay/jitter policy shapes), plus
the AWS Architecture Blog "Exponential Backoff And Jitter" (Brooker, 2015; the
full/equal jitter taxonomy) — see NOTICE. Clock/delay-injection and spinlock
patterns follow the `ratelimit`/`throttle` siblings.

- **Status:** `gap`.
- **Model after:** resilience4j + Polly + failsafe-go (see above).
- **Platform:** posix (the default clock uses the posix `clock_gettime`
  errno form; the default delay uses posix `nanosleep`) — both injectable,
  everything else is pure logic. **Role:** util. **Concurrency:** threadsafe —
  `CircuitBreaker` is internally synchronized (documented spinlock, O(1)
  critical sections, no allocation); `Bulkhead` is lock-free (a CAS loop on
  one atomic counter); `Retry`/`Deadline` are immutable values.
- **Deps:** none (std only).

## Layers

| Layer | What | Needs |
|---|---|---|
| `CircuitBreaker` | `closed → open → half_open`, fast-fail, probes | an injected `Clock` |
| `Bulkhead` | ≤ `max_concurrent` calls in flight; full = `error.BulkheadFull` (or a bounded wait) | injected `Clock`/`Delay` only for the bounded wait |
| `Retry` | pure backoff math: `nextDelay(attempt, random)` | a seeded `std.Random` for jitter |
| `Deadline` | cooperative time budget (`expired()`/`remainingMs()`) | an injected `Clock` |
| `run(op, policy)` | one-call composition: breaker → retry → timeout | all of the above, injected |

## Usage

```zig
const resilience = @import("resilience");

// An operation = any value with a call() method returning an error union.
const Fetch = struct {
    client: *http.Client,
    url: []const u8,
    pub fn call(self: *Fetch) !u16 {
        var res = try self.client.request(.get, self.url, .{});
        defer res.deinit();
        if (res.status >= 500) return error.UpstreamDown;
        return res.status;
    }
};

var breaker: resilience.CircuitBreaker = .init(.{
    .failure_threshold = 5, // consecutive failures that trip it
    .cooldown_ms = 30_000, // open -> half_open probe delay
    .half_open_probes = 1, // probes admitted; all must succeed to close
});
var prng = std.Random.DefaultPrng.init(seed);

var op: Fetch = .{ .client = &client, .url = "https://upstream/api" };
const status = try resilience.run(&op, .{
    .breaker = &breaker, // one breaker per upstream, shared across threads
    .retry = .{ .max_attempts = 3, .base_delay_ms = 100, .jitter = .full },
    .timeout_ms = 2_000, // per-attempt budget
    .random = prng.random(), // entropy for the jitter
});
```

A bare "fn ptr + ctx" pair works via the adapter:
`resilience.run(resilience.operation(&state, doFetch), policy)`.

## Composition ordering (`run`)

`breaker → retry → timeout`, applied **per attempt**: the breaker gates
*every* attempt (an open breaker fast-fails the whole run with
`error.CircuitOpen` before any delay or call); each admitted attempt is
timeout-classified and its outcome recorded to the breaker; failures are
retried while attempts remain and `retryable(err)` agrees, sleeping
`nextDelay()` in between. Observably this is resilience4j's default
decoration order `Retry(CircuitBreaker(TimeLimiter(call)))`. Deliberate
deviation: a breaker denial is never retried within one `run` — fast-fail is
the point; call `run` again later to probe after the cooldown.

## Semantics notes

- **Breaker trip condition:** count-based — `failure_threshold`
  **consecutive** failures (Polly's classic breaker; any success resets the
  streak). The alternative — resilience4j's failure-*rate* over a sliding
  call window, which tolerates interleaved successes — is noted as a
  possible future extension, not built.
- **Breaker contract:** ask `allow()` before each call; when admitted,
  report exactly one `onSuccess()`/`onFailure()`. Results reported while
  `open` (stragglers from before the trip) are ignored. The `open →
  half_open` transition is lazy — `state()` reports `.open` after the
  cooldown until an `allow()` asks to probe.
- **Jitter:** **full jitter** is the recommended flavor (uniform `[0, d]`,
  best contention spread per the AWS analysis); `equal` (`[d/2, d]`) and
  `none` are available. The *default* is `none` only because randomness must
  be injected — Zig 0.16 std has no ambient entropy and this module has no
  hidden globals; pass a seeded `std.Random` and pick `.full` in production.
  With a jittered flavor and no rng, delays deterministically fall back to
  the un-jittered schedule.
- **Delay injection:** waits between attempts go through `Policy.delay` —
  `.blocking` (posix `nanosleep`, the production default) or `.none`, or any
  injected fn; tests inject a recording no-op, so no test ever sleeps.
- **Retryable predicate:** `Retry.retryable: fn (anyerror) bool` (default:
  everything, including `error.Timeout`). Zig errors are globally unique, so
  an `anyerror` predicate can match any operation's error set.
- **Retried attempts may repeat side effects** — only wrap idempotent work
  (the standard retry caveat).
- **Bulkhead** (resilience4j's semaphore bulkhead, behavior only): at most
  `max_concurrent` calls in flight; a full bulkhead rejects with
  `error.BulkheadFull` immediately (`max_wait_ns = 0`, the default) or
  after a bounded wait. Pair every successful `tryAcquire()`/`acquire()`
  with exactly one `release()`, or use `Bulkhead.run(op)` which releases on
  the error path too. The bounded wait is a **poll** over the injected
  `Clock`/`Delay` (granularity `poll_ns`) — this module is std-only with no
  `Io`, so there is no futex to park on; the `throttle` sibling has the
  futex-parked variant. The breaker reacts to *failures*, the bulkhead to
  *saturation* — compose both when calling a fleet (see the `upstream`
  module).

## Timeout — what it can and cannot do

`Policy.timeout_ms` bounds each attempt **observationally and
cooperatively** — it does NOT preempt the operation:

- *Observational:* the attempt is stopwatched with the injected clock; a
  result arriving after the budget — **even a success** — is discarded and
  classified `error.Timeout`, feeding the breaker and the retry decision
  (the spirit of resilience4j's TimeLimiter).
- *Cooperative:* an operation declaring
  `pub fn setDeadline(self, d: resilience.Deadline) void` receives each
  attempt's deadline before the call — map `remainingMs()` onto your own I/O
  timeouts, or poll `expired()`.
- *It cannot interrupt anything.* A `call()` stuck in a blocking syscall
  blocks `run` past the timeout — the same caveat as this repo's http
  connect-timeout. No thread/signal machinery is hiding here; for hard
  cancellation, run the work somewhere preemptible and make `call()` await
  it with its own timeout.

## Verification

`zig build test-resilience` — fully deterministic offline tests (injected
clock + injected recording delay + fail-scripted synthetic operations; no
real sleeps anywhere): breaker trips after N consecutive failures / success
resets the streak / fast-fail while open / half-open after cooldown with a
fresh-cooldown re-open / probe budget honored; exponential backoff
progression + cap + overflow safety; full/equal jitter bounds + same-seed
reproducibility; retry runs exactly `max_attempts` with the exact delay
sequence; non-retryable errors return immediately; timeout fires on slow
attempts (including slow *successes*) and is retryable by default; the
cooperative deadline reaches the operation; composition (M<threshold
failures then success never trips; persistent failure trips mid-run, then
fast-fails without invoking the operation; recovery after cooldown); plus an
8-thread breaker check (no lost failure counts, exact half-open probe
admission). Bulkhead: N acquires then immediate N+1 rejection; `run` returns
the slot on success and on the error path and fast-fails a full bulkhead
without invoking the op; the bounded wait succeeds when a slot frees within
the (virtual-time) budget and times out poll-by-poll when none does; a real
cross-thread handover; and an 8-thread `run()` hammer asserting in-flight
never exceeds `max_concurrent` and no slot leaks.
