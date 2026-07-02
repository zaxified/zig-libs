# SPEC — `throttle`

Global concurrency limiting / load-shedding as a `router` middleware. Web/API cluster (T5.5).
`extract · any · util · tsafe`. Model after: Netflix concurrency-limits / SEDA load-shedding +
Go `golang.org/x/sync/semaphore`. Deps: `router`, `http`. New `build.zig` entry
`.{ .name = "throttle", .deps = &.{ "router", "http" } }`.

## Why

`ratelimit` bounds request *rate per key*; `abuseguard` bounds *connections per IP*. `throttle`
bounds **total concurrent in-flight requests** to protect the backend from overload regardless of
who — when the server is saturated it **sheds load** (fast 503) instead of collapsing under an
unbounded queue. This is the "survive a spike" piece.

## Scope

1. **Concurrency limiter (semaphore):** a max-in-flight counter. A `router.Middleware` acquires a
   slot on entry; on success → `next`, release on exit (via `defer`, even on handler error). At
   capacity → **503 Service Unavailable** + `Retry-After` + short body, `next` NOT called.
2. **Optional bounded wait (backpressure):** `max_wait_ms` — instead of shedding immediately, wait
   up to that long for a slot to free (bounded queue), then 503 if still full. Default 0 = shed
   immediately. If you implement waiting, cap the number of waiters too (an unbounded waiter set is
   itself a memory DoS) → shed when the wait-queue is full.
3. **Observability:** `inFlight()` and (if waiting) `waiting()` getters; expose `max_in_flight` so
   `metrics` can chart utilization later.
4. **Thread-safe:** the counter is touched by every connection thread — atomics or a documented
   mutex. No hidden globals.
5. *(Optional, note as TODO if skipped):* an **adaptive** variant (AIMD on observed latency, Netflix
   Gradient-style) that discovers the limit instead of a static number. The static max-in-flight is
   the required primary.

## Public API sketch (final shape your call)

```zig
pub const Throttle = struct {
    pub fn init(gpa, Options) Throttle;   // Options: max_in_flight, max_wait_ms=0, max_waiters, clock, retry_after_ms
    pub fn deinit(*Throttle) void;
    pub fn middleware(self) router.Middleware;   // 503 + Retry-After on shed
    pub fn inFlight(self) usize;
    pub fn tryAcquire(self) bool;  pub fn release(self) void;   // the separable primitive
};
```

## Acceptance / verification

- **Offline unit tests:** `tryAcquire`/`release` semantics — acquire up to `max_in_flight` succeeds,
  the next fails; release frees a slot; counter never goes negative or exceeds the cap; bounded-wait
  behavior + waiter cap if implemented; a multi-thread stress (N threads hammering acquire/release,
  assert the cap is never exceeded and the count returns to 0).
- **In-process integration (must NOT skip normally):** router+`http.Server` with `max_in_flight = N`
  and a handler that blocks on a caller-controlled signal; open N concurrent client requests (they
  occupy all slots), then request N+1 → **503 with Retry-After** (not queued past the limit); release
  the signal, let one finish, a fresh request now succeeds. Use threads + the `http.Client`.
- `zig build test-throttle` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with `deps = &.{"router","http"}`.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (atomics, threads, condition/wait if you do bounded-wait; the
  repo uses `std.Io.Group` for spawning and a documented spinlock for mutual exclusion — mirror
  those). Reuse `router.Middleware {state,run}` (state = `*Throttle`) and its `Ctx`.
- Keep the semaphore primitive (`tryAcquire`/`release`) separable + unit-tested without HTTP.
- The 503 path mirrors ratelimit's 429 path (idempotent `ctx.res.end()` so stack-buffer header
  values reach the wire before the frame unwinds — see ratelimit for the pattern).
- SPDX header + a `Provenance:` line (clean-room; design refs Netflix concurrency-limits / x/sync).
