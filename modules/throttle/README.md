# throttle

Global concurrency limiting / load shedding: a max-in-flight semaphore plus
a `router` middleware answering **503 + Retry-After**. `ratelimit` bounds
request *rate per key*; `abuseguard` bounds *connections per IP*; `throttle`
bounds **total concurrent in-flight requests** — when the server is
saturated it sheds load (a fast 503) instead of collapsing under an
unbounded queue. The "survive a spike" piece of the Web/API cluster.

Provenance: original work of the zig-libs authors (MIT); modeled after Go
`golang.org/x/sync/semaphore` (BSD-3-Clause, The Go Authors; slot semantics
only, no source copied), Netflix concurrency-limits (Apache-2.0; design
notes only) and the SEDA architecture (Welsh et al., SOSP '01; bounded-queue
load shedding) — see NOTICE. Clock-injection patterns follow the
`ratelimit` sibling module.

- **Status:** `gap`.
- **Model after:** Go `golang.org/x/sync/semaphore` (tryAcquire never
  blocks, failed attempts consume nothing, acquire/release pairing) + SEDA /
  Netflix concurrency-limits (static limit, bounded queue, fast rejection).
- **Platform:** posix (the default clock uses the posix `clock_gettime`
  errno form). **Role:** util. **Concurrency:** threadsafe — pure atomics
  (no mutex, no allocation, no hidden globals); all orderings are
  deliberately `seq_cst` so the waiter/releaser handoff audit stays simple.
- **Deps:** `router`, `http` (http is exercised by the tests and by the 503
  path's response types via `router.Ctx`).

## Layers

| Layer | What | Needs |
|---|---|---|
| `tryAcquire()` / `release()` | the bare counting semaphore | nothing — atomics only |
| `acquire()` | bounded wait (`max_wait_ms`), capped waiter set | an `Io` (futex) + injected `Clock` |
| `middleware()` | `router.Middleware`, 503 + `Retry-After` on shed | a `Router` |

## Usage

```zig
const throttle = @import("throttle");
const router = @import("router");

var th = throttle.Throttle.init(.{
    .max_in_flight = 256, // hard cap on concurrent requests
    // .max_wait_ms = 50,  // optional backpressure: wait briefly before shedding
    // .max_waiters = 64,  // cap the wait queue (default = max_in_flight)
    // .io = io,           // required when max_wait_ms > 0 (futex wait)
    .retry_after_ms = 1_000, // Retry-After hint on the 503
});
defer th.deinit();

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(th.middleware()); // before routes (chi rule); or on a group
try r.get("/api/thing", handler);
```

Admitted requests hold a slot for the rest of the chain and release it via
`defer` — also when the handler errors. Shed requests get **503 Service
Unavailable** with `Retry-After` (whole seconds, rounded up, ≥ 1) and a
short `text/plain` body; the rest of the chain never runs. Registered
router-level, 404/405 traffic is throttled too.

Observability: `inFlight()`, `waiting()`, `maxInFlight()`, `maxWaiters()` —
utilization is `inFlight() / maxInFlight()` (for the future `metrics`
module).

## Bounded wait (backpressure)

Default `max_wait_ms = 0` sheds immediately (pure load shedding). With
`max_wait_ms > 0`, an over-capacity request parks on a futex
(`Io.futexWaitTimeout` — Zig 0.16 moved futexes onto the Io vtable, hence
`Options.io`; pass the server's `std.Io.Threaded`) until a slot frees or the
deadline passes. The waiter set is itself capped (`max_waiters`, default =
`max_in_flight`): a full wait queue sheds immediately — an unbounded waiter
set is just a slower way to fall over, and is itself a memory/thread DoS
(SEDA's bounded-queue rule). A parked request keeps occupying its server
connection task; that *is* the backpressure, bounded by
`max_waiters × max_wait_ms`.

## Semantics notes (x/sync/semaphore parity)

- `tryAcquire` never blocks; a failed attempt consumes nothing; the counter
  can never exceed `max_in_flight` (CAS-enforced) nor go negative
  (`release` without a matching acquire asserts in Debug and saturates at 0
  in release builds).
- **Deviation from Go x/sync:** freed slots are not handed to waiters in
  FIFO order — `release` wakes all waiters and they re-contend with new
  arrivals (barging). Under sustained saturation a waiter can lose every
  race until its deadline and shed at `max_wait_ms`; acceptable because
  shedding under overload is the point, and it needs no per-waiter queue
  memory. Go's waiter list is also unbounded; ours is capped.
- Unlike `ratelimit`'s 429, no exact retry time is computable (it depends on
  in-flight handler durations) — `Retry-After` is the configured
  `retry_after_ms` hint.
- TODO: adaptive limit discovery (Netflix Gradient-style AIMD on observed
  latency) — the static `max_in_flight` is the required primary.

## Verification

`zig build test-throttle` — offline tests (acquire-to-cap/release semantics,
0-wait fast path, an 8-thread over-admission stress for both `tryAcquire`
and the bounded-wait path, deadline shed with the full wait honored,
release-inside-the-window handoff, waiter-cap immediate shed), middleware
goldens over the socket-free `http.Server.serveStream` (503 wire bytes +
`Retry-After` rounding, release-on-handler-error, throttled 404s,
bounded-wait 200-after-release and 503-after-deadline), and an in-process
integration run (`router` + `http.Server` + `http.Client` over loopback:
N slots occupied by live blocked requests → request N+1 sheds with 503 +
`Retry-After`, a released slot serves a fresh request, everything drains to
zero) that only skips when loopback binding is unavailable.
