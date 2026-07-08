# SPEC — `throttle`

**Purpose** — Global concurrency limiting / load shedding: a max-in-flight semaphore plus a
`router` middleware answering **503 + Retry-After**. `ratelimit` bounds request *rate per key*;
`abuseguard` bounds *connections per IP*; `throttle` bounds **total concurrent in-flight
requests** — when the server is saturated it sheds load (a fast 503) instead of collapsing under
an unbounded queue. The "survive a spike" piece of the Web/API cluster.

**Model after / Seed** — Clean-room, no seed project and no third-party code. Model after Go
`golang.org/x/sync/semaphore` (`tryAcquire` never blocks, failed attempts consume nothing,
acquire/release pairing; slot semantics only) + SEDA (Welsh et al., SOSP '01; bounded-queue load
shedding) + Netflix concurrency-limits (design notes only). Design refs in `NOTICE`.

**Design & invariants**
- **Layered:** `tryAcquire()`/`release()` — the bare counting semaphore, lock-free (a CAS loop on
  one atomic counter), zero allocation, no clock, no I/O; the counter can never exceed
  `max_in_flight` (the CAS refuses) nor go negative (`release` asserts in Debug, saturates at 0 in
  release builds). `acquire()` — the bounded-wait variant: waits up to `max_wait_ms` on
  `Io.futexWaitTimeout` (Zig 0.16 moved futexes onto the `Io` vtable, hence `Options.io`) instead
  of shedding immediately, with the waiter set itself capped (`max_waiters`, default =
  `max_in_flight`) — an unbounded wait queue is just a slower way to fall over (SEDA's
  bounded-queue rule). `middleware()` — a `router.Middleware`: acquires on entry, releases via
  `defer` (also on handler error); at capacity, **503** + `Retry-After` + short body, `next` never
  called.
- **x/sync/semaphore parity, with one deliberate deviation:** freed slots are not handed to
  waiters in FIFO order — `release` wakes all waiters and they re-contend with new arrivals
  (barging). Under sustained saturation a waiter can lose every race until its deadline and shed at
  `max_wait_ms`; acceptable because shedding under overload is the point, and it needs no
  per-waiter queue memory (Go's waiter list is also unbounded; this one is capped).
- **No exact retry time:** unlike `ratelimit`'s 429 (computable from bucket math), `Retry-After`
  here is the configured `retry_after_ms` hint — in-flight handler duration is not predictable.
- **Concurrency:** pure atomics, no mutex, no hidden globals; all orderings are deliberately
  `seq_cst` so the waiter/releaser handoff (three atomic locations: slot counter, waiter counter,
  release generation) stays auditable under a single total order.

**Threat model / out of scope** — Not per-key: a single client can consume the whole in-flight
budget the same as a legitimate burst — pair with `ratelimit` (per-key rate) or `abuseguard`
(per-IP connections) for that. No adaptive limit discovery: `max_in_flight` is a static number the
operator must size correctly (a Netflix Gradient-style AIMD variant is an explicit TODO, not
implemented). Bounded wait requires the caller to pass an `Io` (the server's `std.Io.Threaded`)
whenever `max_wait_ms > 0`; the default (immediate shed) touches no `Io` at all. A parked request
keeps occupying its server connection task — the backpressure is real capacity held, bounded by
`max_waiters × max_wait_ms`, not a queueing mechanism that frees resources while waiting.

**Verification** — 15 tests (`zig build test-throttle`). Offline: acquire-to-cap/release
semantics, 0-wait fast path, an 8-thread over-admission stress for both `tryAcquire` and the
bounded-wait path, deadline shed with the full wait honored, release-inside-the-window handoff,
waiter-cap immediate shed. Middleware goldens over the socket-free `http.Server.serveStream` (503
wire bytes + `Retry-After` rounding, release-on-handler-error, throttled 404s, bounded-wait
200-after-release and 503-after-deadline). In-process integration (`router` + `http.Server` +
`http.Client` over loopback): N slots occupied by live blocked requests → request N+1 sheds with
503 + `Retry-After`, a released slot serves a fresh request, everything drains to zero — skips only
when loopback binding is unavailable.

**Status** — `gap · posix · util · threadsafe` · deps: `router`, `http`.
