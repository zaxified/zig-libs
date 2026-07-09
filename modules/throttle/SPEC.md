# throttle — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Layered: `tryAcquire()`/`release()` — the bare counting semaphore, lock-free (a CAS loop on one
atomic counter), zero allocation, no clock, no I/O; the counter can never exceed `max_in_flight` (the
CAS refuses) nor go negative (`release` asserts in Debug, saturates at 0 in release builds).
`acquire()` — the bounded-wait variant: waits up to `max_wait_ms` on `Io.futexWaitTimeout` instead of
shedding immediately, with the waiter set itself capped (`max_waiters`, default = `max_in_flight`).
`middleware()` — a `router.Middleware`: acquires on entry, releases via `defer` (also on handler
error); at capacity, **503** + `Retry-After` + short body, `next` never called. Deliberate deviation
from Go `x/sync/semaphore` parity: freed slots are not handed to waiters in FIFO order — `release`
wakes all waiters and they re-contend with new arrivals (barging); acceptable because shedding under
overload is the point, and it needs no per-waiter queue memory. `Retry-After` is a configured hint,
not computed from bucket math (unlike `ratelimit`'s 429). Concurrency: pure atomics, no mutex, no
hidden globals; all orderings are deliberately `seq_cst` so the waiter/releaser handoff (slot
counter, waiter counter, release generation) stays auditable under a single total order. Modeled
after Go `x/sync/semaphore` (slot semantics) + SEDA (bounded-queue load shedding) + Netflix
concurrency-limits (design notes) — see NOTICE.

## Threat model / out of scope
Not per-key: a single client can consume the whole in-flight budget same as a legitimate burst — pair
with `ratelimit` (per-key rate) or `abuseguard` (per-IP connections) for that. No adaptive limit
discovery: `max_in_flight` is a static number the operator must size correctly (a Netflix
Gradient-style AIMD variant is a documented TODO, not implemented). Bounded wait requires the caller
to pass an `Io` whenever `max_wait_ms > 0`; the default (immediate shed) touches no `Io` at all. A
parked request keeps occupying its server connection task — the backpressure is real capacity held,
bounded by `max_waiters × max_wait_ms`, not a queueing mechanism that frees resources while waiting.

## Verification
15 tests. Offline: acquire-to-cap/release semantics, 0-wait fast path, an 8-thread over-admission
stress for both `tryAcquire` and the bounded-wait path, deadline shed with the full wait honored,
release-inside-the-window handoff, waiter-cap immediate shed. Middleware goldens over the
socket-free `http.Server.serveStream` (503 wire bytes + `Retry-After` rounding, release-on-handler-
error, throttled 404s, bounded-wait 200-after-release and 503-after-deadline). In-process integration
(`router` + `http.Server` + `http.Client` over loopback): N slots occupied by live blocked requests →
request N+1 sheds with 503 + `Retry-After`, a released slot serves a fresh request, everything drains
to zero — skips only when loopback binding is unavailable. Run: `zig build test-throttle`.

## Backlog / deferred
Adaptive limit discovery (Netflix Gradient-style AIMD on observed latency) — documented TODO in
README, not implemented.

## Status
`gap · posix · util · threadsafe` + deps: `router`, `http` — canonical source is `pub const meta` in
src/root.zig.
