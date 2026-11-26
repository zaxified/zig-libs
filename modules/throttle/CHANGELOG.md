# throttle — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-26** — Fix: `Throttle.release` and `Partitioned.release` without a matching acquire now really saturate at 0 in ReleaseFast/ReleaseSmall, as documented. The guard sat behind `std.debug.assert(cur > 0)`, which those modes compile to `unreachable`, so the optimizer deleted it and the counter wrapped to 4294967295 (every later acquire then refused). Debug and ReleaseSafe still trap on the caller bug. Plus killing tests from the 2026-11-25 whole-module mutation run.
- **2026-11-21** — ADDED opt-in adaptive limit discovery: `Options.adaptive` (`Adaptive`: `gradient2` / `aimd`, Netflix concurrency-limits' constants), `Throttle.limit()`, `acquirePermit` / `releasePermit` with `Permit` and `Outcome`; the middleware samples served requests when it is set. `max_in_flight` becomes the ceiling. Default (null) behaviour and all existing signatures are unchanged.
- **2026-11-16** — New `Partitioned` limiter (Netflix `PartitionedLimiter` shape): per-partition guaranteed percentage shares of `max_in_flight` plus borrowing of unused capacity (`tryAcquire(p)` / `release(p)` / `inFlight` / `inFlightIn` / `guaranteed` / `middleware()` with an optional `classify` callback). `init` returns `PartitionError` (`ZeroLimit`, `NoPartitions`, `TooManyPartitions`, `SharesExceed100`) instead of panicking. Additive; `Throttle` is unchanged. Note the borrowed total may exceed `max_in_flight` by up to the sum of guarantees while guaranteed requests land on a fully borrowed budget.
- **2026-11-08** — **NO CONSUMER-VISIBLE CHANGE:** the private monotonic OS read behind `Clock.monotonic` (duplicate-code pass) is replaced by the `clock` module: `Clock` is now `clock.Clock` (same fields, `.monotonic`, `now()`; additionally `.coarse` and `since()`). A failed read still gives 0; a negative timespec field now maps to 0 instead of tripping `@intCast`. New dependency: `clock`.
- **2026-10-04** — Tests: first mutation run (27 mutants, 25 killed, 2 equivalent); 5 tests added
  (fake-clock deadline arithmetic and `>=` boundary, release in the pre-wait window, canceled
  wait, `Retry-After` rounding and floor, monotonic clock resolution). No source change.
- **2026-08-13** — **BEHAVIOURAL, not breaking** — the 503 shed path no longer forces an early
  `ResponseWriter.end()`. The `Retry-After` value is formatted on `shed`'s
  stack frame and the early `end()` existed only to beat that frame's death;
  `http`'s `setHeader` copies those bytes now. **What changes for a
  consumer:** the 503 head reaches the wire when the serving loop ends the
  response, not inside the middleware — so an *outer* middleware that works
  after `next.run` can still touch it. That is the point rather than a side
  effect: `sessions` saves its cookie there and `csrf` issues its token
  there, and on a 503 both writes were being swallowed as
  `error.HeadersSent`. The status, headers and body of the 503 are
  unchanged.
- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on Go
  `golang.org/x/sync/semaphore` (slot semantics) + SEDA / Netflix concurrency-limits
  (bounded queue, shed) (design reference, not a test anchor).
