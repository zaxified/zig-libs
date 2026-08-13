# ratelimit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only, no behaviour change: two regression tests close a coverage gap the
  2026-08-13 `end()` entry below left open. (1) `"middleware: an OUTER middleware writing after
  next.run still lands its header"` pins the property that entry's prose claims — reverting to the
  pre-fix early `end()` now turns this test (and only this test) red, 31/32; `throttle` and `cors`
  got the identical test when they copied the same fix, this module (where the fix originated,
  `6ba5d7d`) had neither it nor a dead-frame test until now. (2) `"middleware: 429 Retry-After/
  RateLimit-* values survive the caller's dead frame"` pins that `retry_buf`/`limit_buf`/`reset_buf`
  — formatted on `middlewareRun`'s stack frame — depend on `http`'s `ResponseWriter.setHeader`
  copying their bytes rather than borrowing the caller's; verified by fault-injecting `http`'s
  `dupe` to return the input slice unchanged, which turns this test red alongside 7 sibling
  dead-frame tests across the collection (`router`, `tracecontext`, `sessions`, `csrf`, `cookies`,
  `throttle`, `http`'s own). Both mutations reverted, tree confirmed byte-identical (`cmp`).
- **2026-08-13** — **BEHAVIOURAL, not breaking** — the 429 deny path no longer forces an early
  `ResponseWriter.end()`. The `Retry-After` and `RateLimit-*` values are
  formatted on the middleware's stack frame and the early `end()` existed only
  to beat that frame's death; `http`'s `setHeader` copies those bytes now.
  **What changes for a consumer:** the 429 head reaches the wire when the
  serving loop ends the response, not inside the middleware — so an *outer*
  middleware that works after `next.run` can still touch it. That is the point
  rather than a side effect: `sessions` saves its cookie there and `csrf`
  issues its token there, and on a 429 both writes were being swallowed as
  `error.HeadersSent`. The status, headers and body of the 429 are unchanged.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `golang.org/x/time/rate` (token bucket) + nginx `limit_req` (keyed store) (design
  reference, not a test anchor).
