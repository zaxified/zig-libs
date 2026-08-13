# throttle — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
