# router — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **BEHAVIOURAL, not breaking** — the trailing-slash redirect no longer forces
  an early `ResponseWriter.end()`. The `Location` value is built in a stack
  buffer and the early `end()` existed only to put the head on the wire before
  that frame died; `http`'s `setHeader` copies those bytes now. **What changes
  for a consumer:** a 301/308 from `trailing_slash = .redirect` is completed by
  the serving loop instead of inside `tryRedirect`, so anything wrapped around
  the router can still touch the head after `dispatch` returns. Nothing inside
  the router could: the redirect is answered *outside* the middleware chain,
  so no `next.run` post-step was ever watching. The bytes on the wire are
  unchanged.
