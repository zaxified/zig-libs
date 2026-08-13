# requestid — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on nginx
  `$request_id`, Envoy `x-request-id`, chi `middleware.RequestID` (design reference, not
  a test anchor).
- **2026-07-08** — New module: Request/correlation-ID middleware — adopt incoming
  `X-Request-Id` or generate, echo on the response, expose via `current()` (composes
  with auth).
