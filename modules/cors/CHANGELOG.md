# cors — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — New opt-in `Options.allow_unconditional_wildcard` (default `false`, unchanged
  behavior) — a named, deliberate deviation from spec-correct CORS for one migration shape: an
  existing API that has always answered every `OPTIONS` with 204 and put
  `Access-Control-Allow-Origin: *` on every response, and cannot change what's on the wire to adopt
  this module. Requires `allowed_origins = .any` (`Cors.init` rejects any other combination with the
  new `error.UnconditionalWildcardRequiresAnyOrigin`). `applyActual` is now `pub` — it was always
  called automatically before `next.run`, and is now also documented as the concrete fix for an
  outer response-rewriting middleware that calls `ResponseWriter.reset()` after `next.run` and needs
  to re-apply the CORS headers `reset()` wiped (see README's "Header timing vs.
  `ResponseWriter.reset()`" and SPEC.md for why the default ordering itself was evaluated and kept).
- **2026-08-13** — **BEHAVIOURAL, not breaking** — the preflight short-circuit no longer
  forces an early `ResponseWriter.end()`. Unlike the sites this mirrors
  (`ratelimit`, `throttle`), none of `handlePreflight`'s header values ever
  needed the early `end()` for their own sake: the reflected
  `Access-Control-Allow-Headers` is the *request's* own header slice, which
  outlives the response head regardless of copying, and every other value
  comes from the `Cors` instance, not a stack frame. **What changes for a
  consumer:** the 204 preflight head reaches the wire when the serving loop
  ends the response, not inside the middleware — so an *outer* middleware
  that works after `next.run` can still touch a preflight response. That is
  the point rather than a side effect: `sessions` saves its cookie there and
  `csrf` issues its token there; both writes were being swallowed as
  `error.HeadersSent` on every preflight. The status, headers and (absence
  of) body of the 204 are unchanged.
- **2026-07-19** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on rs/cors (Go), expressjs/cors,
  gin-contrib/cors (design reference, not a test anchor).
