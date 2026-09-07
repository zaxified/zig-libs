# cors — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: `fuzzGates` handed all three pure gates the
  empty string on every run.** It opened with `smith.bytes(&buf)` and then drew
  the length with `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the eight
  it reads as a little-endian `u64` and returned the range MINIMUM. `len` was 0
  for every input the ordinary test lane can carry. That is the *worst*
  possible single input here: `requestedHeadersAllowed("")` returns `true`
  through the "no header named" path without ever reaching the comma split, so
  the refusal branch this gate exists for had never executed. The harness now
  draws with one `smith.slice(&buf)` over a 14-seed corpus of real `Origin`,
  `Access-Control-Request-Method` and `Access-Control-Request-Headers` values.
  Measured 2026-09-07: **0 of 14 seeds arrived non-empty before, 14 of 14
  after; 0 origins granted before, 2 after; 0 method tokens allowed, now 3; 0
  header lists refused, now 10.** ⭐ An `accepted > 0` guard would have read
  green throughout — under the DEFAULT `.reflect` policy
  `requestedHeadersAllowed` answers `true` for any input at all — so the new
  corpus guard pins origins granted, methods allowed and header lists refused,
  none of which the empty input can produce.

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
