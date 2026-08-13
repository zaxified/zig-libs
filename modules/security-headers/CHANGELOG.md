# security-headers — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-12** — **BREAKING** `SecurityHeaders.init` now returns `InitError!SecurityHeaders`
  instead of `SecurityHeaders`. Every call site needs a `try` (or equivalent
  error handling) added; there were no in-repo consumers outside this
  module's own tests, so nothing else in the collection is affected. It
  exists because `http`'s response writer now copies header name/value bytes
  into a fixed per-response budget (`f5007ef`, see `http`'s own changelog
  entry for `error.HeaderBytesExhausted`) — a budget that did not exist
  before that fix. `SecurityHeaders.apply`/`.middleware` already propagated
  `error.HeaderBytesExhausted` (part of `http.Server.ResponseWriter
  .SetHeaderError`) uncaught, which is the right instinct (silently dropping
  a security header via `catch {}` would leave a response looking normal
  while unprotected — strictly worse than failing), but it left a real
  footgun: since this middleware is meant to run first in the chain, whether
  it fails depends only on its *own* configured header set (a
  `content_security_policy` large enough, especially paired with a
  comparably large `content_security_policy_report_only` while trialing a
  stricter policy — this module's own documented use case), never on what
  other middleware adds — yet that failure only ever surfaced at request
  time, as `http.Server`'s automatic 500 with *none* of this module's
  headers on it either (its own "Known limitation"). `init` now runs the
  exact same byte-accounting `apply` would and rejects an over-budget
  configuration with `InitError.HeaderBudgetExceeded` up front, in every
  build mode — a misconfiguration is refused once, at startup, not
  discovered by every caller as a mysterious 500 in production. The budget
  itself is read off `http.Server.ResponseWriter`'s actual field via
  `@FieldType`, not duplicated as a literal, so it cannot drift out of sync
  with `http`'s real value.
