# cookies — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — `zig build check-fuzz` coverage: a `testing.fuzz` harness on `parse`
  (the `Cookie`-header decode entry point), generating both arbitrary bytes and
  cookie-shaped input assembled from the grammar's own alphabet (`=`, `;`,
  `"`), so the DQUOTE-toggle branch is actually exercised rather than only
  reachable by chance. `parse`/`Iterator.next` are allocation-free, so this is
  a never-panics harness, not a leak oracle. No panic, hang or leak found.
- **2026-08-13** — **BREAKING** `SetError` gains `error.HeaderBytesExhausted`, by inheritance
  from `http.Server.ResponseWriter.SetHeaderError`. An exhaustive `switch` over
  `cookies.SetError` stops compiling until it handles the new case; a `catch
  |e| switch (e) { … else => }` is unaffected. This shipped in the same release
  as the `set` signature change below and only `http`'s changelog mentioned it,
  so it is recorded here as the second, independent source-level break it is.
- **2026-08-13** — `max_set_cookie_bytes` is now pinned by value AND to `http`'s copy store,
  instead of being asserted by comment. The doc-comment grounded 4096 in two
  authorities — RFC 6265 §6.1's "at least 4096 bytes per cookie" and `http`'s
  `header_copy_bytes` — but `header_copy_bytes` was a private `const` this
  module could not import, so the "same size" property was a duplicated
  literal, and the constant was unpinned upward: measured, 4096 → **8192 left
  38/38 green in Debug and ReleaseSafe**. `header_copy_bytes` is public now and
  imported here, with a comptime floor (the RFC minimum) and ceiling (the
  writer's store) so the two cannot drift apart in either direction, plus a
  test that states the value. Note the RFC basis is exact but the fit is not:
  a maximal conforming cookie is 4096 bytes of `Set-Cookie` VALUE and the
  header name costs 10 more, so such a cookie does not fit a 4096-byte copy
  store — which is what the "refused, not truncated" test observes. Recorded
  rather than silently rounded up; growing it is a per-response memory
  decision. Purely an addition.
- **2026-08-13** — **BREAKING** — `set` no longer takes a caller-supplied buffer.
  **What a consumer must change:** drop the third argument, and the local it
  came from.

  ```zig
  // before
  var buf: [256]u8 = undefined;
  try cookies.set(res, sc, &buf);
  // after
  try cookies.set(res, sc);
  ```

  The parameter existed for exactly one reason: the response head is not
  serialized until the serving loop calls `end()`, *after* the handler returns,
  and `http`'s response writer used to store the caller's slices — so a value
  formatted on the handler's frame was read once that frame was gone, and the
  buffer had to be pushed up into a longer-lived one. `http` copies header
  bytes into the response's own storage at `setHeader` time now, so the
  parameter bought nothing; `set` formats into a buffer of its own.

  That buffer is `max_set_cookie_bytes` (new, public) = 4096 bytes, from RFC
  6265 §6.1's "at least 4096 bytes per cookie, as measured by the sum of the
  length of the cookie's name, value, and attributes" — the largest cookie a
  conforming user agent must keep, so no cookie that would have worked is
  refused here. It is also the size of `http`'s entire per-response header copy
  store, which makes it a bound rather than a second budget to get wrong: any
  value this buffer would reject, `setHeader` rejects first (the header name
  costs bytes too). A cookie past either limit fails — `error.BufferTooSmall`
  or `error.HeaderBytesExhausted` — and is **never truncated**, because a
  truncated `Set-Cookie` still parses and would be stored silently corrupted.

  The module's own test used to thread a buffer through `req.context` to fake a
  frame that outlives the handler. It is replaced by the anchor that shape was
  standing in for: a `noinline` helper sets the cookie from its own frame,
  returns, and a second `noinline` deliberately clobbers that frame before
  `end()` runs. That test fails if the copy in `http` is ever removed — the old
  suite did not.
- **2026-07-19** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this). Modeled on RFC 6265 §4.2/§5.4
  behavior (no single reference implementation named; anchored to the RFC text
  directly).
