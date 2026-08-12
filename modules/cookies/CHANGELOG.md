# cookies — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **BREAKING** — `set` no longer takes a caller-supplied buffer.
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
