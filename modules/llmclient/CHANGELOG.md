# llmclient — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — `EventIterator.next` now surfaces a canceled SSE body read as
  `Error.Canceled`, closing the gap the previous entry (below) flagged and left
  open. `http.Client.Response` gained a public `readFailure()` accessor (an
  `http`-side API addition, approved separately — see its changelog) that asks
  the same question `readAllAlloc`'s internal `Conn.readFailure` already
  answered; `next`'s `error.ReadFailed` arm now calls it through the existing
  `mapHttpError`, the same widener `create`/`stream` use for the connect phase.
  The stale doc comment this module carried since the gap was first found (it
  said the cancel was unrecoverable "because `http.Client` does not expose the
  concrete reader") is now false and has been replaced with what actually
  happens.
  New loopback test (`EventIterator.next: a canceled body read surfaces
  error.Canceled, not error.HttpFailed`), proven by mutation: reverting
  `Response.readFailure()` to unconditionally return `error.ReadFailed` turned
  it red (`expected error.Canceled, found error.HttpFailed`); restoring it is
  green.
  `zig build test-llmclient` — 24/25 (1 unconditionally-skipped live test).
- **2026-08-22** — No code change; verified and pinned. `Client.create`'s body read
  goes through `http.Client.Response.readAllAlloc`, and `mapHttpError` already
  named `error.Canceled` explicitly for it — so once `http` stopped laundering a
  canceled body read into `error.ReadFailed` (its own root fix, `Client.zig:552`),
  a cancel during `create`'s body wait started surfacing as `Error.Canceled`
  instead of `Error.HttpFailed`, for free, with nothing to change here. New
  loopback test proves it rather than assuming it: reverting `http`'s fix alone
  (with this file untouched) turns it red (`expected error.Canceled, found
  error.HttpFailed`); restoring it is green.
  **`EventIterator.next`'s own cancel gap is unchanged and is NOT fixed by any of
  this.** Its doc comment (added when the gap was found) says a cancel there
  cannot be told apart from `error.HttpFailed`, because `it.res.reader()` is a
  bare `*std.Io.Reader` with no accessible concrete reader to recover the cause
  from — `http.Client.Response.conn` is `*Conn`, and `Conn` is a private type
  local to `http`'s `Client.zig`, so nothing outside that file can call
  `readFailure()` on it (confirmed: a private method reached only through a
  public field's private type does not compile from another file). That remains
  true after the root fix, which only reaches `readAllAlloc`'s own internal call
  to `res.conn.readFailure()` — a path this module has no access to. Fixing
  `EventIterator.next` for real needs `http.Client.Response` to expose a new
  public accessor (e.g. a `canceled()` query, or widening `reader()`'s contract)
  — a deliberate API-widening decision, flagged here rather than made silently.
  `zig build test-llmclient` — 23/24 (1 unconditionally-skipped live test).
- **2026-07-18** — Security audit: one finding fixed (part of the collection-wide audit;
  the root changelog records no further detail than this).
- **2026-07-09** — New module: Anthropic Messages API client (buffered + streaming SSE)
  over `http` — no third-party SDK.
