# llmclient — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-17** — **NO CONSUMER-VISIBLE CHANGE:** tests only. The `create` and `EventIterator.next` body-read cancel tests canceled after a fixed
  sleep. Both now cancel once the client is inside the socket read under test (`ReadCueIo`, a
  `std.Io` double that counts `netRead` entries), and the peer is released from `accept`
  before `join`. On a loaded full gate the sleep could land the cancel before the connect. The
  peer thread then waited in `accept` forever, the shape that hung `http` in full-gate attempt 3.

- **2026-09-10** — **BEHAVIOURAL, not breaking — the remaining 16 A1 findings (F6-F8,
  F11-F14, F16-F24), all closed.** A stream event whose `event:` name disagrees with its
  JSON `"type"` is now `error.MalformedResponse` (F6) instead of silently dispatching on
  the JSON alone. `sse_parse` now requires `retry:` to be all-ASCII-digits per WHATWG
  (a leading `+`/`-` used to slip through `std.fmt.parseInt`), strips exactly the one
  line terminator instead of trimming every trailing `\r`/`\n` (which used to eat a
  legitimate trailing `\r` that belonged to a field value), and skips a leading UTF-8 BOM
  on the stream's first line (F24). `messagesUrl` (an oversized `base_url`) now returns
  a new error `error.BaseUrlTooLong` instead of reusing `error.MalformedResponse` — a
  caller configuration mistake no longer looks like a wire failure (F23). Docs corrected,
  not code: `SPEC.md`/`README.md` no longer claim `http.Client` opens "a fresh connection
  per request (`Connection: close`)" — that was never true (`http.Client.Options.pool`
  defaults to enabled and this module has no per-request lever over a caller-owned,
  shared transport) (F22); `SPEC.md` now documents the ~4088-byte SSE line ceiling that
  `http`'s own internal buffer imposes, previously unstated anywhere in this module (F13).
  The other twelve findings (F7, F8, F11, F12, F14, F16-F21) needed no code change — each
  guard already existed (several as a side effect of the entry below) but had no test that
  would fail if the guard were deleted or weakened; 19 new regression tests close that gap,
  each verified against the audit's own mutation. `scripts/modtest llmclient`: 32 → 51 pass
  (+1 unconditionally-skipped live test, unchanged).

- **2026-09-06** — **The key stays at `base_url`, the wire's numbers are checked, and
  what the peer sends is bounded in the quantity that costs.** The five HIGH findings
  of the A1 audit (2026-09-06), plus F9/F10/F15.
  - **BEHAVIOURAL, not breaking — redirects are never followed (F1).** A 3xx from
    `base_url` is `error.UnexpectedStatus` with its body in `lastErrorBody`. Before,
    one `Location:` sent `x-api-key` and the whole prompt to the host the peer named,
    and `create` returned `OK`. The API never answers 3xx; a proxy that does was
    getting the key forwarded through it.
  - **`error.MalformedResponse` instead of a panic (F2):** a content-block `index`
    above `u32`, or a `usage` count that is negative, ≥ 2^64 or non-finite, was
    `@intCast`/`@intFromFloat` on the raw value — exit 134 in Debug/ReleaseSafe, a
    wrong `index`/billing number in ReleaseFast.
  - **New knobs, new error `ResponseTooLarge`:** `max_parsed_bytes` [64 MiB] bounds
    the memory a response's or an event's parse may allocate (F5: 7.8 MB under the
    10 MiB wire cap parsed into 310 MiB and returned `OK`); `max_event_bytes` [1 MiB]
    bounds one SSE dispatch group (F3: 10 MB of legal 4 KiB lines in one group →
    2.4 GB live, kept after the error — the buffers are released now, F15);
    `read_timeout_ms` [60 s] bounds the body read on `create` and each `next()`
    (F4: a one-byte-a-second peer held `create` 30 s against a 2 s total timeout).
    `http`'s `BodyTooLarge` also maps to `ResponseTooLarge` now rather than
    `HttpFailed`. `EventIterator` gained an `io` field (copied from the transport).
  - `lastErrorBody` after `stream` keeps the first 512 bytes of a longer error body
    instead of returning null (F10).
  - The three fuzz harnesses use `smith.slice` and carry seeds (F9).

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
