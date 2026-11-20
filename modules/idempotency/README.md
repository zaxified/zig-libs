# idempotency

Idempotency-Key deduplication of unsafe request retries (Stripe-style) as a
`router` middleware over a `ramcache`-backed store.

A client that retries an unsafe request — a dropped connection, a timeout, a
flaky mobile link — risks doing the side effect twice (charging a card twice,
creating two orders). The fix: the client sends a stable
`Idempotency-Key: <key>` header and *the same key on every retry*. The **first**
request with that key runs the handler and the server remembers its response; a
**replay** of the same key within a TTL returns the remembered response
**without re-running the handler**, so the retry is a safe no-op that still
hands the client the original result.

A request without the header runs normally, without deduplication. With
`Options.require_key = true` a guarded method (`methods`, POST/PUT/PATCH by
default) without it answers **400** `Idempotency-Key required` and the handler
does not run; a present but empty, oversized or repeated key is **400**
`Invalid Idempotency-Key` either way.

```zig
var cache = ramcache.Cache.init(gpa, .{ .max_bytes = 8 << 20, .max_entries = 4096 });
defer cache.deinit();
var store = idempotency.Store{ .cache = &cache };
var idem = idempotency.Idempotency{ .store = &store };
try r.use(idem.middleware()); // before the routes it guards

fn createOrder(ctx: *router.Ctx) anyerror!void {
    const app: *App = @ptrCast(@alignCast(ctx.state.?));
    const body = try renderOrder(...);        // the side-effecting work
    try app.store.respond(ctx, 201, "application/json", body);
}
```

## The contract (read this)

The middleware records the guarded handler's answer **transparently**
(`Options.capture`, default `.all`): a handler that just
writes `ctx.res` is deduplicated like one that calls `store.respond` — the
node-idempotency / IdempotentAPI / Stripe behaviour. `store.respond` stays the
cooperative path and wins when a handler uses it. Details and limits are under
"Transparent capture" below.

- The **middleware** owns the *replay* half. On a guarded request with a valid
  key it looks the (scoped) key up in the `Store`; on a hit it writes the
  cached status + `Content-Type` + the headers the handler (or a middleware
  inside the guard) set — `Location`, `ETag`, … — + body, stamps
  `Idempotent-Replayed: true`,
  and short-circuits the chain — **the handler genuinely never runs** (the
  strongest guarantee, and what the hit-counter test asserts). On a miss it
  binds the scoped key to the request (`store.current(ctx.req)`) and runs the
  chain.
- ⚠ **Set `Options.principal`** unless there is exactly one caller: without
  it every caller shares one key namespace, and a second client that picks
  the same key for the same endpoint and body is handed the FIRST client's
  recorded response (A1 F1). The principal (e.g. the `Authorization` value)
  enters the cache key as a SHA-256 tag, never raw.
- The *record* half is transparent capture (below) or, explicitly,
  `store.respond(ctx, status, content_type, body)`, which writes the response
  **and** records it under the key the middleware exposed (recording first, so
  a client that dropped still leaves the record). With `capture = .off` only
  `respond` records: a handler that writes `ctx.res` directly then still works
  but is **not** deduplicated.

### Transparent capture

When the guarded handler returns without error and did not call `respond`, the
middleware records the status, the headers set inside the guard (`Location`,
`ETag`, …; transfer headers and `Set-Cookie`, which is the first caller's, are never recorded) and the body, read off the `http`
writer **before** the server puts a buffered response on the wire. A body
that outgrows the server's response buffer (4 KiB by default) streams; its
bytes are collected through the `http.Server.ResponseWriter.BodyTap` seam, as
the plain bytes the handler wrote (before gzip), up to
`Options.max_capture_bytes` (1 MiB). h1 and h2 serve through the same writer.

- `capture = .all` (default) records every status, 5xx included (Stripe).
  `.success` keeps only 2xx (IdempotentAPI `CacheOnlySuccessResponses`), so a
  transient error is not replayed. `.off` is the cooperative-only mode.
- A handler error records nothing and releases the key: the retry runs.
- Never recorded, and counted in `Store.capture_refused`: a body over
  `max_capture_bytes` (or out of memory), `upgrade` (WebSocket) / `tunnel` /
  `detach`, a failed response, a HEAD, declared trailers, a declared
  `Content-Length` the body does not match, a body the handler content-coded
  itself (`Content-Encoding` set), and `text/event-stream`. The retry of such
  a request runs the handler again — watch the counter.
- A streamed response whose socket write fails mid-handler surfaces as a
  handler error and is not recorded; a buffered one is recorded before the
  write.

### Scope, methods, validation

- **Scope** (`Options.scope`, default `.target`): the cache key is the client's
  key namespaced by `"<METHOD> <path>"`, so the same key value on two endpoints
  cannot cross-replay (the header draft's "unique in the scope of a resource").
  `.key_only` keys on the client's value verbatim.
- **Methods** (`Options.methods`, default POST/PUT/PATCH): only these are
  deduplicated; any other method bypasses (runs normally). A POST **without**
  the key header also bypasses — idempotency is opt-in per request.
- **Validation**: a key must be non-empty, ≤ `max_key_len` (255) bytes and all
  printable non-space ASCII; otherwise the request answers **400**. A
  well-formed key whose *scoped* form would exceed 1 KiB degrades to running
  normally (no dedup) rather than erroring.

### Request-fingerprint mismatch: 422

A key reused across a different method or path is already safe under the
default `scope = .target`: those are different cache entries, so a
`POST /orders` answer can never replay for `POST /refunds` (only
`scope = .key_only` opts out of that). The same target with a **different
body** is the dangerous case — a client library reusing one key for two
genuinely different payloads must NOT get the first payload's answer back.
The middleware buffers the request body (bounded by `Options.max_body_bytes`,
default 16 KiB) and SHA-256-fingerprints it; the digest is recorded alongside
the response and compared (constant-time, `std.crypto.timing_safe.eql`) on
every same-key request. A mismatch answers **422** without running the
handler (the IETF Idempotency-Key draft's SHOULD). A body over the cap cannot
be safely fingerprinted, so it fails closed with **413** instead of silently
falling back to no check — the whole point is that a check that can be
dodged is not a check. The query string is part of the fingerprint: the same
body sent to a different query is a 422 too. The buffered bytes are re-exposed to the handler
transparently (via the same `req.decoded` seam inbound gzip decoding uses),
so a handler that reads the body still sees it.

`Options.spool` (default null) lifts the cap for uploads: the first
`max_body_bytes` stay in memory, the rest goes to a spool the caller opens per
request (`http.Server.FileSpool` over a temp file is the ready one), the body
is hashed in the same pass and the handler reads it back from byte 0.
`Options.max_spooled_body_bytes` caps the whole body (413 above it); a spool
failure is a server error and reserves nothing. The spool's storage holds the
request body, so it is the caller's security boundary.

### Bounds & retention

`ramcache` supplies the store's spine: a TTL (default 24 h via `Store.ttl_ns`),
a byte cap, an entry cap, and W-TinyLFU admission/eviction — so an unbounded
stream of one-shot keys cannot flush the hot set or exhaust memory. The cache
owns its copies of the recorded status/`Content-Type`/body bytes.

### Concurrent first-flights: handled via in-flight reservation

Two requests carrying the same key that arrive before either has recorded a
response do **not** both run the handler: the first to see a miss reserves the
key (`Store.in_flight`) for the duration of its handler, and a second same-key
request arriving in that window is answered **409** (already in flight)
instead of re-running it. This is in-process state, not shared through
`ramcache` — it closes the race within one process but not across multiple
processes/machines sharing one store.

## Durable or shared records: `Backend`

`Store.backend` replaces the in-process `ramcache` with any store that
implements `Backend` (`lookupOrReserve` atomic per key, `put`, `release`;
the contract is on the type). Bundled: `KvBackend`, records in a `kv` file,
fsync'd and expiring on kv's wall clock, so a retry after a crash or restart
still replays instead of charging twice:

```zig
var db = try kv.Db.open(gpa, fs.storage(), "idempotency.kv", .{});
defer db.close();
var kb = idempotency.KvBackend{ .db = &db, .gpa = gpa };
defer kb.deinit();
var store = idempotency.Store{ .backend = kb.backend() };
defer store.deinit();
```

A backend over a database several processes share (Redis `SET NX PX`, a SQL
row lock) closes the race across processes too; `Store.lease_ns` lets such a
backend hand over a reservation whose holder died. `KvBackend` keeps its
reservations in memory (the kv file is single-process), and answers 409 when
it cannot read a record — never a second run.

## Attributes

- **Role:** server. **Platform:** any. **Deps:** `router`,
  `http`, `ramcache`, `kv`, `clock`. **Concurrency:** threadsafe — the `ramcache` store sits
  behind an internal spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std
  SmpAllocator pattern), so `respond` and the middleware may race across all
  connection threads; the cached bytes are copied out under the lock and
  written to the socket lock-free. The scoped key travels middleware→handler in
  the store, bound to the request's address -- never thread-local, which a
  nested dispatch or another fiber on the same thread overwrote (A1 F2). The `Store` and
  `Idempotency` must outlive the `Router`, at stable addresses. The clock is
  injected (`Store.clock`) so TTL tests are deterministic; only the default
  `.monotonic` clock touches the OS.

Provenance: clean-room from the Idempotency-Key pattern (Stripe's idempotent
requests; `draft-ietf-httpapi-idempotency-key-header`). No third-party source
copied; built on the sibling `ramcache`, `router` and `http` modules.
`tools/lead_probe` is own tooling that runs `@node-idempotency/core` 1.1.0
(MIT, read in full before running) as a black-box oracle; no data of it is
committed.

## Not provided

No bundled cross-process store (the `Backend` seam takes one) and no one-pass
streaming body hash by default (bounded 413, or the opt-in `Options.spool`);
see SPEC *What is deliberately not done* and *Backlog / deferred*.

## Verification

`scripts/modtest idempotency` — offline tests through
`http.Server.serveStream` with a real `router` and `ramcache`, `Backend` /
`KvBackend` tests, and seeded model-fuzz; the classes are listed in SPEC
*Verification*. The card's `**Audit:**` line in SPEC is the current score.
