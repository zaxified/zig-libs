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

This repo's `router` handler writes **directly** to `ctx.res`
(`http.Server.ResponseWriter`), which streams to the socket. `Ctx.res` is a
*concrete* type the router hands the handler — there is no interface seam to
slip a capturing writer under — so the middleware **cannot** transparently
buffer an already-streamed response and cache it after the fact. This module is
therefore **cooperative** (approach (a) of the brief — a `Store` over
`ramcache`, no response capture; approach (b), an interposed capturing writer,
is simply not expressible against a concrete `ResponseWriter`):

- The **middleware** owns the *replay* half. On a guarded request with a valid
  key it looks the (scoped) key up in the `Store`; on a hit it writes the
  cached status + `Content-Type` + body, stamps `Idempotent-Replayed: true`,
  and short-circuits the chain — **the handler genuinely never runs** (the
  strongest guarantee, and what the hit-counter test asserts). On a miss it
  exposes the scoped key via `idempotency.currentKey()` and runs the chain.
- The **handler** owns the *record* half. Instead of writing to `ctx.res`
  directly it calls `store.respond(ctx, status, content_type, body)`, which
  writes the response **and** records it under the key the middleware exposed.
  A handler that writes to `ctx.res` directly still works — it just is **not**
  deduplicated (nothing was recorded). This cooperation requirement is the
  honest, unavoidable consequence of the streaming, concrete `ResponseWriter`.

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
dodged is not a check. The buffered bytes are re-exposed to the handler
transparently (via the same `req.decoded` seam inbound gzip decoding uses),
so a handler that reads the body still sees it.

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

## Attributes

- **Role:** server. **Platform:** any. **Deps:** `router`,
  `http`, `ramcache`. **Concurrency:** threadsafe — the `ramcache` store sits
  behind an internal spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std
  SmpAllocator pattern), so `respond` and the middleware may race across all
  connection threads; the cached bytes are copied out under the lock and
  written to the socket lock-free. The scoped key travels middleware→handler in
  thread-local storage (the server is task-per-connection: one request at a
  time per thread), the same model `requestid` uses. The `Store` and
  `Idempotency` must outlive the `Router`, at stable addresses. The clock is
  injected (`Store.clock`) so TTL tests are deterministic; only the default
  `.monotonic` clock touches the OS.

Provenance: clean-room from the Idempotency-Key pattern (Stripe's idempotent
requests; `draft-ietf-httpapi-idempotency-key-header`). No third-party source
consulted or copied; built on the sibling `ramcache`, `router` and `http`
modules.

## Verification

`zig build test-idempotency` — 13 offline tests through `http.Server.serveStream`
with a real `router` + `ramcache`: first key runs the handler once and a replay
returns the cached response without re-running (hit-counter asserted), a
concurrent same-key duplicate fired from inside the first handler is rejected
409 in-flight rather than double-running it, a different key runs again, a
non-idempotent method (GET) bypasses, a POST with no key bypasses, an invalid
key → 400, target-scope isolation across paths, TTL expiry re-runs the handler
(injected clock), encode/decode round-trip (now including the digest), a
different body under the same key answers 422 without running the handler
(and the original entry still replays afterward, untouched), a same body
retry with a real request body still replays, `.key_only` scope still
cross-replays across endpoints when the body genuinely matches, and the body
cap boundary (exactly at the cap fingerprints normally, one byte over answers
413). `zig fmt --check` clean.
