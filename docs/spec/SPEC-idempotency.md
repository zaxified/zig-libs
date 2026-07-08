# SPEC — `idempotency`

**Purpose** — A client retrying an unsafe request (dropped connection,
timeout, flaky mobile link) risks performing the side effect twice — charging
a card twice, creating two orders. `idempotency` is the Stripe-style fix: a
`router` middleware over a `ramcache`-backed `Store` that deduplicates
`Idempotency-Key`-bearing retries, returning the first response instead of
re-running the handler.

**Model after / Seed** — Clean-room from the Idempotency-Key pattern
(Stripe's public idempotent-requests docs +
`draft-ietf-httpapi-idempotency-key-header`). No third-party source consulted
or copied; built on the sibling `ramcache`, `router` and `http` modules
(NOTICE).

**Design & invariants**
- **Cooperative by necessity, not by choice:** this repo's `router` handler
  writes directly to a *concrete* `http.Server.ResponseWriter` that streams to
  the socket — there is no interface seam to slip a capturing writer under.
  So the middleware cannot transparently buffer-then-cache a response after
  the fact (the "interposed capturing writer" design is simply not
  expressible here). Instead: the **middleware** owns replay (look up the key
  on entry; on a hit, write the cached status/`Content-Type`/body, stamp
  `Idempotent-Replayed: true`, and short-circuit — the handler genuinely never
  runs); the **handler** owns recording, by calling
  `store.respond(ctx, status, content_type, body)` instead of writing
  `ctx.res` directly. A handler that bypasses `store.respond` still works,
  just isn't deduplicated.
- **Key scoping (`Options.scope`, default `.target`):** the cache key is the
  client's key namespaced by `"<METHOD> <path>"`, so the same key value on two
  endpoints cannot cross-replay (matching the draft's "unique in the scope of
  a resource"); `.key_only` keys on the client value alone.
- **Method gating:** only POST/PUT/PATCH (configurable) are deduplicated by
  default; idempotency is opt-in per request — any other method, or a
  gated method with no key header, bypasses and runs normally.
- **Key validation:** non-empty, ≤ `max_key_len` (255) bytes, printable
  non-space ASCII, else 400. A well-formed key whose *scoped* form would
  exceed 1 KiB degrades to running normally (no dedup) rather than erroring.
- **Bounds via `ramcache`:** TTL (default 24h via `Store.ttl_ns`), byte cap,
  entry cap, W-TinyLFU admission/eviction — an unbounded stream of one-shot
  keys cannot flush the hot set or exhaust memory. The cache owns copies of
  the recorded status/`Content-Type`/body bytes.
- **Concurrency:** the `ramcache` store sits behind an internal spinlock
  (`std.atomic.Mutex` + `spinLoopHint`, the std `SmpAllocator` pattern), so
  `respond` and the middleware race safely across all connection threads;
  cached bytes are copied out under the lock and written to the socket
  lock-free. The scoped key travels middleware→handler via thread-local
  storage (task-per-connection, same model as `requestid`). `Store` and
  `Idempotency` must outlive the `Router` at stable addresses. The clock is
  injected (`Store.clock`) for deterministic TTL tests; only the default
  `.monotonic` clock touches the OS.

**Threat model / out of scope** — **Concurrent first-flights of the same key
are not handled**: two requests arriving before either has recorded a
response will both execute the handler (there is no in-progress "409 in
flight" lock) — a true concurrent-retry race can still double-run the side
effect; this module dedupes *sequential* retries against a *completed*
response only. **Request-fingerprint mismatch is not detected**: a client
reusing a key with a different request body gets the originally recorded
response regardless — that is treated as the client's bug, not something this
module verifies against. Not a general response cache (it only ever serves
the byte-for-byte original response back to the *same key*), and not a
security boundary — a key is whatever the client sends, with no
authentication tying it to a caller identity.

**Verification** — `zig build test-idempotency`, 8 offline tests through
`http.Server.serveStream` with a real `router` + `ramcache`: first key runs
the handler once and a replay returns the cached response without re-running
(hit-counter asserted), a different key runs again, a non-idempotent method
(GET) bypasses, a POST with no key bypasses, an invalid key → 400,
target-scope isolation across paths, TTL expiry re-runs the handler (injected
clock), encode/decode round-trip. `zig fmt --check` clean.

**Status** — `gap · any · server · threadsafe` · deps: `router`, `http`,
`ramcache`.
