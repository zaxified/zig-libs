# idempotency — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Cooperative by necessity, not by choice: this repo's `router` handler writes directly to a
*concrete* `http.Server.ResponseWriter` that streams to the socket — there is no interface seam to
slip a capturing writer under. So the middleware cannot transparently buffer-then-cache a response
after the fact. Instead: the **middleware** owns replay (look up the key on entry; on a hit, write
the cached status/`Content-Type`/body, stamp `Idempotent-Replayed: true`, short-circuit — the
handler genuinely never runs); the **handler** owns recording via `store.respond(ctx, status,
content_type, body)` instead of writing `ctx.res` directly (a handler that bypasses it still works,
just isn't deduplicated). Key scoping (`Options.scope`, default `.target`): the cache key is the
client's key namespaced by `"<METHOD> <path>"`, so the same key value on two endpoints cannot
cross-replay; `.key_only` keys on the client value alone. Method gating: only POST/PUT/PATCH
(configurable) are deduplicated by default; any other method, or a gated method with no key header,
bypasses and runs normally. Key validation: non-empty, ≤ `max_key_len` (255) bytes, printable
non-space ASCII, else 400; a scoped key exceeding 1 KiB degrades to running normally (no dedup)
rather than erroring. Bounds via `ramcache`: TTL (default 24h via `Store.ttl_ns`), byte cap, entry
cap, W-TinyLFU admission/eviction. Concurrency: the `ramcache` store sits behind an internal
spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std `SmpAllocator` pattern); cached bytes are
copied out under the lock and written to the socket lock-free. The scoped key travels
middleware→handler via thread-local storage (task-per-connection, same model as `requestid`).
`Store`/`Idempotency` must outlive the `Router` at stable addresses. The clock is injected
(`Store.clock`) for deterministic TTL tests. Clean-room from the Idempotency-Key pattern (Stripe's
public docs + `draft-ietf-httpapi-idempotency-key-header`); built on sibling `ramcache`/`router`/
`http` — see NOTICE.

## Threat model / out of scope
**Concurrent first-flights of the same key are not handled**: two requests arriving before either
has recorded a response will both execute the handler (no in-progress "409 in flight" lock) — a
true concurrent-retry race can still double-run the side effect; this module dedupes *sequential*
retries against a *completed* response only. **Request-fingerprint mismatch is not detected**: a
client reusing a key with a different request body gets the originally recorded response regardless
— treated as the client's bug, not verified against. Not a general response cache (only ever serves
the byte-for-byte original response back to the *same key*), and not a security boundary — a key is
whatever the client sends, with no authentication tying it to a caller identity.

## Verification
8 offline tests through `http.Server.serveStream` with a real `router` + `ramcache`: first key runs
the handler once and a replay returns the cached response without re-running (hit-counter
asserted), a different key runs again, a non-idempotent method (GET) bypasses, a POST with no key
bypasses, an invalid key → 400, target-scope isolation across paths, TTL expiry re-runs the handler
(injected clock), encode/decode round-trip. `zig fmt --check` clean. Run: `zig build
test-idempotency`.

## Backlog / deferred
None beyond the two explicit non-goals in Threat model (concurrent-first-flight locking,
request-fingerprint verification) — `idempotency` sits in the prod-API hardening cluster
with no further per-module gap noted.

## Status
`gap · any · server · threadsafe` · deps: `router`, `http`, `ramcache` — canonical source is `pub
const meta` in src/root.zig.
