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
rather than erroring. Body-fingerprint verification: a same-key, same-target request is only a
valid retry if its body also matches — the middleware buffers the body (bounded by
`Options.max_body_bytes`, default 16 KiB) and SHA-256-fingerprints it, recording the digest
alongside the response and comparing it (constant-time, `std.crypto.timing_safe.eql` — both
operands are client-influenced, so a variable-time compare would let an attacker binary-search the
stored digest across retries) on every subsequent same-key request. A mismatch answers 422 without
running the handler; a body over the cap cannot be safely fingerprinted and fails closed with 413
rather than silently letting the check be skipped. The buffered body is re-exposed to the handler
via the `req.decoded` override seam (the same one inbound gzip decoding uses), so a cooperating
handler that reads the body still sees it. Bounds via `ramcache`: TTL (default 24h via
`Store.ttl_ns`), byte cap, entry cap, W-TinyLFU admission/eviction. Concurrency: the `ramcache` store sits behind an internal
spinlock (`std.atomic.Mutex` + `spinLoopHint`, the std `SmpAllocator` pattern); cached bytes are
copied out under the lock and written to the socket lock-free. The scoped key travels
middleware→handler via thread-local storage (task-per-connection, same model as `requestid`).
`Store`/`Idempotency` must outlive the `Router` at stable addresses. The clock is injected
(`Store.clock`) for deterministic TTL tests. Clean-room from the Idempotency-Key pattern (Stripe's
public docs + `draft-ietf-httpapi-idempotency-key-header`); built on sibling `ramcache`/`router`/
`http` — see NOTICE.

## Threat model / out of scope
**Concurrent first-flights of the same key ARE handled**, via an in-flight reservation set
(`Store.in_flight`, a `StringHashMapUnmanaged(void)`): the first request to see a miss reserves the
key for the duration of its handler; a second same-key request arriving before the first completes
sees the reservation and is answered **409** (`reserve` returns `.in_flight`) rather than running the
handler a second time — proven by a reentrant test that fires the duplicate *from inside* the first
handler while it is still executing (`"concurrent first-flight of the same key does not double-run
(in-flight 409)"`). This closes the true concurrent-retry race for requests routed through the same
process; it does not span multiple processes/machines (the reservation set is in-process state, not
shared via `ramcache`). **Request-fingerprint mismatch IS detected**: a client reusing a key with a
different request body gets **422**, not the originally recorded response — the body is
SHA-256-fingerprinted (bounded by `Options.max_body_bytes`, fail-closed 413 over the cap) and the
digest checked against the one recorded for the key, constant-time. Not a general response cache
(only ever serves the byte-for-byte original response back to the *same key*, and only when its body
fingerprint matches), and not a security boundary — a key is whatever the client sends, with no
authentication tying it to a caller identity.

## Verification
13 offline tests through `http.Server.serveStream` with a real `router` + `ramcache`: first key runs
the handler once and a replay returns the cached response without re-running (hit-counter
asserted), a concurrent same-key duplicate fired from inside the first handler is rejected 409
in-flight without a second handler run, a different key runs again, a non-idempotent method (GET)
bypasses, a POST with no key bypasses, an invalid key → 400, target-scope isolation across paths,
TTL expiry re-runs the handler (injected clock), encode/decode round-trip (digest included), a
different body under the same key answers 422 and leaves the original entry replayable (graduated
from the `GAP:` test pinned in commit 71540f3), a same-key/same-body retry with a real request body
still replays, `.key_only` scope still cross-replays across endpoints when the body matches, and the
body-cap boundary (exactly at the cap fingerprints normally, one byte over answers 413).
`zig fmt --check` clean. Run: `zig build test-idempotency`.

## Backlog / deferred
None. The one explicit non-goal previously noted here (request-fingerprint verification) is closed —
see "Request-fingerprint mismatch" above. In-flight reservation is still single-process only; a
multi-process/multi-machine deployment sharing one `ramcache`-backed store would still need a
distributed lock to close the same race across processes.

## Status
`gap · any · server · threadsafe` · deps: `router`, `http`, `ramcache` — canonical source is `pub
const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class D · oracle n/a

- **Class D** — our own design — no third party exists to agree with, by construction.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** own design over Stripe/IETF-draft pattern, no byte wire format (SPEC.md)
