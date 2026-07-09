# sessions

Server-side web sessions + CSRF as a `router` middleware: opaque CSPRNG session
ids, a pluggable `Store` (default over `ramcache`), OWASP-hardened cookies, and
signed double-submit CSRF tokens.

A session is server-side state keyed by an unguessable id the browser echoes in
a cookie. The id comes from a CSPRNG (`std.Io.random`, threaded in at
construction — never the removed `std.crypto.random`, never a test-only
`DefaultPrng`), so it can neither be guessed nor forged; the state lives in the
`Store` and the cookie carries only the id.

```zig
var cache = ramcache.Cache.init(gpa, .{ .max_bytes = 8 << 20, .max_entries = 4096 });
defer cache.deinit();
var store: sessions.RamcacheStore = .{ .cache = &cache };
var mgr = sessions.Manager.init(gpa, store.store(), .{ .io = io });
try r.use(mgr.middleware()); // before the routes it guards

fn dashboard(ctx: *router.Ctx) anyerror!void {
    const s = sessions.sessionOf(ctx).?;   // loaded-or-created for you
    try s.setData("uid=42");               // persisted after the handler returns
    try ctx.res.writeAll(s.data());
}
```

## What the middleware does

On each request it **loads** the session named by the cookie (rejecting and
evicting one past its idle or absolute timeout) or **creates** a fresh one,
attaches the `*Session` to `ctx.data` (the slot `router` reserves —
`sessionOf(ctx)` reads it back, the `aaa-gate` identity pattern), runs the
handler, then **saves**: it re-encodes the session into the store and stamps a
refreshed `Set-Cookie` (rolling idle expiry). A handler calls `session.revoke()`
to log out — the middleware then **destroys** the session (evicts it and expires
the cookie with `Max-Age=-1`). After a privilege change (login), call
`Manager.regenerate` — a new id is minted, the data carried over, the old id
killed in the store (session-fixation defense).

## Cookie hardening (OWASP Session Management Cheat Sheet)

Session cookies are always `HttpOnly` and `Secure` with `SameSite=Lax` by
default. `Secure` is dropped for a plain-HTTP dev server **only** via the
explicit `Options.allow_insecure_cookie` escape hatch — never silently.

## CSRF — signed double-submit (`Csrf`)

The token is `HMAC-SHA256(key, session_id)`, hex-encoded. Being a keyed MAC over
the session id it is **bound to the session** (a token for session A does not
verify for B — no cross-session replay) and **stateless** (the server recomputes
the expected MAC and compares in constant time — `std.crypto.timing_safe.eql`,
never `std.mem.eql`). `Csrf.middleware` guards the unsafe methods
(POST/PUT/PATCH/DELETE): a guarded request must present the token (in the
`X-CSRF-Token` header, or a query-parameter fallback) matching its session id,
else **403**; safe methods pass and receive a fresh JS-readable token cookie.

Body form-field extraction is deliberately *not* done in the middleware: the
handler owns the streamed request body, so a middleware that drained it to find
a `csrf_token` field would steal it. An app that renders a classic hidden form
field parses its own body and calls the pure `Csrf.verify(session_id, field)`.

## Concurrency & the no-copy cookie buffer

A built `Manager`/`Csrf` is immutable and shared across `http.Server`'s
connection threads. The only mutable state is the `Store`, whose default
`RamcacheStore` serializes every cache touch behind its **own**
`std.atomic.Mutex` (`ramcache` is single-owner). `ramcache` has no single-key
delete, so deletion writes a zero-length **tombstone** (an empty record reads as
absent; a real record is always ≥ 16 bytes). Per-request `Session` state lives
on the serving thread's stack. The `Set-Cookie` value is staged in a
**thread-local** buffer: the response writer stores header slices uncopied and
serializes them lazily at `writeHead`, *after* the handler returns — a stack
buffer would dangle (task-per-connection makes the thread-local safe). The clock
is injected (`Options.clock`) so timeout tests are deterministic; only the
default `.monotonic` clock touches the OS.

## Not handled (deferred)

Distributed `Store` (Redis adapter — implement the `Store` vtable);
signed-cookie *stateless* sessions (no server store); `SameSite=None`
cross-site flows; CSRF token rotation / synchronizer-token mode and
`Csrf.key` provisioning/rotation; logout-everywhere (a user→sessions index);
concurrent same-session read-modify-write races (last save wins); automatic
CSRF body form-field extraction (use `Csrf.verify` from the handler instead).

Provenance: original work of the zig-libs authors (MIT); modeled after the
OWASP Session Management and CSRF Prevention Cheat Sheets — see NOTICE. No
third-party source consulted or copied; built on the sibling `router`,
`http`, `cookies` and `ramcache` modules.

## Verification

`zig build test-sessions` — 16 offline tests (Debug + `-Doptimize=ReleaseFast`),
`zig fmt --check modules/sessions`. Session core (6): create→save→load
round-trip, forged id → absent, idle-expiry evict, absolute-cap expiry,
regenerate (old id dead / data carried), insecure escape hatch. Middleware (3):
hardened Set-Cookie + cookie round-trip, revoke expires+evicts, small-buffer
early-flush (no cookie-buffer corruption). CSRF (6): token/verify round-trip +
tamper, per-key distinctness, safe-GET issues a non-HttpOnly cookie, POST 403
without a token / 200 with the right one, cross-session token rejected,
query-param fallback. Plus the dark-tests aggregator pulling in `csrf.zig`.
