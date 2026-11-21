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
var mgr = try sessions.Manager.init(gpa, store.store(), .{ .io = io });
try r.use(mgr.middleware()); // before the routes it guards

fn dashboard(ctx: *router.Ctx) anyerror!void {
    const s = sessions.sessionOf(ctx).?;   // loaded-or-created for you
    try s.setData("uid=42");               // persisted after the handler returns
    try ctx.res.writeAll(s.data());
}
```

### Sessions that survive a restart — `KvStore`

```zig
var db = try kv.Db.open(gpa, fs_store.storage(), "sessions.kv", .{});
defer db.close();
var store = try sessions.KvStore.init(&db, .{}); // prefix "session:", 12 h kv expiry
var mgr = try sessions.Manager.init(gpa, store.store(), .{ .io = io, .clock = .realtime });
// now and then: if (db.deadBytes() > 1 << 20) try db.compact();
```

Records go to a `kv` store under `prefix ++ id`, with a `kv` expiry refreshed by
every save that drops abandoned sessions at the next `compact`. The manager
needs `Clock.realtime` — `Manager.init` refuses the monotonic default over a
persistent store, whose origin a reboot resets. Every save is an `fsync` -- including the `last_seen` roll of a session the handler did not change, as scs does when its idle timeout is on -- and
the middleware saves on every request with a session: throughput is bounded by
the disk's fsync rate (~300/s measured by `kv` on NVMe ext4). After a failed
`kv` write the store answers "no session" to everything until rebuilt over a
reopened `Db` (fail closed: a logout that did not reach the disk must not be
undone by a read).

### Values and flash messages

A session carries a small ordered key/value map over its data blob (≤ 4096 bytes in all;
keys 1..255 bytes, values any bytes). Writing marks the session to be saved, so a new session
holding a value gets its cookie without `keep()`:

```zig
try s.putValue("uid", "42");                    // replace in place or append
const uid = try s.getValue("uid");              // ?[]const u8, a slice into s.data()
try s.putValue("flash", "Profile saved");       // flash: show it once ...
var buf: [128]u8 = undefined;
if (try s.popValue("flash", &buf)) |msg| try ctx.res.writeAll(msg); // ... copied out, then removed
_ = try s.removeValue("uid");
var it = s.valueIterator();                     // insertion order
while (try it.next()) |e| std.log.info("{s}={s}", .{ e.key, e.val });
s.clearValues();
```

`putValue` returns `error.Overflow` when the blob would exceed `max_session_bytes` (nothing
changes) and `error.InvalidKey` for an empty or over-255-byte key. Raw `setData` and these
calls share one blob: after a raw `setData` the values calls answer `error.Malformed` until
`clearValues()` — never a wrong value.

### Remember me

```zig
var mgr = try sessions.Manager.init(gpa, store.store(), .{ .io = io, .persist_cookie = false });
// login handler:  if (form.remember) s.rememberMe(true);
```

With `persist_cookie = false` the session cookie has no `Max-Age` (it ends with the browser
session) unless the session called `rememberMe(true)`; the default (`true`) is the old
behaviour. The flag is stored with the session; server-side timeouts apply either way.

### Logout everywhere

```zig
fn ofUser(ctx: ?*anyopaque, s: *const sessions.Session) sessions.IterateAction {
    const uid: *const []const u8 = @ptrCast(@alignCast(ctx.?));
    const v = (s.getValue("uid") catch return .keep) orelse return .keep;
    return if (std.mem.eql(u8, v, uid.*)) .destroy else .keep;
}
const n = try mgr.iterate(gpa, &uid, ofUser); // number destroyed
```

`iterate` visits every live (not expired) session; `.destroy` removes it through the store's
delete, so a request that already holds the session cannot save it back. `KvStore` supports
it, listing `KvStore.Config.iterate_page` keys (default 4096) per `kv` scan page, so its memory
does not grow with the number of sessions; over `RamcacheStore` it copies `iterate_page` records (default 128) out of the cache per lock hold, and a grow of the cache's index between pages restarts the walk (a session may then be shown twice). A third-party `Store` without an enumerator returns `error.Unsupported`.

A `RamcacheStore` keys the cache by the cookie value (or its hash) with no prefix: give it a
`ramcache.Cache` of its own, never one shared with other data — a client chooses the key it
presents. (`KvStore` has a prefix.)

### Hashed ids in the store

`Options.hash_id_in_store = true` keys the store by `SHA-256(id)` (32 raw bytes), so a leaked
store file does not hold live session ids. The cookie and `Csrf` still use the real id.
Changing it on a populated store logs everyone out. Under it, `Session.id()` inside an
`iterate` callback is the store key, not a cookie value.

### Stateless sessions in the cookie — `CookieManager`

The whole session lives in the cookie, sealed with AES-256-GCM (`.encrypted`, default) or
signed with HMAC-SHA256 (`.signed`, readable by the client). No server state: gorilla
`CookieStore`, Rails `CookieStore`, Flask's session. Same `Session`, same `sessionOf(ctx)`,
same handler API.

```zig
var keys: [1]cookies.Key = undefined;
try cookies.Key.deriveInto(&keys[0], master_secret); // >= 32 random bytes
var cm = try sessions.CookieManager.init(.{ .io = io, .keys = &keys }); // Clock.realtime
try r.use(cm.middleware());
const csrf: sessions.Csrf = .{ .key = csrf_key, .cookie_sessions = &cm }; // bind tokens to the id inside
try r.use(csrf.middleware());
```

- **Rotation:** `keys[0]` seals, every key opens. Put the new key first.
- **Size:** `cm.dataLimit()` is what fits one cookie (`max_cookie_bytes`, 3072 by default,
  at most 4096; `http` gives a response 4 KiB of header bytes in all). `setData`/`putValue`
  return `error.Overflow` above it in the handler. A changed session whose cookie still cannot
  be written fails the request instead of losing the write.
- **Limits of the design (all cookie stores):** `revoke` clears the browser's cookie, but a
  copy of the old value opens until its idle/absolute timeout. A client can replay an older
  value of its own session. Concurrent requests: the last cookie wins. No `iterate`. Use
  `Manager` and a store when a logout must end the session everywhere.

## What the middleware does

On each request it **loads** the session named by the cookie (rejecting and
evicting one past its idle or absolute timeout) or **creates** a fresh one,
attaches the `*Session` to `ctx.data` (the slot `router` reserves —
`sessionOf(ctx)` reads it back, the `aaa-gate` identity pattern), runs the
handler, then **saves**: it re-encodes the session into the store and stamps a
refreshed `Set-Cookie` (rolling idle expiry). A session created for this request
is saved only if the handler wrote to it (`setData`), called `session.keep()` or
`manager.regenerate(session)` — otherwise nothing is stored and no cookie is
issued, so cookieless traffic cannot evict other users' sessions from a bounded
store (`Options.persist_untouched_sessions = true` turns that off). A login-form
page protected by `Csrf` calls `keep()`. A handler calls `session.revoke()`
to log out — the middleware then **destroys** the session (evicts it and expires
the cookie with `Max-Age=-1`). After a privilege change (login), call
`Manager.regenerate` — a new id is minted, the data carried over, the old id
killed in the store (session-fixation defense).

## Without the router

The middleware only moves strings between the cookie header and the core;
the core itself is public and request-type-free. `Manager.create(&session)`
mints an id, `Manager.lookup(sid, &session)` loads by the raw cookie value,
`Manager.persist(&session)` writes back; `Csrf.token(session_id, &buf)` and
`Csrf.verify(session_id, presented)` are pure HMAC over strings. A server
with its own dispatch (or a non-HTTP protocol with a session concept) runs
the same session machinery without `router`.

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

`Csrf` has no `init`: call `csrf.validate()` once at startup. It returns `error.InvalidCookieOptions` for a token-cookie name or `SameSite=None` without `Secure` that could never be written (otherwise every token cookie is silently dropped and every guarded request is refused).

Body form-field extraction is deliberately *not* done in the middleware: the
handler owns the streamed request body, so a middleware that drained it to find
a `csrf_token` field would steal it. An app that renders a classic hidden form
field parses its own body and calls the pure `Csrf.verify(session_id, field)`.

A caller that does not run `Csrf.middleware` at all — using the core module
directly under a different router — can still reuse the exact same guard:
`Csrf.presented(req)` is the public header-then-query token extraction (the
one `middleware` itself calls), and `Csrf.check(req)` is the whole guard minus
the 403 response: session cookie present, a token presented, and it `verify`s.
`check` does **not** apply the middleware's safe-method exemption — it never
looks at the request method, so calling it on a GET tells you whether that GET
carried a valid token, not "GET is always fine". Only `Csrf.middleware` treats
safe methods specially.

## Concurrency

A built `Manager`/`Csrf` is immutable and shared across `http.Server`'s
connection threads. The only mutable state is the `Store`, whose default
`RamcacheStore` serializes every cache touch behind its **own**
`std.atomic.Mutex` (`ramcache` is single-owner). Per-request `Session` state lives
on the serving task's stack, and the `Set-Cookie` value is copied into the
response writer before the call returns, so fibers multiplexed on one thread are
as safe as a thread per connection.

Two concurrent requests of one session (two tabs): every save is a
compare-and-swap on a generation the request loaded. A logout (`revoke`) or a
`regenerate` always wins — a request still in flight cannot save the old session
back — and between two requests that both wrote data the **first** save wins; the
later one is dropped, without a `Set-Cookie`. `Manager.persist` returns whether a
save landed. (A `CookieManager` has no server state: there the last cookie wins.)
The clock is injected (`Options.clock`) so timeout tests are deterministic.

## Not provided

What this module refuses to do (a Redis/SQL store, typed getters, a user → sessions
index, CSRF body-field extraction in the middleware, server-side revocation of a
`CookieManager` session …) are listed, with the reasons, in
[`SPEC.md`](SPEC.md) under *What is deliberately not done*.

Provenance: original work of the zig-libs authors (MIT); modeled after the
OWASP Session Management and CSRF Prevention Cheat Sheets. No third-party
source consulted or copied; built on the sibling `router`, `http`, `cookies`,
`ramcache`, `entropy` and `kv` modules. The comparative benchmark under `tools/` (`bench.zig`, its `go_bench/` reference side against alexedwards/scs v2.9.0, 2026-10-11, and its `go_fast_bench/` gofiber/fiber v3.6.1 side, 2026-10-24) and the `lead_probe/` race probe of scs (2026-10-24) are our own tooling; they drive the other implementations only through their public APIs.

## Verification

`scripts/modtest sessions` (Debug + `-Doptimize=ReleaseFast`), `zig fmt --check
modules/sessions`. What the tests cover, by area, is listed under "Verification" in `SPEC.md`.
