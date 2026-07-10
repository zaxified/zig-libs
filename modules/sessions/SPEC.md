# sessions — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Server-side sessions + CSRF as a `router` middleware.** A session is server-side state keyed by
  an unguessable id the browser echoes in a cookie; the id comes from a CSPRNG (`std.Io.random`,
  threaded in at construction — never the removed `std.crypto.random`, never a test-only
  `DefaultPrng`) so it can neither be guessed nor forged. State lives in a pluggable `Store`
  (default `RamcacheStore` over `ramcache`); the cookie carries only the id. Greenfield, clean-room
  from the OWASP Session Management and CSRF Prevention Cheat Sheets — no third-party source
  consulted or copied; composes the sibling `router`, `http`, `cookies`, `ramcache` modules (see
  NOTICE).
- **Per-request lifecycle:** load the session named by the cookie (rejecting and evicting one past
  its idle or absolute timeout) or create a fresh one, attach `*Session` to `ctx.data` (the slot
  `router` reserves — the `aaa-gate` identity pattern; `sessionOf(ctx)` reads it back), run the
  handler, then save: re-encode into the store and stamp a refreshed `Set-Cookie` (rolling idle
  expiry).
- **Session-fixation defense — `Manager.regenerate`:** after a privilege change (login), a new id
  is minted, the session data carried over, and the **old id is killed in the store** before the
  new cookie is issued — an attacker who fixed a pre-auth session id cannot ride it into an
  authenticated one. `revoke()` destroys a session outright: evicted from the store, cookie expired
  with `Max-Age=-1`.
- **Cookie hardening (OWASP baseline):** session cookies are always `HttpOnly` and `Secure` with
  `SameSite=Lax` by default. `Secure` is dropped for a plain-HTTP dev server **only** via the
  explicit `Options.allow_insecure_cookie` escape hatch — never silently.
- **CSRF — signed double-submit (`Csrf`):** the token is `HMAC-SHA256(key, session_id)`, hex-encoded
  — bound to the session (a token for session A never verifies for B, no cross-session replay) and
  stateless (the server recomputes the expected MAC). **The comparison is
  `std.crypto.timing_safe.eql`, never `std.mem.eql`** — a non-constant-time compare here would leak
  the expected MAC byte-by-byte through timing. `Csrf.middleware` guards unsafe methods
  (POST/PUT/PATCH/DELETE): a guarded request must present the token (header or query-param
  fallback) matching its session id, else 403; safe methods pass and receive a fresh JS-readable
  token cookie. Body form-field extraction is deliberately *not* done in the middleware — draining
  the streamed body there would steal it from the handler; callers use `Csrf.verify` directly for
  classic hidden-form-field flows.
- **Concurrency, optimistic-concurrency CAS & the no-copy cookie buffer:** a built `Manager`/`Csrf`
  is immutable and shared across connection threads. The only mutable state is the `Store`; the
  default `RamcacheStore` serializes every cache touch behind its own lock (`ramcache` itself is
  single-owner). Each stored value is framed `[generation u64 LE] ++ record`; `save` is a
  compare-and-swap against the loaded generation, atomic under that lock, so a stale save from a
  concurrent request cannot resurrect a destroyed/rotated session (see the cross-request
  resurrection note below). `ramcache` has no single-key delete, so deletion writes a **tombstone**
  — the 8-byte bumped generation alone (reads as absent, but keeps the generation so the delete is
  visible to a racing CAS; a live record is always ≥ 8 + 16 bytes). The `Set-Cookie` value is staged in a
  **thread-local** buffer — the response writer stores header slices uncopied and serializes them
  lazily at `writeHead` *after* the handler returns, so a stack buffer would dangle; task-per-
  connection makes the thread-local safe. The clock is injected (`Options.clock`) so timeout tests
  are deterministic; only the default `.monotonic` clock touches the OS.

## Threat model / out of scope

Security-critical module — server-side session identity and CSRF are the trust boundary for every
route behind them. In scope: session-id unguessability (CSPRNG, never a weak RNG), session
fixation (closed via mandatory-on-privilege-change `regenerate`), CSRF via constant-time signed
double-submit, cookie hardening (HttpOnly/Secure/SameSite by default, opt-out is explicit and
named). Out of scope / not handled (v1): a distributed `Store` (Redis adapter — implement the
`Store` vtable); signed-cookie *stateless* sessions (no server store); `SameSite=None` cross-site
flows; CSRF token rotation / synchronizer-token mode and `Csrf.key` provisioning/rotation;
logout-everywhere (no user→sessions index); automatic CSRF body form-field extraction (use
`Csrf.verify` from the handler instead, so the middleware never touches the request body).
Concurrent same-session writes are **generation/CAS-guarded** (see the cross-request resurrection
note above): a delete/regenerate always wins over a stale save, and two concurrent data writes are
first-writer-wins — the store is not a full lost-update-*merging* store, but a stale save can no
longer silently overwrite a newer write or undo a delete.

**Cross-request resurrection race — FIXED (store-level optimistic concurrency).** Both the
same-request case *and* the harder cross-request case are now closed. The same-request case is
closed structurally (`middlewareRun` does not re-`save` a session that was `revoke()`'d or
`regenerate()`'d during that request — see `Session.revoked` / `Session.regenerated`). The
**cross-request** case — two genuinely concurrent requests sharing one cookie, e.g. one tab in
flight while another tab logs out — is closed by a **generation (version) tag + compare-and-swap**
on the `Store`:

- Every stored record carries a monotonic `Generation` (`Store.Loaded.generation`); **absent or
  tombstoned reads as generation 0, every live record is `>= 1`.** `lookup`/`load` tag the loaded
  `Session` with the generation it read (`Session.generation`).
- `save` (via `Manager.persist`) is a **compare-and-swap**: `Store.put(id, record, expected)` writes
  only if the generation the store *currently* holds for `id` equals `expected` (the generation the
  request loaded). The read-compare-write is atomic under the `RamcacheStore` mutex. On success it
  returns the new (bumped) generation; on a mismatch it returns **null** and writes nothing.
- `destroy`/`revoke` (`Store.delete`) and `regenerate` **bump the generation** — `delete` leaves a
  tombstone that remembers the bumped generation; `regenerate` deletes the old id (bump) and resets
  `Session.generation` to 0 so the new id is persisted as a fresh *create*-CAS. So the instant a
  concurrent request destroys or rotates the session, any other in-flight request still holding the
  old generation can no longer CAS-match: **a delete/rotate always wins over a concurrent stale
  save.** Because an absent key reads as generation 0 and a stale save's `expected` is always `>= 1`,
  the stale save fails even if the tombstone has since been LRU-evicted.

**Save-CAS-failure policy (fail closed).** A `save` whose CAS loses the race is a **no-op**: nothing
is written to the store and **no rolling `Set-Cookie` is issued**. The session stays whatever the
winning request made it (dead after a logout, rotated after a regenerate); the browser keeps its
current cookie and the next request re-resolves it (absent after a logout ⇒ a fresh login). For two
concurrent *data* writes to a still-live session the policy is **first-writer-wins** (the later,
now-stale save is dropped) — last-write-wins is not attempted; the only security-critical guarantee
is that a delete/regenerate cannot be undone. `Manager.save` returns void (the middleware ignores
the outcome); `Manager.persist` exposes the CAS result as a `bool` so a handler could observe/retry.
A future distributed `Store` (Redis) implements the same CAS via a Lua script or `WATCH`/`MULTI` on
the generation.

**Known limitation — thread-per-connection assumption for the `Set-Cookie` buffer:** `writeCookie`
stages the `Set-Cookie` value in a **threadlocal** buffer (`cookie_buf`) because `http.Server`'s
response writer keeps the header slice uncopied and serializes it lazily at `writeHead`, after the
middleware itself has already returned — a stack buffer would dangle by then. This is only safe
under a **thread-per-connection (blocking)** `std.Io` backend (e.g. `std.Io.Threaded`), where one
OS thread serves exactly one connection's request at a time, so the threadlocal is never shared. A
**cooperative/fiber `Io` backend** that multiplexes multiple connections onto one OS thread (e.g. an
event-loop or green-thread scheduler) would let one connection's handler run, stage its
`Set-Cookie` into `cookie_buf`, yield, and have a *different* connection's request run on the same
OS thread before the first one's header is serialized — bleeding one user's `Set-Cookie` (and
therefore session id) into another user's response. Callers **must** use a blocking, one-thread-
per-connection `std.Io` implementation (or an equivalent scheduling guarantee) with this module;
this is not currently enforced in code (there is no portable way to introspect the `Io`
implementation's scheduling model from here), only documented.

## Verification

22 offline tests (Debug + `-Doptimize=ReleaseFast`), `zig fmt --check modules/sessions`. Session
core (10): create→save→load round-trip, forged id → absent, idle-expiry evict, absolute-cap expiry,
regenerate (old id dead / data carried), **cross-request race — stale save cannot resurrect a
concurrently destroyed session**, **cross-request race — stale save cannot resurrect a concurrently
regenerated (rotated) id (and the new id persists)**, **single-owner save succeeds + bumps the
generation, a second concurrent stale save no-ops (first-writer-wins)**, `min_id_bytes` floor
accepted at floor/default/ceiling, insecure escape hatch. Middleware (5): hardened Set-Cookie +
cookie round-trip, revoke
expires+evicts, same-request revoke does not get resurrected by the trailing save, same-request
regenerate persists only the new id (old id stays dead, post-rotation data survives),
small-buffer early-flush (no cookie-buffer corruption). CSRF (6): token/verify round-trip + tamper,
per-key distinctness, safe-GET issues a non-HttpOnly cookie, POST 403 without a token / 200 with
the right one, cross-session token rejected, query-param fallback. Plus the dark-tests aggregator
pulling in `csrf.zig`. Run: `zig build test-sessions`.

## Backlog / deferred

- **Reviewed 2026-07-10** (adversarial security pass, alongside `aaa-gate`/`jwt`/`acme`/
  `snmp.usm`/`kv`/`http`/`sealedbox`/`hashdigest`) — `sessions` is server-side auth-adjacent state
  (session identity + CSRF): session-fixation and logout-resurrection issues (HIGH) plus an
  id-entropy floor were found and fixed; the cross-request race was separately resolved via CAS
  (commit `c1bc3d7`).
- **Distributed `Store`** (Redis adapter) — implement the `Store` vtable; not built.
- **Signed-cookie stateless sessions** — no server store variant; not built.
- **`SameSite=None` cross-site flows** — not supported.
- **CSRF token rotation / synchronizer-token mode + `Csrf.key` provisioning/rotation** — not built;
  the key is caller-supplied and static for the process lifetime.
- **Logout-everywhere** (a user→sessions index) — not built; `revoke`/`regenerate` act on one
  session id only.
- ~~**Cross-request resurrection race / concurrent same-session write CAS**~~ — **DONE.** Store
  records carry a monotonic `Generation`; `save` is a compare-and-swap against the loaded
  generation and `delete`/`regenerate` bump it, so a stale concurrent `save` is rejected (fail
  closed, delete/rotate wins) instead of silently overwriting a newer write or undoing a delete.
  See the cross-request resurrection note in the Threat-model section above. A full lost-update-
  *merging* store (last-write-wins field merge) is still not attempted — first-writer-wins for
  concurrent data writes.
- **Automatic CSRF body form-field extraction** — deliberately not done in the middleware (see
  design notes); callers use `Csrf.verify` directly.

## Status

`gap · any · server · threadsafe` + deps: `router`, `http`, `cookies`, `ramcache` — canonical
source is `pub const meta` in src/root.zig.
