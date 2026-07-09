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
- **Concurrency & the no-copy cookie buffer:** a built `Manager`/`Csrf` is immutable and shared
  across connection threads. The only mutable state is the `Store`; the default `RamcacheStore`
  serializes every cache touch behind its own lock (`ramcache` itself is single-owner).
  `ramcache` has no single-key delete, so deletion writes a zero-length **tombstone** (empty reads
  as absent; a real record is always ≥ 16 bytes). The `Set-Cookie` value is staged in a
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
logout-everywhere (no user→sessions index); concurrent same-session read-modify-write races (last
save wins — not a lost-update-safe store); automatic CSRF body form-field extraction (use
`Csrf.verify` from the handler instead, so the middleware never touches the request body).

**Known limitation — cross-request resurrection race (not fixed here):** the same-request case is
closed (`middlewareRun` does not re-`save` a session that was `revoke()`'d or `regenerate()`'d
during that request — see `Session.revoked` / `Session.regenerated`). A **deeper**, cross-request
race remains: two genuinely concurrent requests can share a cookie (the same session id) — for
example, one tab in flight while another tab logs out. Request A loads the session (a private,
in-memory copy) before request B calls `revoke()`/`regenerate()` and deletes it from the store;
when A finishes, its trailing `save()` still `put`s its (stale) copy back under the old id,
resurrecting a session that was supposed to be dead, or reviving a fixed pre-auth id after a
same-session regenerate raced it out. This needs store-level optimistic concurrency — a
generation/version tag on the record, with `put` doing a compare-and-swap against the generation
the request originally loaded, so a racing writer's stale `save` is rejected instead of silently
overwriting a newer write or a delete. Not built; backlogged (see below) as a `Store` vtable change
(`get` returning a generation, `put`/`delete` taking an expected generation).

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

19 offline tests (Debug + `-Doptimize=ReleaseFast`), `zig fmt --check modules/sessions`. Session
core (7): create→save→load round-trip, forged id → absent, idle-expiry evict, absolute-cap expiry,
regenerate (old id dead / data carried), `min_id_bytes` floor accepted at floor/default/ceiling,
insecure escape hatch. Middleware (5): hardened Set-Cookie + cookie round-trip, revoke
expires+evicts, same-request revoke does not get resurrected by the trailing save, same-request
regenerate persists only the new id (old id stays dead, post-rotation data survives),
small-buffer early-flush (no cookie-buffer corruption). CSRF (6): token/verify round-trip + tamper,
per-key distinctness, safe-GET issues a non-HttpOnly cookie, POST 403 without a token / 200 with
the right one, cross-session token rejected, query-param fallback. Plus the dark-tests aggregator
pulling in `csrf.zig`. Run: `zig build test-sessions`.

## Backlog / deferred

- **Pre-public security/similarity review** — `sessions` is server-side auth-adjacent state
  (session identity + CSRF) and should be added to the repo's pre-public security-gate checklist
  (`/docs/pre-public-review.md` currently lists `aaa-gate`/`jwt`/`acme`/`snmp.usm`/`kv`/`http`/
  `sealedbox`/`hashdigest` explicitly; `sessions` is not yet named there and should be folded in
  before any release).
- **Distributed `Store`** (Redis adapter) — implement the `Store` vtable; not built.
- **Signed-cookie stateless sessions** — no server store variant; not built.
- **`SameSite=None` cross-site flows** — not supported.
- **CSRF token rotation / synchronizer-token mode + `Csrf.key` provisioning/rotation** — not built;
  the key is caller-supplied and static for the process lifetime.
- **Logout-everywhere** (a user→sessions index) — not built; `revoke`/`regenerate` act on one
  session id only.
- **Concurrent same-session read-modify-write races** — last save wins; no optimistic-concurrency
  guard. Same underlying gap as the cross-request resurrection race in the Threat-model section
  above: needs a generation/version tag on `Store` records and a CAS-style `put`/`delete` so a
  stale concurrent `save` can be rejected instead of silently winning.
- **Automatic CSRF body form-field extraction** — deliberately not done in the middleware (see
  design notes); callers use `Csrf.verify` directly.

## Status

`gap · any · server · threadsafe` + deps: `router`, `http`, `cookies`, `ramcache` — canonical
source is `pub const meta` in src/root.zig.
