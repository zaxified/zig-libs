# SPEC — `abuseguard`

**Purpose** — IP reputation + connection-abuse defense for a **directly internet-facing**
`http.Server`. With no reverse proxy in front, the app IS the edge: `ratelimit` bounds request
*rate* per key; `abuseguard` bounds *connections* and keeps *IP reputation*, so a misbehaving
client is cut at accept time — a reject costs the attacker only a TCP handshake and writes nothing
(the server's documented `on_connect` posture; no polite 503).

**Model after / Seed** — Clean-room, no seed project and no third-party code. Model after nginx
`limit_conn` (per-key concurrent-connection caps, zone-exhaustion semantics; BSD-2-Clause,
documented behavior only) + fail2ban (strike → temporary ban → recidive escalation; GPL-2.0,
documented behavior only, no source consulted or copied) + Cloudflare-style IP reputation
(ban/greylist lists). Design refs in `NOTICE`.

**Design & invariants**
- **Layered:** `Guard` — the reputation store + admission engine (`admit`/`connClosed`,
  `record`/`ban`/`unban`/`greylist`), pure and drivable without HTTP.
  `Guard.onConnect()`/`onConnState()` — the `http.Server` Phase-2.1 hook pair: `on_connect` admits
  or rejects at accept, `on_conn_state` releases the per-IP slot on `.closed` (the per-IP count
  cannot be maintained from `on_connect` alone — exactly why the ConnState hook exists).
  `Guard.middleware()` — optional `router.Middleware` auto-strike on 4xx/429, registered **first**
  so it observes inner denials and the router's own 404/405.
- **Strikes (fail2ban shape):** `record(ip, weight)` decays as a leaky bucket (one strike drains
  per `strike_decay_ms` ≈ `findtime`); reaching `ban_threshold` (≈ `maxretry`) is an offense — the
  balance resets and the IP greylists for `greylist_ttl_ms` (≈ `bantime`); reaching
  `ban_after_offenses` escalates to a permanent ban (≈ the recidive jail).
- **Keying:** the socket peer IP in its 16-byte mapped form (`netaddr` unmap), so an IPv4-mapped
  IPv6 peer and its plain IPv4 form are one client, one entry. The middleware can key on
  `ratelimit`'s trusted-XFF chain instead for behind-proxy deployments.
- **Bounded, fail-closed store:** at most `max_tracked_ips` entries; fully-lapsed entries are swept
  from the LRU tail on insert, live-connection entries are never evicted, banned entries go only as
  a last resort. When nothing is evictable, new IPs are **rejected** — nginx's zone-exhausted
  semantics, deliberately **fail-closed** (contrast `ratelimit`'s fail-open: an uncountable
  connection is exactly the resource being defended).
- **Concurrency:** threadsafe — internally synchronized (spinlock around a hash lookup + O(1) LRU
  relink, same pattern as `ratelimit`); clock injected (default posix `clock_gettime`), never a
  wall-clock read internally, so every ban/greylist/decay test is deterministic.

**Threat model / out of scope** — Per-instance and in-memory only: no shared reputation across
processes or nodes, and a restart clears all bans/greylist/strike state. Scope is admission-time
only — a ban/greylist affects new admissions, connections already admitted run until they close
(pair with the server's read/write/request timeouts; the guard has no handle to kill a live
connection). Known edge: if `http.Server` drops an admitted connection before serving starts
(per-connection buffer OOM), `.closed` never fires and that IP's slot leaks by one (the guard's own
memory stays bounded regardless). Not encryption or authentication — complements but does not
replace TLS/auth, and does not inspect request bodies or protocol content.

**Verification** — 22 tests (`zig build test-abuseguard`). Offline deterministic (injected clock):
ban/greylist add + TTL expiry, strike accumulation → greylist at threshold → ban on repeat, exact
strike decay, per-IP counter inc/dec by driving the `onConnect`/`onConnState` hook pair with
synthetic peers, per-IP + global cap decisions, LRU eviction with live-connection pinning +
banned-last policy + empty-entry sweep, v4-mapped unification, fail-closed OOM, an 8-thread
admission race and an exact-threshold concurrent `record` race. Middleware goldens over the
socket-free `http.Server.serveStream` (4xx/429 weights, zero-weight opt-out, forwarded-IP keying).
Two in-process loopback integrations, skipping only when loopback binding is unavailable: (1)
`max_conns_per_ip` keep-alive connections served concurrently, the next rejected at accept, close →
re-admit, manual ban/unban, greylist TTL expiry re-admits, a `record`-driven greylist→ban
escalation; (2) a router with the auto-strike middleware where three real 404s escalate a path
scanner to an accept-time rejection, then the TTL re-admits it.

**Status** — `gap · posix · server · threadsafe` · deps: `http`, `netaddr`, `router`.
