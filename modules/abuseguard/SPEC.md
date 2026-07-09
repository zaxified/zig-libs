# abuseguard — spec

IP reputation + connection-abuse defense for a directly internet-facing `http.Server`. Usage: see
./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
- **Layered:** `Guard` — reputation store + admission engine (`admit`/`connClosed`,
  `record`/`ban`/`unban`/`greylist`), pure and drivable without HTTP. `Guard.onConnect()` /
  `onConnState()` — the `http.Server` Phase-2.1 hook pair: accept-time admit/reject, release the
  per-IP slot on `.closed` (cannot be maintained from `on_connect` alone). `Guard.middleware()` —
  optional `router.Middleware`, auto-strike on 4xx/429, registered first so it observes inner
  denials + the router's own 404/405.
- **Strikes (fail2ban shape):** `record(ip, weight)` decays as a leaky bucket (one strike per
  `strike_decay_ms` ≈ findtime); reaching `ban_threshold` (≈ maxretry) resets the balance and
  greylists for `greylist_ttl_ms` (≈ bantime); reaching `ban_after_offenses` escalates to a
  permanent ban (≈ the recidive jail).
- **Keying:** socket peer IP in 16-byte mapped form (`netaddr` unmap) — an IPv4-mapped IPv6 peer and
  its plain IPv4 form are one entry. Middleware can key on `ratelimit`'s trusted-XFF chain instead
  for behind-proxy deployments.
- **Bounded, fail-closed store:** at most `max_tracked_ips` entries; fully-lapsed entries swept from
  the LRU tail on insert; live-connection entries never evicted; banned entries evicted only as a
  last resort. When nothing is evictable, new IPs are **rejected** (nginx zone-exhausted semantics,
  deliberately fail-closed — contrast `ratelimit`'s fail-open, since an uncountable connection is
  exactly the resource being defended). Size `max_tracked_ips` ≥ `max_conns_total`.
- **Concurrency:** threadsafe, internally synchronized (spinlock + O(1) LRU relink, same pattern as
  `ratelimit`); clock injected (default posix `clock_gettime`), never read internally, so every
  ban/greylist/decay test is deterministic.

## Threat model / out of scope
Per-instance, in-memory only: no shared reputation across processes/nodes; a restart clears all
state. Admission-time only — a ban/greylist affects new admissions; already-admitted connections run
until close (pair with the server's read/write/request timeouts; the guard cannot kill a live
connection). Known edge: if `http.Server` drops an admitted connection before serving starts
(per-connection buffer OOM), `.closed` never fires and that IP's slot leaks by one (the guard's own
memory stays bounded regardless). Not encryption or authentication — complements but does not replace
TLS/auth; does not inspect request bodies or protocol content.

## Verification
`zig build test-abuseguard` — 22 tests. Offline deterministic (injected clock): ban/greylist add +
TTL expiry, strike accumulation → greylist → ban on repeat, exact decay, per-IP counter inc/dec via
the hook pair, per-IP + global caps, LRU eviction (live-pinning + banned-last + empty-sweep),
v4-mapped unification, fail-closed OOM, an 8-thread admission race and an exact-threshold concurrent
`record` race. Middleware goldens over socket-free `http.Server.serveStream` (4xx/429 weights,
zero-weight opt-out, forwarded-IP keying). Two loopback integrations (skip only when loopback binding
is unavailable): (1) concurrent keep-alive conns, next rejected at accept, close→re-admit, manual
ban/unban, greylist TTL re-admit, record-driven escalation; (2) router auto-strike middleware
escalating a 404 path scanner to accept-time rejection, then TTL re-admits.

## Backlog / deferred
None found beyond the pre-public security/similarity review pass (repo-wide, not abuseguard-specific).

## Status
`gap · posix · server · threadsafe` + deps `http`, `netaddr`, `router` — canonical source is
`pub const meta` in src/root.zig.
