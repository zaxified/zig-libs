# SPEC — `abuseguard`

App-layer connection abuse defense for a directly-internet-facing server. Web/API cluster (T5.4).
`gap · posix · server · tsafe`. Model after: nginx `limit_conn` + fail2ban (strike→ban) +
Cloudflare-style IP reputation. Deps: `http`, `netaddr`, `router`. New `build.zig` entry
`.{ .name = "abuseguard", .deps = &.{ "http", "netaddr", "router" } }`.

## Why

With no reverse proxy, the app IS the edge. `ratelimit` bounds request *rate* per key; `abuseguard`
bounds *connections* and maintains *IP reputation*: per-IP + global concurrent-connection caps and a
ban/greylist so a misbehaving client is cut at accept time (cheap — the hardening step made a reject
cost the attacker only a handshake). It plugs into the `http.Server` hooks added in Phase 2.1
(`on_connect` for admission, `on_conn_state` for lifecycle, `activeConnections()` for the global cap).

## Scope

1. **Admission (`on_connect`):** an `OnConnectFn` the server calls at accept, before any alloc/read.
   Reject (`.reject`) when: the peer IP is **banned**, is **greylisted** (temporary), exceeds the
   **per-IP concurrent-connection cap**, or the **global** cap is hit. Otherwise accept + increment
   the per-IP counter.
2. **Lifecycle (`on_conn_state`):** decrement the per-IP counter on `.closed` (the per-IP count can't
   be maintained from `on_connect` alone — this is exactly why Phase 2.1 added the ConnState hook).
3. **Reputation store (thread-safe, bounded):** ban list (manual/permanent) + greylist (auto-expiring
   TTL) keyed by IP; a per-IP **strike counter** with decay. `record(ip, weight)` adds strikes;
   crossing `ban_threshold` auto-greylists (escalating to ban on repeat). Bounded map + LRU/expiry so
   the store can't be memory-exhausted (an abuse vector itself). Clock-injected (deterministic tests),
   default monotonic via the posix `clock_gettime` errno form.
4. **Strike sources:** `record()` for the app to flag abuse; an optional `router.Middleware` that
   auto-strikes on 4xx/429 responses (configurable weights) so repeat offenders escalate to a ban.
5. **Keying:** default = socket peer IP (`req.peerAddress()` / the `on_connect` peer), formatted via
   `netaddr` (unmap v4-mapped). Directly-internet means the peer is the real client. (If deployed
   behind a trusted proxy, allow keying on the same trusted-XFF rule as `ratelimit` — optional.)

## Public API sketch (final shape your call)

```zig
pub const Guard = struct {
    pub fn init(gpa, Options) Guard;   // Options: max_conns_total, max_conns_per_ip, greylist_ttl_ms,
                                       //   ban_threshold, strike_decay_ms, max_tracked_ips, clock
    pub fn deinit(*Guard) void;
    pub fn onConnect(self) http.Server.OnConnectFn;   // + onConnectCtx() -> *anyopaque
    pub fn onConnState(self) http.Server.ConnStateFn; // decrement per-IP on .closed
    pub fn record(self, ip: netaddr.Ip, weight: u32) void;  // strike (auto-greylist/ban at threshold)
    pub fn ban(self, ip) void;  pub fn unban(self, ip) void;  pub fn isBanned(self, ip) bool;
    pub fn middleware(self) router.Middleware;   // optional auto-strike on 4xx/429
};
```

## Acceptance / verification

- **Offline unit tests (clock-injected):** ban/greylist add + TTL expiry + check; strike accumulation
  → auto-greylist at threshold → ban on repeat; strike decay over time; per-IP counter inc/dec via the
  `on_connect`/`on_conn_state` pair (drive the two fns directly with synthetic peers); global + per-IP
  cap decisions; bounded store eviction at `max_tracked_ips`; per-IP isolation; a small multi-thread
  race check on the store.
- **In-process integration (must NOT skip normally):** wire `Guard.onConnect`/`onConnState` into
  `http.Server` on `127.0.0.1:0`; open `max_conns_per_ip` concurrent keep-alive connections (all
  loopback = same IP) all served, the next **rejected at accept** (client sees connection refused/EOF,
  `activeConnections()`/per-IP count correct); `ban(127.0.0.1)` → next connection rejected;
  greylist TTL expiry re-admits. A `record`-driven auto-ban path exercised end-to-end.
- `zig build test-abuseguard` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered with `deps = &.{"http","netaddr","router"}`.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (atomics/mutex, clock_gettime errno form, StringHashMap/LRU).
- Reuse the Phase-2.1 `http.Server` hooks EXACTLY (`OnConnectFn`, `ConnStateFn`, `ConnDecision`) —
  read Server.zig for their precise signatures. Key IPs via `netaddr` (unmap v4-mapped so one client
  = one entry). Keep the reputation store separable + unit-tested without HTTP.
- Reject writes nothing (matches the server's reject posture) — a polite 503 is out of scope here.
- SPDX header + a `Provenance:` line in the README (clean-room; design refs nginx/fail2ban).
