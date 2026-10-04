# abuseguard

IP reputation + connection-abuse defense for a **directly internet-facing**
`http.Server`. With no reverse proxy in front, the app IS the edge:
`ratelimit` bounds request *rate* per key; `abuseguard` bounds
*connections* and keeps *IP reputation*, so a misbehaving client is cut at
accept time — a reject costs the attacker only a TCP handshake and writes
nothing (the server's documented `on_connect` posture; no polite 503).

- **Model after:** nginx `limit_conn` (per-key concurrent-connection caps,
  zone-exhaustion semantics) + fail2ban (strike → temporary ban → recidive
  escalation) + Cloudflare-style IP reputation (ban/greylist lists).
- **Platform:** posix (the default clock uses the posix `clock_gettime`
  form). **Role:** server. **Concurrency:** threadsafe — internally
  synchronized (a spinlock around a hash lookup + O(1) LRU relink; Zig 0.16
  std has no io-less blocking mutex — this is the std `SmpAllocator`
  pattern, same as `ratelimit`).
- **Deps:** `http` (the Phase-2.1 server hooks), `netaddr` (IP keying),
  `router` (the optional auto-strike middleware).

Provenance: original work of the zig-libs authors (MIT) — no third-party code. Design
references: nginx `limit_conn` (BSD-2-Clause; documented behavior only) and
fail2ban (GPL-2.0; **documented behavior only — no source consulted or
copied**), plus the `ratelimit` sibling for the bounded-LRU/clock-injection
store shape.

## Layers

| Layer | What | Wiring |
|---|---|---|
| `Guard` | reputation store + admission engine (`admit`/`connClosed`, `record`/`ban`/`unban`/`greylist`) | none — pure, drivable without HTTP |
| `Guard.onConnect()` / `onConnState()` | accept-time admission + per-IP slot release on `.closed` | `http.Server.Options` hook pair |
| `Guard.middleware()` | auto-strike on 4xx/429 responses | `router.use`, register **first** |

The store never reads a wall clock on its own: time comes from
`Options.clock` (default = OS `CLOCK_MONOTONIC`), so every ban/greylist/decay
test is deterministic.

## Usage

```zig
const abuseguard = @import("abuseguard");

var guard = abuseguard.Guard.init(gpa, .{
    .max_conns_per_ip = 100, // nginx limit_conn shape; null = no cap
    .max_conns_total = 10_000, // global load shedding; null = no cap
    .ban_threshold = 5, // fail2ban maxretry
    .greylist_ttl_ms = 10 * std.time.ms_per_min, // fail2ban bantime
    .strike_decay_ms = 2 * std.time.ms_per_min, // ≈ findtime (leaky bucket)
    .ban_after_offenses = 2, // 1st offense greylists, the repeat bans
    .max_tracked_ips = 4096, // hard memory bound
});
defer guard.deinit();

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(guard.middleware()); // FIRST: must observe inner 4xx/429s
try r.use(limiter.middleware()); // ratelimit's 429s feed the guard
try r.get("/api/thing", handler);

var server = http.Server.init(io, gpa, .{
    .handler = r.handler(),
    .context = &r,
    .on_connect = guard.onConnect(), // admission at accept
    .on_connect_ctx = guard.onConnectCtx(),
    .on_conn_state = guard.onConnState(), // slot release on .closed
    .on_conn_state_ctx = guard.onConnStateCtx(),
});
```

App code can flag abuse directly — `guard.record(ip, weight)` (an auth
failure, malformed input, …) — and manage lists manually: `ban`, `unban`
(full forgiveness), `greylist(ip, ttl_ms)`, `isBanned`, `isGreylisted`.
Diagnostics: `connCount(ip)`, `totalConns()`, `trackedCount()`.

Operator controls (all keyed as described under *Keying* below):

```zig
const allow = [_]netaddr.Prefix{ netaddr.parsePrefix("192.0.2.0/24").? }; // health checker
var guard = abuseguard.Guard.init(gpa, .{
    .allow = &allow, // fail2ban ignoreip; borrowed, must outlive the Guard
    .ipv6_key_bits = 64, // default: one /64 = one client; 128 = per address
    .max_prefix_bans = 256,
});
try guard.banPrefix(netaddr.parsePrefix("203.0.113.0/24").?); // range ban
_ = guard.unbanPrefix(netaddr.parsePrefix("203.0.113.0/24").?);

// Persist bans across a restart (the caller owns the file):
const recs = try guard.snapshot(gpa); // bans, range bans, live greylists
defer gpa.free(recs);
try abuseguard.writeSnapshot(recs, writer); // "ban <prefix>" / "greylist <prefix> <ms>"
// ... after restart, per line of the file:
if (try abuseguard.parseSnapshotLine(line)) |rec| try list.append(gpa, rec);
try guard.restore(list.items);
```

## Semantics (and where they come from)

- **Admission (`on_connect`):** reject when the peer IP is banned, is
  greylisted (TTL pending), is at `max_conns_per_ip` live connections, or
  the guard counts `max_conns_total` live connections overall; otherwise
  count and accept. The per-IP count is released by the `on_conn_state`
  `.closed` event — it cannot be maintained from `on_connect` alone, which
  is exactly why the Phase-2.1 ConnState hook exists.
- **Strikes (fail2ban):** `record(ip, weight)` ≈ a failregex hit. Strikes
  decay as a leaky bucket (one strike per `strike_decay_ms` ≈ `findtime`).
  Reaching `ban_threshold` (≈ `maxretry`) is an *offense*: the balance
  resets and the IP is greylisted for `greylist_ttl_ms` (≈ `bantime`);
  reaching `ban_after_offenses` escalates to a permanent ban (≈ the
  recidive jail). `unban` clears everything.
- **Middleware:** after the chain runs, a 4xx response strikes the client
  (`strike_4xx`, default 1), a 429 strikes harder (`strike_429`, default 2;
  a `ratelimit` deny is a strong signal). 5xx/handler errors are never
  punished (the server's fault, not the client's). Register the guard
  middleware first so it wraps — and therefore observes — inner middleware
  denials and the router's own 404/405.
- **Keying:** the socket peer IP, unmapped (an IPv4-mapped IPv6 peer and
  its plain IPv4 form are **one client, one entry**, `netaddr` unmap
  semantics) and then masked to `Options.ipv6_key_bits` (default **64**:
  one subscriber is one /64, RFC 6177, so an attacker rotating addresses
  inside it shares one budget) or `ipv4_key_bits` (default 32). Live-conn
  count, strikes, ban, greylist and offenses are per such key, and every
  public function taking an `ip` masks it the same way -- so
  `max_conns_per_ip` is a cap per /64 for IPv6 clients. Set
  `ipv6_key_bits = 128` for the old per-address behaviour. Ports are
  irrelevant. The middleware
  can key on the `ratelimit` trusted-XFF chain instead
  (`Options.middleware_key = .forwarded_ip`) for behind-proxy deployments;
  header values must parse as IP literals or they fall through to the peer.
- **Allowlist (`Options.allow`):** a member of any listed prefix (matched
  after unmapping) is never rejected for reputation -- not by an entry's
  ban/greylist, not by `banPrefix` -- and `record` / the middleware's
  auto-strike do nothing for it. Caps still apply (a cap is not
  reputation). A manual `ban`/`greylist` of a member is stored but ignored
  while it stays listed; `isBanned` reports the stored state.
- **Range bans:** `banPrefix` / `unbanPrefix` (at most `max_prefix_bans`,
  linear scan per admission, checked before any entry is created so a
  rejected peer costs no store slot). Independent of the key width.
- **Persistence:** `snapshot` returns the bans, range bans and live
  greylists (remaining time rounded up); strikes and offense counts are not
  kept. `restore` puts a key-width record back as a key ban/greylist and a
  ban of another width as a range ban; a greylist of another width is
  `InvalidRecord`. The text codec is one line per record, `#` comments and
  blank lines ignored on read.
- **Bounded store (the store must not be an abuse vector itself):** at most
  `max_tracked_ips` entries. Fully-lapsed entries (no live connections, no
  ban, no offenses, greylist over, strikes decayed away) are swept from the
  LRU tail on insert; at the cap the least-recently-used evictable entry is
  dropped. Entries with live connections are **never** evicted (their loss
  would corrupt the per-IP cap); banned entries go only as a last resort.
  When nothing is evictable, new IPs are **rejected** — nginx's
  zone-exhausted semantics (nginx answers 503; we drop at the TCP level
  like every other reject). The guard is deliberately **fail-closed**
  (contrast `ratelimit`'s fail-open): an uncountable connection is exactly
  the resource being defended. Size `max_tracked_ips` ≥ `max_conns_total`.
  The default is itself a lockout vector — N addresses holding one idle
  connection each fill the store and every *new* address is refused — so
  `on_store_full = .admit_untracked` admits such an address with no entry
  (`.admitted_untracked`: no per-IP cap, ban or greylist) but still counts
  it in `max_conns_total`; set that cap when you pick it.
- **Scope:** a ban/greylist affects new admissions only; connections
  already admitted run until they close (pair with the server's
  read/write/request timeouts). Known server edge: if `http.Server` drops
  an admitted connection before serving starts (per-connection buffer OOM),
  `.closed` never fires and that IP's slot leaks by one; the guard's own
  memory stays bounded regardless.

## Verification

`zig build test-abuseguard` — offline deterministic tests (injected clock:
ban/greylist add + TTL expiry, strike accumulation → greylist at threshold →
ban on repeat, exact strike decay, per-IP counter inc/dec by driving the
`onConnect`/`onConnState` hook pair with synthetic peers, per-IP + global
cap decisions, LRU eviction at `max_tracked_ips` with live-connection
pinning + banned-last policy + empty-entry sweep, v4-mapped unification,
fail-closed OOM, an 8-thread admission race and an exact-threshold
concurrent `record` race), middleware goldens over the socket-free
`http.Server.serveStream` (4xx/429 weights, zero-weight opt-out,
forwarded-IP keying), and two in-process integrations over loopback that
only skip when loopback binding is unavailable: (1) `max_conns_per_ip`
keep-alive connections served concurrently, the next rejected at accept
(`activeConnections()` and the per-IP count agree), close → re-admit,
manual ban/unban, greylist TTL expiry re-admits (clock injected — no
sleeps), and a `record`-driven greylist→ban escalation; (2) a router with
the auto-strike middleware where three real 404s escalate a path scanner to
an accept-time rejection, then the TTL re-admits it.
