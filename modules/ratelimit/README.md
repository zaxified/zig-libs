# ratelimit

Token-bucket request limiting: a pure keyed limiter plus a `router`
middleware answering **429 + Retry-After**. First consumer of `router`'s
`Middleware { state, run }` interface — per-instance state (the buckets),
zero globals.

- **Model after:** Go `golang.org/x/time/rate` (token bucket: float token
  balance, lazy refill, burst cap, denials consume nothing) + nginx
  `limit_req`'s keyed-store shape.
- **Platform:** any. **Role:** util. **Concurrency:** threadsafe — the
  `Limiter` is internally synchronized (a spinlock around a hash lookup +
  O(1) LRU relink; Zig 0.16 std has no io-less blocking mutex — this is the
  std `SmpAllocator` pattern). The bare `TokenBucket` is single-owner.
- **Deps:** `router`, `http`, `netaddr` (peer-IP key formatting).

Provenance: clean-room (token-bucket + keyed store). Design references only, no
source consulted or copied: `golang.org/x/time/rate` (BSD-3-Clause, The Go
Authors) and nginx `limit_req` (BSD-2-Clause).

## Layers

| Layer | What | I/O, clock, locking |
|---|---|---|
| `TokenBucket` | the bare algorithm | none — caller passes `now_ns` |
| `Limiter` | per-key buckets, bounded LRU store | injected `Clock`, internal lock |
| `Limiter.middleware()` | `router.Middleware`, 429 + `Retry-After` | key from request headers / socket peer |
| `ConnectionLimiter` | new **connections** per **user**, for `on_connect` | injected `Clock`, internal lock |

The algorithm never reads a wall clock: time comes from `Options.clock`
(default = OS `CLOCK_MONOTONIC`), so tests are fully deterministic
(`Limiter.allowAt(key, now_ns)` is the explicit-instant entry point).

## Usage

```zig
const ratelimit = @import("ratelimit");
const router = @import("router");

var limiter = ratelimit.Limiter.init(gpa, .{
    .rate_per_s = 5, // sustained tokens/second per key
    .burst = 10, // bucket capacity per key
    .max_keys = 4096, // memory bound: LRU-evicted beyond
    .ttl_ms = 10 * std.time.ms_per_min, // idle keys dropped/reset
    // No default (deliberately — see "Client-key trust policy" in root.zig):
    // pick `.forwarded_ip` only behind a trusted reverse proxy that always
    // sets X-Forwarded-For/X-Real-IP; a directly internet-facing server
    // MUST use `.custom` straight to the socket peer instead, or a client
    // can forge its way into a fresh bucket per request.
    .key = .forwarded_ip, // or .{ .header = "X-Api-Key" } / .custom
});
defer limiter.deinit();

var r = router.Router.init(gpa);
defer r.deinit();
try r.use(limiter.middleware()); // before routes (chi rule)
try r.get("/api/thing", handler);
```

Allowed requests flow to the handler untouched. Denied requests get **429**
with `Retry-After` (whole seconds, rounded up, ≥ 1), the IETF draft
`RateLimit-Limit` / `RateLimit-Remaining` / `RateLimit-Reset` headers, and a
short `text/plain` body; the rest of the chain never runs.

The keyed store is bounded: at most `max_keys` entries, least-recently-used
evicted first (an evicted key seen again starts over with a full bucket),
plus an idle TTL that releases memory early and resets long-idle keys.
`allow` is infallible — on allocator exhaustion a *new* key is admitted
untracked (fail-open: the limiter must not turn OOM into an outage).

## Client-key trust policy (X-Forwarded-For / socket peer) — security relevant

The default key (`KeySource.forwarded_ip`) is the client IP — as established
by a trusted reverse proxy when one is in front, or the **socket peer
address** when the server faces the internet directly. Resolution order
(`ratelimit.clientKey`, reusable by other middleware):

1. **Rightmost element of the last `X-Forwarded-For` header.** Every
   compliant proxy hop *appends* the peer address it observed, so the final
   element of the final header line was written by the nearest — trusted —
   proxy and is the only part of the header a client cannot forge. Leftmost
   elements (and any extra `X-Forwarded-For` lines the client sent) are
   attacker-supplied and deliberately ignored. A client "spoofing"
   `X-Forwarded-For: 8.8.8.8` still lands in its own real-IP bucket.
2. **`X-Real-IP`** as a fallback for proxies that set it instead
   (nginx-style). Only trustworthy when the proxy overwrites it — a client
   that can reach the server directly can forge it freely.
3. **The socket peer address** (`http.Server.Request.peerAddress()`) — the
   real client in a direct-internet deployment. The key is the IP only
   (ports vary per connection, so one client stays one bucket) and
   IPv4-mapped IPv6 peers key as their plain IPv4 form (dual-stack
   listeners see one client, one bucket).
4. **`ratelimit.fallback_key`** — one shared bucket, only reachable when
   even the peer is unknown, i.e. driving the codec socket-free
   (`serveStream` without `StreamOptions.peer`). A socket-served request
   always has a peer.

**Caveat for direct exposure:** a directly-reachable client can send forged
`X-Forwarded-For` / `X-Real-IP` headers and steps 1–2 will honor them. That
still yields a per-client bucket (it is a key, not a bypass), but if you are
*not* behind a proxy that always sets XFF, prefer a `KeySource.custom`
extractor that goes straight to `req.peerAddress()`, or strip those headers
at the edge. If you chain *multiple* trusted proxies, the rightmost entry is
your outermost proxy's peer, not the client — supply a `KeySource.custom`
extractor that walks the chain past your own hops.

`KeySource.header` (API-key limiting) uses the named header's value as the
key and falls back to the forwarded-IP chain when the header is absent.

## Connection-establishment limiting (`ConnectionLimiter`) — security relevant

A different question from the one above: not "how many requests may this
client send" but **"how fast may this user open new connections"**. It runs
in `http.Server.Options.on_connect`, on the accept loop, **before a byte is
read** — the only place a connection can be refused for the price of one
`close()` and zero response bytes.

```zig
const acme_v4 = netaddr.parsePrefix("192.0.2.0/24").?;
const acme_v6 = netaddr.parsePrefix("2001:db8:1::/48").?;
const users = [_]ratelimit.ConnUser{
    // Both prefixes are the SAME user → one shared bucket.
    .{ .name = "acme", .prefixes = &.{ acme_v4, acme_v6 } },
    // Per-user override.
    .{ .name = "bulk", .prefixes = &.{bulk_v4}, .rate_per_s = 50, .burst = 100 },
};
var conn_limit = try ratelimit.ConnectionLimiter.init(gpa, .{
    .users = &users,
    .rate_per_s = 4, // default: 4 new connections/s per user
    .burst = 8,      // …plus 8 of headroom
});
defer conn_limit.deinit();

var server = http.Server.init(io, gpa, .{
    .handler = r.handler(),
    .context = &r,
    .on_connect = ratelimit.ConnectionLimiter.onConnect,
    .on_connect_ctx = &conn_limit,
});
```

- **Identity = a list of CIDR prefixes.** No mTLS, no JWT — nothing but the
  peer address exists yet. Prefixes, not single addresses: every address of
  a user shares **one** bucket, otherwise "4/s per user" is really "4/s per
  address" and means nothing to anyone with a /24. First configured match
  wins, so a specific prefix listed before its enclosing range works.
- **Dual-stack peers are unmapped before matching.** A dual-stack listener
  is handed `::ffff:192.0.2.7` for a v4 client, and that must reach the same
  bucket as plain `192.0.2.7`. Skipping the unmap is a silent bypass, not a
  cosmetic bug: a customer configured with v4 prefixes stops matching at
  all, falls through to the *unlisted* default (so their per-user override
  quietly does not apply), and — since only unlisted keys are evictable —
  becomes flushable by the very address-rotation flood the fixed-array
  design exists to stop. On top of that every v4-mapped address shares the
  `::/64` key, so all v4 clients would collapse into **one** unlisted
  bucket and any single one of them could starve the rest.
  **Consequence for operators:** spell a v4 user in **v4 CIDR**.
  `::ffff:0:0/96` matches nothing, precisely because peers are unmapped
  first. The reverse never happens: `Prefix.contains` is family-strict, so
  a v4 peer cannot fall into a v6 customer's bucket, and unmap merges only
  the two spellings of one host — two different addresses keep two buckets.
- **Unlisted addresses get a defined default**, `rate_per_s`/`burst`, **per
  address** — never one shared bucket (that would let a single stranger
  starve every other stranger), never "unlimited", never "denied".
- **IPv6 rotation.** Unlisted v6 peers are keyed by their **/64**
  (`unlisted_v6_bits`), the standard single-host allocation, so rotating
  inside one — the free case — is a single bucket. Unlisted v4 keys per
  address (`unlisted_v4_bits = 32`).
- **The table is bounded** at `max_unlisted_keys` (LRU + idle TTL). **What
  an attacker gets, plainly:** with a /48 they still hold 2^16 distinct /64s
  and can churn the unlisted table, evicting *other unlisted* keys — an
  evicted key restarts full, so a flood can hand other strangers up to
  `burst` extra connections. What they cannot touch is a **configured
  user**: listed users' buckets live in a fixed array allocated at `init`,
  never in the evictable table, so no amount of rotation resets a customer's
  limit or grows memory on their behalf.
- **Not a spoofing concern** — the TCP handshake completes before the hook
  runs, so the peer address is real. **NAT is solved for listed users only**:
  a company behind one address gets its own bucket because it is listed;
  unlisted traffic behind a shared address shares that address's bucket.

## Semantics notes (x/time/rate parity)

- Bucket starts **full** (a fresh key gets its whole burst).
- Refill is lazy and fractional: `tokens += elapsed * rate`, capped at
  `burst`; one token per request; **denials consume nothing**.
- `Decision.retry_after_ms` is rounded **up**, so waiting exactly that long
  guarantees the next attempt passes (absent other traffic).
- `RateLimit-*` headers appear on 429 responses only: `http.Server`'s
  `ResponseWriter` retains header slices until the head hits the wire, which
  on allowed responses happens after the middleware frame is gone — only the
  deny path (which finalizes the response itself) can carry per-request
  numbers safely.

## Verification

`zig build test-ratelimit` — for `ConnectionLimiter`: two addresses of one
user sharing a bucket (the 5th connection of a second refused from either),
a per-user override actually overriding while the default user does not,
unlisted addresses limited and isolated from one another, rotation inside a
/64 collapsing to one bucket, and a 4096-/64 flood leaving the table bounded
and a listed user's drained bucket untouched — all on an injected clock, no
sleeps. Plus offline deterministic tests (bucket math, refill
and `retry_after` exactness, per-key isolation, LRU eviction + TTL sweep, an
8-thread over-admission race check, fail-open OOM), middleware goldens over
the socket-free `http.Server.serveStream` (429 wire bytes, XFF/X-Real-IP/
API-key/custom key extraction, spoof resistance, peer-address fallback —
port-insensitive, IPv4-mapped unified, headers win over peer), and an
in-process integration run (`router` + `http.Server` + `http.Client` over
loopback: burst → 200s, then 429 + `Retry-After`, key isolation, XFF
exercised, headerless requests keyed by the loopback peer) that only skips
when loopback binding is unavailable.
