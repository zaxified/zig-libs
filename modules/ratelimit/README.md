# ratelimit

Token-bucket request limiting: a pure keyed limiter plus a `router`
middleware answering **429 + Retry-After**. First consumer of `router`'s
`Middleware { state, run }` interface — per-instance state (the buckets),
zero globals.

- **Status:** `gap`.
- **Model after:** Go `golang.org/x/time/rate` (token bucket: float token
  balance, lazy refill, burst cap, denials consume nothing) + nginx
  `limit_req`'s keyed-store shape.
- **Platform:** any. **Role:** util. **Concurrency:** threadsafe — the
  `Limiter` is internally synchronized (a spinlock around a hash lookup +
  O(1) LRU relink; Zig 0.16 std has no io-less blocking mutex — this is the
  std `SmpAllocator` pattern). The bare `TokenBucket` is single-owner.
- **Deps:** `router`, `http`, `netaddr` (peer-IP key formatting).

## Layers

| Layer | What | I/O, clock, locking |
|---|---|---|
| `TokenBucket` | the bare algorithm | none — caller passes `now_ns` |
| `Limiter` | per-key buckets, bounded LRU store | injected `Clock`, internal lock |
| `Limiter.middleware()` | `router.Middleware`, 429 + `Retry-After` | key from request headers / socket peer |

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
    // .key = .{ .header = "X-Api-Key" },  // or .forwarded_ip (default) / .custom
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

`zig build test-ratelimit` — offline deterministic tests (bucket math, refill
and `retry_after` exactness, per-key isolation, LRU eviction + TTL sweep, an
8-thread over-admission race check, fail-open OOM), middleware goldens over
the socket-free `http.Server.serveStream` (429 wire bytes, XFF/X-Real-IP/
API-key/custom key extraction, spoof resistance, peer-address fallback —
port-insensitive, IPv4-mapped unified, headers win over peer), and an
in-process integration run (`router` + `http.Server` + `http.Client` over
loopback: burst → 200s, then 429 + `Retry-After`, key isolation, XFF
exercised, headerless requests keyed by the loopback peer) that only skips
when loopback binding is unavailable.
