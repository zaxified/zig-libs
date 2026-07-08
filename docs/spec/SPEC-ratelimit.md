# SPEC — `ratelimit`

Rate limiting as a `router` middleware (and a standalone limiter). Web/API cluster (T5.2).
`gap · any · util · tsafe`. Model after: Go `golang.org/x/time/rate` (token bucket) + nginx
`limit_req` (sliding window). Deps: `router`, `http`. New `build.zig` entry
`.{ .name = "ratelimit", .deps = &.{ "router", "http" } }`.

## Why

Anything internet-facing (behind Caddy) needs per-client request limiting. This is the first
consumer of `router`'s `Middleware { state, run }` interface — it proves per-instance state
(buckets) works without globals.

## Scope

1. **Algorithm (standalone, clock-injected, no globals):** a **token bucket** limiter
   (`rate` tokens/sec, `burst` capacity) — the primary. Optionally a fixed/sliding **window**
   counter variant. Time comes from a caller-supplied monotonic clock (a `now_ns` fn or a clock
   struct) so tests are deterministic — do NOT read the wall clock internally at the algorithm
   layer. (Zig 0.16: no `std.time` timestamps; the default production clock uses
   `std.posix.clock_gettime(.MONOTONIC)` — inject it, don't hardcode.)
2. **Keyed store:** per-key buckets in a bounded map (cap + LRU/expiry eviction so idle keys don't
   grow memory). Thread-safe (a mutex is fine; document it) — middleware runs on many connection
   threads. Do NOT depend on `ramcache` (not built yet); a small internal bounded map is fine.
3. **Key function:** configurable `keyFor(*Ctx) []const u8` — default = client IP. Behind Caddy the
   real client is in a forwarded header; support `X-Forwarded-For` (rightmost/leftmost policy —
   pick one, document; behind a trusted proxy leftmost is the client) / `X-Real-IP`, with a
   fallback to the connection peer. Also allow an API-key header as the key.
2. **Middleware:** `middleware(*Limiter) router.Middleware` — on allow → `next`; on deny → **429**
   with a **`Retry-After`** header (seconds until a token frees) and a short body; do NOT call next.
   Standard rate-limit headers (`RateLimit-Limit`/`-Remaining`/`-Reset`, IETF draft) are a nice-to-have.

## Public API sketch (final shape your call)

```zig
pub const Limiter = struct {
    pub fn init(gpa, Options) Limiter;   // Options: rate_per_s, burst, max_keys, ttl, clock, key_fn
    pub fn deinit(*Limiter) void;
    pub fn allow(self, key: []const u8) Decision;         // { allowed: bool, retry_after_ms: u64, remaining: u32 }
    pub fn middleware(self) router.Middleware;            // 429 + Retry-After on deny
};
```

## Acceptance / verification

- **Offline unit tests (deterministic, injected clock):** token-bucket math — burst allowed then
  throttled, refill over time, `retry_after` correctness; per-key isolation (key A throttled doesn't
  affect key B); eviction when `max_keys` exceeded; window variant if implemented; concurrent
  `allow` from multiple threads doesn't corrupt state (spawn a few threads, assert invariants).
- **In-process integration (via `router` + `http.Server` + `http.Client`, must NOT skip normally):**
  a route behind the limiter middleware — first N requests 200, next → **429 with Retry-After**;
  a different key still 200. `X-Forwarded-For` key extraction exercised.
- `zig build test-ratelimit` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check`
  clean. Registered in `build.zig` (`deps = &.{"router","http"}`).

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (clock_gettime, threads/mutex, ArrayList unmanaged, StringHashMap).
- Reuse `router.Middleware { state, run }` (the state pointer = your `*Limiter`) and `router.Ctx`
  (req/res). Get the peer/forwarded IP from the request headers.
- Keep the pure algorithm (bucket + keyed store) separable and unit-tested independently of HTTP —
  it's reusable beyond the middleware.
- Document the XFF trust policy clearly (it's a security-relevant choice behind a proxy).
