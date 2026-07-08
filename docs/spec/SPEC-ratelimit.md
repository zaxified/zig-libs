# SPEC — `ratelimit`

**Purpose** — Token-bucket request limiting: a pure keyed limiter plus a `router` middleware
answering **429 + Retry-After**. First consumer of `router`'s `Middleware { state, run }`
interface — per-instance state (the buckets), zero globals.

**Model after / Seed** — Clean-room (token bucket + keyed store). Model after Go
`golang.org/x/time/rate` (float token balance, lazy refill, burst cap, denials consume nothing) +
nginx `limit_req`'s keyed-store shape. Design refs in `NOTICE`.

**Design & invariants**
- **Layered:** `TokenBucket` — the bare algorithm, no clock/lock/allocation, caller passes
  `now_ns`. `Limiter` — per-key buckets in a bounded LRU store (`max_keys` + idle `ttl_ms`),
  internally synchronized (spinlock around a hash lookup + O(1) LRU relink — the std
  `SmpAllocator` pattern, since Zig 0.16 std has no io-less blocking mutex), clock injected via
  `Options.clock` (default OS `CLOCK_MONOTONIC`). `Limiter.middleware()` — the `router.Middleware`.
- **x/time/rate parity:** a fresh key's bucket starts full; refill is lazy and fractional
  (`tokens += elapsed * rate`, capped at `burst`); denials consume nothing; `retry_after_ms` rounds
  **up** so waiting exactly that long guarantees the next attempt passes.
- **Fail-open by design:** `allow` is infallible — on allocator exhaustion a *new* key is admitted
  untracked rather than rejected, because the limiter must not turn OOM into an outage.
- **Client-key trust policy:** the default key resolves in order — rightmost element of the last
  `X-Forwarded-For` (the only part of that header a client cannot forge, since every compliant
  proxy hop appends its own observed peer) → `X-Real-IP` → the socket peer address → a shared
  `fallback_key` (only reachable when even the peer is unknown, i.e. `serveStream` without a
  peer). `KeySource.header` (API-key limiting) falls back to the same chain when the header is
  absent.
- **Concurrency:** `Limiter` threadsafe; the bare `TokenBucket` single-owner.

**Threat model / out of scope** — Per-instance only: each process keeps its own bucket store, no
cross-instance coordination — behind a naive load balancer with N instances the effective limit is
N× the configured rate; a distributed limiter needs a shared backend this module does not provide.
Fail-open is deliberate but means a determined allocator-exhaustion attack buys untracked (not
unlimited) admits, never a hard block — document this tradeoff to operators. The XFF/`X-Real-IP`
trust chain is only as trustworthy as the deployment: a directly-reachable client can forge both
and land in a per-client-but-attacker-chosen bucket (a key, not a bypass) — behind multiple chained
trusted proxies, or with no proxy at all, use a `KeySource.custom` extractor instead of the
defaults. Not an authentication mechanism, and not a defense against connection-level abuse
(`abuseguard` is the sibling for that).

**Verification** — 16 tests (`zig build test-ratelimit`). Offline deterministic: bucket math,
refill and `retry_after` exactness, per-key isolation, LRU eviction + TTL sweep, an 8-thread
over-admission race check, fail-open OOM. Middleware goldens over the socket-free
`http.Server.serveStream`: 429 wire bytes, XFF/`X-Real-IP`/API-key/custom key extraction, spoof
resistance, peer-address fallback (port-insensitive, IPv4-mapped unified, headers win over peer).
In-process integration (`router` + `http.Server` + `http.Client` over loopback): burst → 200s, then
429 + `Retry-After`, key isolation, XFF exercised, headerless requests keyed by the loopback peer —
skips only when loopback binding is unavailable.

**Status** — `gap · any · util · threadsafe` · deps: `router`, `http`, `netaddr`.
