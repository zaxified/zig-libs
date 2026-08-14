# ratelimit — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Layered:** `TokenBucket` — the bare algorithm, no clock/lock/allocation, caller passes `now_ns`.
  `Limiter` — per-key buckets in a bounded LRU store (`max_keys` + idle `ttl_ms`), internally
  synchronized (spinlock around a hash lookup + O(1) LRU relink — the std `SmpAllocator` pattern,
  since Zig 0.16 std has no io-less blocking mutex), clock injected via `Options.clock` (default OS
  `CLOCK_MONOTONIC`). `Limiter.middleware()` is the `router.Middleware`. Modeled after Go
  `golang.org/x/time/rate` (float balance, lazy refill, burst cap) + nginx `limit_req`'s keyed
  store — design refs only, see NOTICE.
- **x/time/rate parity:** a fresh key's bucket starts full; refill is lazy and fractional
  (`tokens += elapsed * rate`, capped at `burst`); denials consume nothing; `retry_after_ms` rounds
  **up** so waiting exactly that long guarantees the next attempt passes.
- **Fail-open by design:** `allow` is infallible — on allocator exhaustion a *new* key is admitted
  untracked rather than rejected, so the limiter never turns OOM into an outage.
- **Client-key trust policy:** default key resolution order — rightmost element of the last
  `X-Forwarded-For` (the one part of that header a client cannot forge, since every compliant proxy
  hop appends its own observed peer) → `X-Real-IP` → the socket peer address → a shared
  `fallback_key`. `KeySource.header` falls back to the same chain when the header is absent.
- **Concurrency:** `Limiter` threadsafe; the bare `TokenBucket` single-owner.
- **`ConnectionLimiter` (conn.zig):** limits *new connections per user* from
  `http.Server.Options.on_connect` — on the accept loop, before a byte is read, so a refusal
  costs one `close()` and zero response bytes. A **user is a list of CIDR prefixes** (v4+v6,
  `netaddr.Prefix.contains`, first configured match wins, peers unmapped first) and all of a
  user's addresses share **one** bucket. **The unmap is load-bearing, not cosmetic:** a
  dual-stack listener sees `::ffff:a.b.c.d`, so without it a v4-configured customer matches
  nothing, silently loses their per-user override to the unlisted default, and — unlisted keys
  being the evictable ones — becomes flushable by address rotation; additionally every
  v4-mapped address shares the `::/64` unlisted key, collapsing all v4 clients into one bucket.
  Spell v4 users in v4 CIDR: `::ffff:0:0/96` matches nothing, by construction. The converse is
  impossible (family-strict `contains`), and unmap merges only one host's two spellings.
  Per-user `rate_per_s`/`burst` overrides the defaults
  (4/s, burst 8 — owner's ruling 2026-08-10). Unlisted addresses get those defaults **per
  address**, v6 keyed by /64.
- **Eviction cannot reach a configured user.** Listed users' buckets are a fixed array
  allocated at `init`; only unlisted keys live in the bounded LRU table. This is the whole
  point of the split: an IPv6-rotating attacker can churn the unlisted table but can neither
  reset a customer's bucket nor grow memory in a customer's name.

## Threat model / out of scope

Per-instance only: no cross-instance coordination — behind a naive N-instance load balancer the
effective limit is N× the configured rate; a distributed limiter needs a shared backend this module
does not provide. Fail-open is deliberate but means a determined allocator-exhaustion attack buys
untracked (not unlimited) admits, never a hard block — document this tradeoff to operators. The
XFF/`X-Real-IP` trust chain is only as trustworthy as the deployment: a directly-reachable client can
forge both and land in a per-client-but-attacker-chosen bucket (a key, not a bypass) — behind
multiple chained trusted proxies, or with no proxy at all, use `KeySource.custom` instead of the
defaults. Not an authentication mechanism, and not a defense against connection-level abuse
(`abuseguard` is the sibling for that; `ConnectionLimiter` covers only the *establishment rate*,
not concurrency — a peer obeying 4/s holds 240 connections after a minute, so a concurrency cap
must exist beside it, not instead of it).

`ConnectionLimiter` specifics: identity is the source address only, so it is **not**
authentication — anyone inside a listed prefix is that user, and a listed NAT gateway means the
whole site shares one bucket (deliberate; that is what "per user" means here). Spoofing is not a
threat (the TCP handshake completes first). Address rotation by **unlisted** peers is bounded but
not free: v6 rotation inside a /64 is one bucket, while an attacker with a /48 can churn the
`max_unlisted_keys` LRU table and reset *other unlisted* peers' buckets (up to `burst` extra
connections each) — configured users are unreachable that way by construction. No cross-instance
coordination here either: N instances behind a load balancer admit N× the configured rate.

## Verification

Offline deterministic: bucket math, refill and `retry_after` exactness, per-key isolation,
LRU eviction + TTL sweep, an 8-thread over-admission race check, fail-open OOM. Middleware goldens
over the socket-free `http.Server.serveStream`: 429 wire bytes, XFF/`X-Real-IP`/API-key/custom key
extraction, spoof resistance, peer-address fallback (port-insensitive, IPv4-mapped unified, headers
win over peer). In-process integration (`router` + `http.Server` + `http.Client` over loopback):
burst → 200s, then 429 + `Retry-After`, key isolation, XFF exercised, headerless requests keyed by
the loopback peer — skips only when loopback binding is unavailable.

`ConnectionLimiter`: shared bucket across two prefixes of one user (5th connection of a second
refused from either address), per-user override honored while the default user is not, unlisted
per-address isolation, /64 collapse under intra-/64 rotation, a 4096-/64 flood proving the table
stays ≤ `max_unlisted_keys` while a listed user's drained bucket survives, first-match ordering,
the `OnConnectFn` shape itself, and an 8-thread race admitting exactly `burst` — all on an
injected clock (no wall-clock sleeps anywhere in this module's tests).

The v4-mapped identity is asserted by **bucket identity, never by `.allowed`**: a fresh bucket
admits a stranger too, so `expect(allowPeer(mapped).allowed)` passes whether or not the address
matched a user. The tests drain the user over one spelling and require a **refusal** on the
other (both directions), assert `unlistedKeyCount() == 0` so a demoted customer is caught, and
repeat the whole thing through `onConnect` with an override (burst 6) larger than the unlisted
default (burst 2) so a mapped peer that fails to match is refused three connections early.

Run: `zig build test-ratelimit`.

⚠ conn.zig's tests are pulled in by an explicit `test { _ = @import("conn.zig"); }` in root.zig.
Without it Zig never analyses the file and reports a confident all-green run with that entire
suite missing — observed here as `18/18 tests passed` while 8 tests silently did not exist.

## Backlog / deferred

None beyond the documented out-of-scope items above
(distributed/cross-instance coordination is an explicit non-goal, not a v1 gap).

## Status

`gap · any · util · threadsafe` + deps: `router`, `http`, `netaddr` — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** token-bucket internal utility, no wire
