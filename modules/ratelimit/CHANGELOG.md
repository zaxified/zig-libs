# ratelimit — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-31** — **CONSUMER-VISIBLE (additive):** `TrustedProxies` (`none`, `loopback`, `set: *const netaddr.IpSet`), `clientIp(req, trusted) ?netaddr.Ip` and `KeySource.forwarded_ip_trusted`: `X-Forwarded-For`/`X-Real-IP` count only when the socket peer is a trusted proxy; the last XFF line is walked from the right past trusted hops to the first untrusted address, a non-address entry stops at the hop to its right, a `:port` is dropped, IPv4-mapped is v4. For a server reachable both through its proxy and directly (asked for by zpinger, whose `viewerOf` did this by hand). `forwarded_ip` and `clientKey` unchanged. SPEC backlog entry closed.

- **2026-10-29** — **NO CONSUMER-VISIBLE CHANGE:** Delta audit of the no-panic sweep: 7 mutants over the changed code: 5 not scored (`checkConfig` is a checked panic), 2 equivalent (a null `.?` panics either way). The sweep added no other behaviour, so no test was needed. Checked panics are not mutated (a test cannot observe a panic in-process). Cumulative 55/61, 6 eq. Card A1 again.
- **2026-10-28** — **Fix (no-panic sweep):** no consumer-reachable panic or UB (coordinator pass, `~/CML/20261028-panic-sweep/ratelimit-sweep.report.md`). `TokenBucket.allowNAt`/`reserveNAt` check the caller's config in every build mode (an `assert`, UB in ReleaseFast); the middleware with no `state` and `ConnectionLimiter.onConnect` with no context are checked panics instead of `.?`.
- **2026-10-24** — **SECURITY fix (over-admission):** the idle TTL reset an expired key to a full bucket even when the bucket could not have refilled in that time — 5/hour with the default 10-minute TTL admitted 5 more every 10 minutes. The effective TTL is now at least the refill time `burst / rate_per_s` (`Options.ttl_ms` doc). **Behaviour change:** the middleware's `forwarded_ip` key (and the `header` source's fallback to it) keys an IPv6 client by its /64 (new `Options.v6_key_bits = 64`; 128 restores per-address keys) and renders every address key canonically (`::1` = `0:0:0:0:0:0:0:1`, v4-mapped = v4) — a host rotating through its /64 got a fresh bucket per address. **Behaviour change:** eviction at `max_keys` is second chance (CLOCK, an LRU approximation) instead of exact LRU: a hit only marks the key; the keyed decision is ~20 % cheaper. **Behaviour change:** `Limiter.init`, `setConfigAt` and `ConnectionLimiter.init` panic on an invalid configuration in every build mode (it was `std.debug.assert`, unchecked in release); new `optionsError` (both) and `validRate` say why. Docs: `KeySource.header` must sit behind authentication; `waitN` is fail-open on OOM. Internal: one allocation per key (entry + key bytes), hashing and the `Decision` math outside the lock. Tests: model-fuzz against an exact integer model (decisions, eviction, TTL, `setConfigAt`); mutation run. Tools: `tools/rust_fast_bench` (governor 0.10.4) in the bench, `tools/lead_probe` (x/time/rate's repeated `CancelAt`). Grade 1.

- **2026-10-19** — **Fix:** `ConnectionLimiter` matched configured user prefixes literally while peers are `unmap`ped, so a user configured as a v4-mapped v6 prefix (`::ffff:192.0.2.0/120`, `::ffff:0:0/96`) never matched a v4 peer and fell into the unlisted pool under the default limits. Prefixes of /96 or longer in the mapped range are now canonicalised to the v4 prefix they denote (as abuseguard does). Test: `ConnectionLimiter: unmapping never merges two distinct peers` (extended).

- **2026-10-18** — **NO CONSUMER-VISIBLE CHANGE:** Docs: README/SPEC statements that Zig has no io-less blocking mutex / `std.Thread` primitives re-checked against the 0.17.0 std (still true).

- **2026-10-11** — x/time/rate parity: `TokenBucket.allowNAt`/`reserveNAt`/`cancelAt`/`tokensAt`/`advanceAt`, `Reservation`; `Limiter.allowN`/`allowNAt`, `waitN` (sleeps on an `Io`; `WaitError`), `setRate`/`setBurst`/`setConfigAt`, `currentConfig`. `Decision` gains `limit` (the burst it was made against; the middleware's `RateLimit-Limit` now reads it, so a concurrent `setBurst` is not a data race) and `retry_after_ms = maxInt(u64)` for `n > burst`. `TokenBucket.tokens` may be negative while reservations are outstanding; `TokenBucket` gains `last_event_ns` (defaulted). A pending reservation keeps its key from the idle-TTL reset. Anchored on 10 captured x/time/rate operation sequences (`src/xrate_ops_vectors.zig`, driver `tools/xrate/ops.go`). Deliberate differences: a second `cancelAt` is a no-op (x/time/rate v0.15.0 restores again), `waitN` cancelled via `io` keeps the tokens.

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-ratelimit`, kept instrument kind 3): card Performance 0.08–0.38× golang.org/x/time/rate, measured on a quiet host. Tooling only, no code change.

- **2026-09-17** — ⚠ **BREAKING (`KeyFn`):** `keyFor` takes a third parameter,
  `*[peer_key_len_max]u8` of caller-owned scratch. Same defect as the sibling
  `aaa-gate`, found while fixing that one: this module's doc has always said
  that a directly-reachable deployment should "use a `KeySource.custom`
  extractor that goes straight to `req.peerAddress()`", and that extractor had
  nowhere to render the address. The buffer already existed at the `.custom`
  call site and was not passed down. `example-apps/http-service` followed the
  advice with a `threadlocal` buffer, which this change lets it drop.

- **2026-09-09** — Docs: `src/xrate_vectors.zig` had no `SPDX-License-Identifier`. It was the
  one file where that mattered — a corpus captured from an external project, with the one
  line that says whose terms apply to the FILE missing. Added, and `zig build check-catalog`
  now refuses any shipped `.zig`/`.c`/`.h` under `modules/**` without one.
- **2026-08-18** — Portability fix (`check-portable`): `Limiter.allowAt`'s two
  `@fieldParentPtr("node", ...)` recoveries of `*Entry` from the intrusive
  `std.DoublyLinkedList.Node` failed to compile on a 32-bit target, same root cause as
  aaa-gate's identical pattern: `Entry.bucket.updated_ns` (`u64`) gives `Entry` a
  stricter alignment than the list node's own fields require there. Wrapped both in
  `@alignCast`, safe because every `Entry` is allocated via `gpa.create(Entry)` (always
  `Entry`-aligned, `node` at offset 0) — matching the idiom already used throughout
  http/ipcbus/zipstream/aaa-gate. Compile-only, identical semantics — no new test.
  Verified: `zig build portable-ratelimit` no longer errors on this site (the module
  still fails that gate via its own live-loopback integration test's thread-spawn/
  `clock_gettime` `[wasi-surface]` gaps, unrelated to this fix and not in scope here) and
  `zig build test-ratelimit --summary all` (32/32) is green.
- **2026-08-13** — Test-only, no behaviour change: two regression tests close a coverage gap the
  2026-08-13 `end()` entry below left open. (1) `"middleware: an OUTER middleware writing after
  next.run still lands its header"` pins the property that entry's prose claims — reverting to the
  pre-fix early `end()` now turns this test (and only this test) red, 31/32; `throttle` and `cors`
  got the identical test when they copied the same fix, this module (where the fix originated,
  `6ba5d7d`) had neither it nor a dead-frame test until now. (2) `"middleware: 429 Retry-After/
  RateLimit-* values survive the caller's dead frame"` pins that `retry_buf`/`limit_buf`/`reset_buf`
  — formatted on `middlewareRun`'s stack frame — depend on `http`'s `ResponseWriter.setHeader`
  copying their bytes rather than borrowing the caller's; verified by fault-injecting `http`'s
  `dupe` to return the input slice unchanged, which turns this test red alongside 7 sibling
  dead-frame tests across the collection (`router`, `tracecontext`, `sessions`, `csrf`, `cookies`,
  `throttle`, `http`'s own). Both mutations reverted, tree confirmed byte-identical (`cmp`).
- **2026-08-13** — **BEHAVIOURAL, not breaking** — the 429 deny path no longer forces an early
  `ResponseWriter.end()`. The `Retry-After` and `RateLimit-*` values are
  formatted on the middleware's stack frame and the early `end()` existed only
  to beat that frame's death; `http`'s `setHeader` copies those bytes now.
  **What changes for a consumer:** the 429 head reaches the wire when the
  serving loop ends the response, not inside the middleware — so an *outer*
  middleware that works after `next.run` can still touch it. That is the point
  rather than a side effect: `sessions` saves its cookie there and `csrf`
  issues its token there, and on a 429 both writes were being swallowed as
  `error.HeadersSent`. The status, headers and body of the 429 are unchanged.
- **2026-07-19** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on Go
  `golang.org/x/time/rate` (token bucket) + nginx `limit_req` (keyed store) (design
  reference, not a test anchor).
