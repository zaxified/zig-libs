# idempotency — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-12** — **Breaking (source):** `scopeKey` takes the method name (`[]const u8`,
  `Request.methodName()`) instead of `http.Method`: since http R9 every extension method is
  `.other`, and two of them must not share a cached result. qap calls it once.

- **2026-10-12** — **Pluggable record store (S3 → S2).** `Backend` (type-erased: `lookupOrReserve` / `put` / `release`, contract on the type) set through `Store.backend`; **Breaking (source):** `Store.cache` is now optional (`?*ramcache.Cache`, the in-process default, unchanged behaviour) — `store.cache.alloc` becomes `store.alloc()` (qap `src/root.zig` reads it twice; initialising with `.cache = &cache` still compiles); `Store.lease_ns`; `Store.alloc()`. `KvBackend`: durable records over `kv.Db` (`putTtl`, survive a restart), in-memory reservations with lease takeover, fail-closed 409 on an unreadable record. New dep `kv`. The sequence model-fuzz also runs over `KvBackend`; its single clock nudge became a loop (a second record could land on the TTL edge).
- **2026-10-11** — tests: seeded model-fuzz comparing random request sequences (methods, keys, bodies, callers, clock) with a linear-scan reference model of the documented decision order, plus random-input checks of `validKey`/`scopeKey`/`principalTag`/`decode`. No API or behaviour change.

- **2026-10-10** — Card Performance `n/a` with the reason (no timeable reference implementation). Docs only.

- **2026-09-21** — `decode` and `RecordedResponse` are public: a server without
  `router` reads a `Store.begin` `.replay` blob itself (status, content type,
  body) to answer the replay.
- **2026-09-21** — **A1 audit (for qap's write layer): three findings fixed, API
  changed.**
  - **F1 (HIGH): one record namespace for every caller.** Keys were scoped by
    method + path + the client's key only, so two clients picking the same key
    for the same endpoint and body shared a record: the second was handed the
    first one's response (with a different body, a 422 told it the key was in
    use). New `Options.principal` hook; the principal enters the key as a
    SHA-256 tag. Default unchanged (null = shared), loudly documented.
  - **F2 (HIGH): the per-request key lived in a thread-local.** A nested
    dispatch -- or on an evented `Io` another fiber -- reset it, the first
    request's `respond` recorded nothing, and its retry ran the side effect
    again. Now bound to the request's address inside the store. ⚠ API:
    `currentKey()`/`currentDigest()` are gone; use `store.current(ctx.req)`.
  - **F3 (MED, doc): "a missed dedup is never fatal" was false.** A full or
    evicting cache means a retry re-runs the side effect; `record` now says so.
  - **F4 (LOW):** the buffered request body is zeroed before it is freed.
  - Router-free API for servers without `router`: `Store.begin` / `finish` /
    `current`, `scopeKey`, `principalTag`, `validKey` are public.
  - Tests red before (F1 by mutation of `scopeKey`, F2 directly); lane 16/16.

- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-08** — New module: Idempotency-Key dedup of unsafe retries — a middleware +
  ramcache-backed `Store` replaying a key's cached response without re-running the
  handler.
