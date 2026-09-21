# idempotency — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
