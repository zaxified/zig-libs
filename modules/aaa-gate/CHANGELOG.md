# aaa-gate — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **All three fuzz harnesses were replaying an EMPTY input, and the
  API-key one had never run its query branch at all.**

  `fuzzBearerToken`, `fuzzApiKeyPresented` and `fuzzQueryValue` opened with
  `smith.bytes(&buf)` followed by `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes`
  consumes `min(buf.len, in.len)` octets and a ranged draw then reads eight *more* as
  a little-endian u64, returning the range minimum when fewer remain — so the drawn
  length was 0 for every input a seed can carry and each extractor was handed a
  zero-length slice while the header block sat unread in `buf`.

  ⛔ `fuzzApiKeyPresented` was worse than the other two. It drew `len` and then drew
  `split` from a range bounded by `len`, so with `len == 0` **both** the header block
  and the query string were empty — and `apiKeyPresented`'s query branch, half of what
  the function does and the half the harness exists to compare against the header,
  had never executed once. A corpus alone would not have fixed that: a knob drawn
  after the byte draw reads an exhausted input and returns its range minimum for ever.
  The split now comes from the bytes themselves — a US octet (0x1F), which is not
  legal in a header block or a query string — so a seed spells out where it divides
  and `--fuzz` still drives it.

  Each harness now takes its bytes in one `smith.slice(&buf)` draw and has a corpus
  with a guard test in the ordinary lane pinning measured numbers: 19 header blocks,
  8 bearer tokens found, 37 credential octets; 18 combined seeds, 12 API keys found,
  **6 from the header side and 6 from the query side**; 16 query strings, 10 hits,
  239 value octets. Non-empty seeds went 0 → 19 / 0 → 18 / 0 → 16 and every counter
  went from 0.

  These three extractors return an optional rather than an error, so there is no
  "accepted" to count and `accepted > 0` was never available as a guard. The octet
  counts are the discriminating half: `api_key=` is a *hit* with a zero-length value,
  so a corpus of empty values would score full marks on hits while returning no octets.

- **2026-08-18** — Portability fix (`check-portable`): `Throttle.decide`'s two
  `@fieldParentPtr("node", ...)` recoveries of `*Entry` from the intrusive
  `std.DoublyLinkedList.Node` failed to compile on a 32-bit target — `Entry.last_ns`/
  `suppressed` (`u64`) give `Entry` a stricter alignment than the list node's own fields
  alone require there, so the compiler can't prove the recovered pointer's alignment from
  `tail`'s declared type. Wrapped both in `@alignCast`, safe because every `Entry` is
  allocated via `gpa.create(Entry)` (always `Entry`-aligned, `node` at offset 0) — the
  same idiom already used throughout http/ipcbus/zipstream for identical intrusive
  lists. Compile-only, identical semantics — no new test. Verified: `zig build
  portable-aaa-gate` no longer errors on this site (the module still fails that gate via
  its own live-loopback integration test's thread-spawn/`clock_gettime`
  `[wasi-surface]` gaps, unrelated to this fix) and `zig build test-aaa-gate --summary
  all` (45/45) is green.
- **2026-08-17** — Bearer parity with the API-key half, plus two escape hatches. New
  `TokenVerifyFn` + `Options.token_verify`/`token_verify_ctx`: the bearer mirror of
  `api_key_verify` — consulted after the static token set misses, outside the lock, and
  **its presence alone closes the bearer open plane** (a gate with no static tokens and a
  verifier denies even under `allow_when_unconfigured`). This is what a runtime-edited
  token file needs: without it a consumer had to mirror the external store into the gate
  on every request via `addToken`/`removeToken` diffing — retaining the secrets in
  plaintext to do so, since the gate hashes and forgets — and fake a deny-everything state
  with a sentinel token no header could present. New `Options.deny_body` /
  `deny_content_type` (default `Unauthorized\n` / `text/plain`, so the 401 is byte-identical
  unless set) let a JSON API answer denials in its own error shape instead of rewriting the
  response from an outer middleware; status, challenge, audit and throttle are unaffected.
  New `ExemptFn` + `Options.exempt`, a predicate over `*router.Ctx` that takes individual
  routes out of the protected scope whatever `protect` says — one open liveness probe on a
  service where `.mutations` would wrongly open every read; an exempt request gets no
  credential check, no identity and no audit. All three default to today's behaviour, so no
  existing consumer or test changes. Also new: an `init` test that fails the allocator at
  every index in turn — the two allocations added here extended an `errdefer` chain that
  nothing executed, let alone checked (deleting one errdefer now reports the leak).
- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this).
- **2026-07-04** — New module: Bearer + API-key auth (constant-time) + audit hook +
  denied-request throttle.
