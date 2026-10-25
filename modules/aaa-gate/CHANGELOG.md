# aaa-gate — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-25** — **SECURITY (hardening, consumer-visible):** a request carrying a credential field the gate reads on more than one line — two `Authorization` lines, or two lines of an API-key header — is DENIED (401), whatever either line holds. Before, the first line decided, so a valid first line admitted any second one; a proxy in front reading the other line authenticates something else than the gate does. `Authorization` is a singleton field (RFC 9110 §5.3); fiber v3 refuses the same. A mode that does not read the field ignores its repetition (an `.api_key` gate and two `Authorization` lines). Tests: `lead: two Authorization headers (or two API-key headers) are denied …`, the Basic wire test.

- **2026-10-25** — **Faster deny path, same answers:** a request with no credential is denied without taking the credential lock when the answer cannot depend on the set (a verifier configured, or `allow_when_unconfigured` off); the 401's challenge and media type are checked once at `init` and lent to every response (`http` `setHeaderBorrowed`), not checked and copied per request. `no_credential` 401: 0.97–1.17× tower-http 0.7.1 net (was 2.67× with http's own speed-ups the same day).

- **2026-10-25** — **Fixes from the A1 audit:** `addApiKey`/`removeApiKey` run under the dead-stack burn like the token and Basic entry points; `init` asserts the Basic contract `addBasicUser` asserts (no `:` in the user, a non-empty password — else `a:b`/`c` matched the pair `a`/`b:c`); `removeToken`'s doc no longer claims removing the last token reopens the plane (it does not, fail-closed). 8 tests from the mutation run, 4 `lead:` tests pinning the Authorization syntax against RFC 9110/7235/7617.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-19** — **NO CONSUMER-VISIBLE CHANGE:** Deprecated std names replaced by their Zig 0.17 spellings (`mem.indexOf*` -> `mem.find*`, `fmt.bufPrint` -> `mem.print`, `fmt.allocPrint(a, …)` -> `a.print(…)`, `bufPrintSentinel` -> `mem.printSentinel`, `@intFromEnum` -> `@backingInt`); the old names are aliases, so behaviour is identical.

- **2026-10-18** — Ported to Zig 0.17.0. No source change beyond the mechanical codemod.
- **2026-10-18** — tests: mutation audit of the echo-parity code (121/129, 8 equivalent). New: the Basic user/password boundary, the exact challenge for every mode and realm, TAB trimming, blanks around key-source values, blank `X-Real-IP`/XFF fall-through, IPv6 peer keys and the v4-mapped boundary, "a configured scheme keeps the plane closed" for every conjunct of `.any`/`.either`, the audit status of a handler error after the head was sent, and `ctx.data` restoration.
- **2026-10-18** — `cookieValue` is now `cookies.find` (new dep `cookies`; the private copy is gone). Differences: a `;` inside a quoted value no longer ends it (`sid="x;y"` → `x;y`), and a pair without `=` reads as an empty value instead of null — an empty value already counted as an absent key source, so no gate verdict changes. ctgrind counts unchanged (2/2/2), digests re-pinned.
- **2026-10-17** — Example: the `addToken` OOM step finds `Gate.init`'s allocation budget by probing instead of a literal 4 (init gained a fifth allocation, key sources, and the example's run failed in CI). Example only.

- **2026-10-17** — `global-alloc-ok` marker on the ctgrind harness's `page_allocator` (`check-global-alloc`). Tooling only.

- **2026-10-17** — **NO CONSUMER-VISIBLE CHANGE:** `addToken`, `removeToken`, `addBasicUser` and `removeBasicUser` run their body under a dead-stack burn (`src/burn.zig`, 2 KiB), so the SHA-256 state that absorbed the credential does not survive in a dead frame (`check-secret-api`). The model-fuzz scripts draw every choice as a reduced `u64` (`check-fuzz-reach` R1: ranged `Smith` draws collapsed `--fuzz` to op 0). `ct-compare` pin 5/4 (the new compares: the Basic removal scan, constant-time; a cookie-name match, public); ctgrind source digests re-pinned, contexts unchanged.

- **2026-10-17** — **NO CONSUMER-VISIBLE CHANGE:** constant-time evidence — `src/ctgrind_harness.zig` (`scripts/checks/ctgrind.sh aaa-gate`): the stored token / API-key / Basic digests tainted in place, `verify*` with a good and a bad credential; in-file 2 per target = the two verdicts, controls and traps 0; pinned in `ctgrind-expected.tsv`.

- **2026-10-17** — Benchmark: verdict now like for like (owner decision) — echo with a validator giving the same guarantee (SHA-256 digests, compare every one) → 0.11–0.87×; echo's raw-key validator printed as `_raw` information (header success rows ~2x: one software SHA-256 per request on a CPU without SHA-NI). Basic rows added. Tooling only, no code change.

- **2026-10-17** — Comparative benchmark against labstack/echo v5.4.0 `middleware.KeyAuth` (`tools/bench.zig`, `tools/go_bench/`, `zig build bench-aaa-gate`): bearer, API key in header and in query, denied and no credential, router + middleware + response over pre-parsed requests, net of a no-middleware twin; ours/echo 0.10–2.37 (x86-64; the two header-lookup success rows are over 1.1×, see `tools/README.md`). Tooling only, no code change.
- **2026-10-17** — **NO CONSUMER-VISIBLE CHANGE:** model-based fuzz harnesses `aaa-gate-verify` and `aaa-gate-throttle` (`src/model_test.zig`): the decision table under rotation (bearer, API key, Basic) and the denied-request throttle through the middleware, each against a naive model; negative control: 3 planted mutants killed; `AAA_GATE_FUZZ=200000` clean.

- **2026-10-17** — echo parity (KeyAuth + BasicAuth v5.4.0): HTTP Basic scheme (`AuthMode.basic` / `.any`,
  `Options.basic_users`/`basic_verify`, `addBasicUser`/`removeBasicUser`, `verifyBasic`,
  `basicCredentialsOf`; `WWW-Authenticate: Basic realm`, default realm `Restricted`; stored as
  SHA-256(user:password), decoded with `b64ct`; new dependency `b64ct`), ordered API-key sources
  (`Options.api_key_sources`: header with optional prefix, query, cookie; `cookieValue`), and
  `Identity.Scheme.basic`. Form-field lookup is deliberately not offered (body would be consumed).
  Fuzz harnesses for Basic header parsing and cookie extraction.

- **2026-10-12** — `http.Method` grew `.connect`, `.trace`, `.other` (http R9): under
  `protect = .mutations` TRACE is a read (RFC 9110 §9.2.1), CONNECT and any extension method are
  gated and audited like writes (fail closed).

- **2026-10-09** — tests: deterministic fuzz driver `AAA_GATE_FUZZ` over the existing harnesses (bearer token,
  bearer value, API key, query value, client key).

- **2026-10-04** — Tests: mutation schemata run (43 mutants, 42 killed, 1 equivalent).
  Four new tests: an `api_key_verify` callback alone keeps the api-key plane closed, the
  denied-audit fold count resets after each admitted entry, `Bearer` followed only by
  blanks presents no token, and `.either` with only a bearer token configured stays
  closed under `allow_when_unconfigured`. No behaviour change.
- **2026-09-17** — ⚠ **BREAKING (`KeyFn`):** `keyFor` takes a third parameter,
  `*[client_key_len_max]u8` of caller-owned scratch, and `formatPeerKey` is
  public.
  - The module doc told a directly-reachable service to set
    `Options.throttle_key` if the audit sink must be bounded against a client
    rotating a forged `X-Forwarded-For`. That extractor has to RENDER the peer
    address, and it had nowhere to put it: `router.Ctx` carries no allocator or
    scratch, a buffer owned by the `KeyFn` is shared across the server's
    per-connection threads, and a stack local does not outlive the callback.
    The mitigation was therefore only reachable via a `threadlocal` — correct
    only while one OS thread serves a connection end to end, which is a
    property of a particular server, not of this API. The buffer already
    existed at the call site and simply was not passed down.
  - Reported by a consumer running this gate on a directly-reachable service:
    20 denials with a rotating forged header produced 19 audit records against
    1 with a fixed one.
  - `throttle_key` had no test at all. It has one now, and it is the
    consumer's measurement: the same three denials with three forged headers
    give three records on the default key and one on a peer-keyed extractor,
    while two distinct peers still give two.

- **2026-09-10** — A1 audit disposition. Two open findings closed, both refuted
  against the tree (the underlying bugs were real but already fixed by the
  2026-09-01 middleware audit, `91d2744d`, outside this campaign):
  - `throttle_max_keys = 0`: audit cited a Debug-only `std.debug.assert` guarding
    a `t.lru.last.?` unwrap that ReleaseFast strips, corrupting the heap on an
    empty store. The tree already replaced the unwrap with `if (t.lru.last) |tail|`
    (no-op when there is no tail to evict). Reproduced the historical bug in a
    standalone probe copying the pre-fix `Throttle.decide`
    (`.zig-cache/probe/aaa-gate-throttle-max0.zig`, not committed — scratch):
    50 calls with `max_keys = 0` on an empty store in ReleaseFast **SIGSEGV** with
    the old unwrap, **1/1 pass** with the current tree's guarded version.
  - "An unauthenticated flood cannot flood the audit sink": the same 2026-09-01
    audit already corrected the module doc comment (`root.zig`) but never touched
    `README.md`, which still asserted the false claim three lines above its own
    correct caveat ("forged forwarding headers let a client pick its own throttle
    key"). Reworded the README paragraph to match. `rg -n "cannot flood the audit
    sink" README.md`: 1 hit before, 0 after.

  Also closed the LOW backlog item ("`fuzzBearerToken` mostly exercises
  `bearerTokenOf(null)`; `clientKeyFrom` has no fuzz target at all") left over
  from the 2026-09-07 fuzz-draw fix below: added direct string-level fuzz
  targets and pinned reach-guard tests for `bearerTokenOf` (9/10 seeds non-empty,
  4 tokens, 21 octets) and `clientKeyFrom` (8/9 seeds non-empty, 2 hit the shared
  fallback, 1 exercises the 48-byte clamp on a forged value) — `queryValue`
  already had one. `clientKeyFrom`'s peer-address fallback stays on the existing
  deterministic unit test; `std.Io.net.IpAddress` is not a byte string to draw.

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
