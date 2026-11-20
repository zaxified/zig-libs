# `sessions` — audit record

The dated reviews and mutation runs of this module, newest first: what was read, which mutants ran, why each
survivor is equivalent, what was found and fixed. The current score is the `**Audit:**` line of the card in
[`SPEC.md`](SPEC.md); this file is the evidence behind it. A new run adds a section at the top; old sections are
not rewritten (a later run supersedes them, it does not edit them).

Runs recorded only in `CHANGELOG.md` are not repeated here (2026-11-06: the whole-module run of 520 + 10
mutants and the `CookieManager` delta audit "G"; 2026-10-28: the no-panic sweep's delta).

## 2026-11-19 — delta mutation over the paged `KvStore.iterate`

Base `04c1315c4`, `KvStore.iterate` over `kv`'s paged scan. `KvStore.init`'s `iterate_page` and `iterateImpl`; schemata, ReleaseSafe, runner filtered to the `iterate` tests: 8 mutants, 8 killed (one by the 20 s hang cap: the cursor never advancing), 0 equivalent — `Config.iterate_page` ignored (killed by the allocation-count difference between page sizes 2 and 256), the `@max(…, 1)` clamp dropped, a junk key ending the walk, `.stop` ignored, the "no more pages" return dropped, both cursor frees dropped (leaks). Card counts cumulative (494/538, 44 eq + 8/8). **Review fixes (same day):** 2 more mutants, 2 killed — the per-page `hasFailed` check dropped (killed by the mid-walk failure test's allocation count) and the default page back at 256 (killed by the default-page assertion); the field default itself is comptime and not switchable, the `Config` default reaches every caller through `init`. Card: 504/548, 44 eq.

## 2026-11-12 — whole-module review and mutation run

Whole module: production code of `root.zig`, `cookiestore.zig`, `csrf.zig`, `values.zig`, `idhex.zig`, `common.zig`; the 2026-11-06 mutant set re-applied by text fragment to the current source plus new mutants for the `clock` reads, `Store.iterate`, `RamcacheStore.currentGen`, `KvStore`'s failed-write return and `iterateImpl`'s guards; schemata in a detached copy, ReleaseSafe + one ReleaseFast build for the six `secureZero` defers (stackprobe clean at M0), strict verdict, adversarial read while placing mutants): 528 mutants, 484 killed, 44 equivalent, 0 undecided, no defect. The `Csrf` safe-path id wipe survived the instrumented build (frame moved) and was killed by a single-mutation ReleaseFast build (stackprobe residue 1013 B). New tests: `Manager.iterate` over `KvStore` skips junk keys under the prefix and walks on; the first of two entries with the same key wins in `values.locate` (a hand-built blob; the layer never writes one); `CookieManager.init` with a name and path that together outgrow a Set-Cookie line is `InvalidCookieSize` (reachable, not as the 2026-11-06 note said). Equivalent: the 42 of 2026-11-06 re-checked on the current source (logout fail-closed: head sent gives `SessionNotCleared` either way, two layers guard it; `val.len >= max_val_len` only matters for a cap over 65535, every caller uses 4096), the `monotonicNowNs` clamp (292 years of uptime), `iterateImpl`'s early return shadowed by `getImpl`'s `hasFailed`. Cut: `burn.zig`, `ctgrind_harness.zig`, the stackprobe test.

## 2026-11-01 — delta review (test code only)

A delta over `src/root.zig` (the fuzz-driver test migrated from sequential `run` calls to one `driver.runAll`, same harnesses and options), test code only; the library source the mutation run scored is unchanged.

## 2026-10-24 — review and mutation (grade-1 wave)

An independent read-only review found two
security defects, both fixed: (1) `RamcacheStore.delete` wrote a tombstone at "current + 1"; after
the cache evicted the live record that was generation 1 again, the generation a concurrent stale
save held, and the save revived the logged-out session (`delete` now removes the entry); (2) a
handler that called `revoke()` and then failed skipped the logout (now destroyed on the error path
too). Also fixed: an unchanged request's refresh made a concurrent data write lose its CAS
(`Store.touch`, generation kept; `Session.persisted`); `RamcacheStore` reported a write the cache
dropped as saved; `Max-Age=0` for a sub-second idle timeout. Judged not a defect: the CSRF token is
issued for whatever session cookie value a safe request carries — a cookie-injecting attacker gets
a valid pair for a real session of his own anyway; `__Host-` on both cookies is the defence
(documented on `Csrf.session_cookie`, with the pairing to `Options.cookie_name`). The 2026-10-04
survivor (the 64-digit length check in `Csrf.verify`) was not equivalent: a longer token verified in
ReleaseFast — test added. 60 schemata mutants over `root.zig`, `csrf.zig`, `values.zig`, `idhex.zig`
(both stores' CAS, touch, delete, landed check, `Store.touch` fallback, `persist`'s touch condition,
the middleware's error path and drop condition, expiry comparisons, cookie attributes, regenerate,
CSRF verify/presented/guard, the values codec, hex encode/decode): 56 killed, 4 equivalent —
`KvStore`'s own `hasFailed` check before a write (`kv` poisons the `Db` after a failed write and
refuses every later one itself), `timing_safe.eql` → `mem.eql` (timing only; ctgrind's job), the
last-match rule in `values.locate` (keys in a well-formed blob are unique), `val.len > max_val_len`
→ `>=` (a 65 535-byte value overflows the 4 KiB cap first). Five survivors of the first run got
tests: `touch` at generation 0 on both stores, the fallback without a `touch` slot, a save the cache
did not take, and a key aliasing bytes a replace shifts.

## 2026-10-11 — model-based differential and the values tests: negative controls

The two test families below were added on this date; the paragraphs are as written then, including the negative
controls taken (which mutation each test was shown to catch). The model has changed since: `RamcacheStore.delete`
no longer leaves a tombstone (2026-10-24), and the model's `delete` removes the key in both stores — see the
current description under *Verification* in `SPEC.md`.

**Model-based differential (2026-10-11).** Test `model: Manager over RamcacheStore and KvStore
agrees with a naive session model …` runs 200 seeds (60 in Debug) per store, each 60–180 random
operations on six handles: create + persist (the create CAS), time steps that land exactly on, one
before and one past the idle edge, `lookup`, `persist` with or without new data, a second handle on
the same id at an older generation (two racing requests), `regenerate`, `Store.delete`, and for
`KvStore` a close/reopen of the `Db`. `SessionModel` re-states the documented rules on its own: expiry
is `now − created > absolute` or `now − last_seen > idle` (strict, 0 disables) and deletes; `persist`
lands iff the generations match; `delete` bumps the generation and leaves a tombstone in
`RamcacheStore` but removes the key in `KvStore` (generation reads 0). Every result is compared:
load outcome, data, `created`, generation, the refreshed `last_seen`, and every CAS verdict and the
generation it returns. Reach (all must be hit): loaded, absent, expired by idle and by absolute
timeout, persist won and stale, regenerated, deleted, restarted. Negative controls: idle `>` → `>=`
fails it (and the exact-limit test); `RamcacheStore.delete` without the generation bump fails it
(and both cross-request race tests). The model covers the session core; CSRF stays on hand-written
examples.

**Values, remember-me, iterate, hashed keys (2026-10-11).** `values.zig` has its own tests (put/get/remove in
insertion order, in-place replace, canonical empty blob, refused puts leave the buffer untouched, a key or
value aliasing the buffer, eight malformed blobs). In `root.zig`: the `Session` values API incl. the
modified-marking and flash `BufferTooSmall` retention; raw `setData` + values = `Malformed`; **a random
operation model against a `StringArrayHashMapUnmanaged`** (put new/replace/overflow/invalid key, remove, flash
pop incl. too-small buffer, clear, raw-payload `Malformed`; every label must be reached; all entries and their
order compared after every step); the created-word codec at ±2^62 and the saturation; the three `Set-Cookie`
shapes **byte for byte** (default, `persist_cookie = false`, `rememberMe(true)`) plus the unchanged clearing
cookie; the flag through save/load on `RamcacheStore` and `KvStore` (also over a restart and a negative
clock); the middleware with `persist_cookie = false`; flash read once through the middleware; logout-everywhere
over `KvStore` (3 of A destroyed, 2 of B kept, a stale in-flight request of A cannot resurrect it, `.stop`,
expired records skipped, non-session keys skipped) and `Unsupported` over `RamcacheStore`; `hash_id_in_store`
over both stores (the raw id is not a key, the SHA-256 is; create/load/regenerate/destroy; the middleware;
`iterate` shows the 32-byte key). Fuzz: `fuzzValuesDecode`/`fuzzValuesMutated` (arbitrary and damaged blobs:
iterator, `getValue` and `putValue` must agree on `Malformed`, a failed put changes nothing) are in the
`SESSIONS_FUZZ` driver and the 400-seed reach test, with a corpus guard. Negative controls (what goes red):
the model test if `put` stopped replacing in place; `persist_cookie…three Set-Cookie shapes` if the flag were
ignored or `Max-Age` were emitted for `persist_cookie = false`; `rememberMe…KvStore` if bit 63 were dropped
or the timestamp were not sign-extended; `Manager.iterate…KvStore` if `.destroy` bypassed the generation
bump (the stale `persist` would succeed); `hash_id_in_store…RamcacheStore` if a raw id reached the store.

## 2026-10-04 — mutation run

Schemata over a copy of `root.zig` + `csrf.zig`, one ReleaseSafe
build, the whole suite): 48 mutants — both stores' CAS compare, generation bump and
tombstone, `KvStore`'s key bound, value framing, fail-closed flag (get/put/set on write
and delete errors) and TTL write, `setData`'s bound and `kept`, every `Manager.init`
check, the `Secure`/`HttpOnly` cookie attributes, `lookup`'s record checks, both timeout
comparisons and the eviction, the rolling refresh, the loaded generation, `persist`'s
generation advance, `regenerate`'s delete and generation reset, the id length,
`maxAgeSeconds`, the middleware's revoke/untouched decision, and in `csrf.zig` the token
length check, the MAC compare, `presented`'s empty-header / empty-query rules, `check`'s
missing cookie, the guard, the token cookie's `HttpOnly`, `issue_on_safe` and the query
name match. First run: 32 killed, 16 alive; ten tests added (exact timeout limits and
the rolling refresh, `setData` at the bound, an oversized record from a foreign `Store`,
`maxAgeSeconds` with the idle timeout off — RFC 6265 §5.2.2, `Secure` dropped on the
wire, a regenerate-only new session persisted, a closed `KvStore` with a readable disk,
a truncated CSRF token, `presented`'s empty/look-alike cases, `check` without a cookie);
rerun: 45 killed, 2 equivalent, 1 alive. Equivalent: a tombstone served as an empty
record (`lookup` refuses any record shorter than its 16-byte header), and `KvStore.put`
on a closed store (`kv` refuses every write once poisoned, so the write fails and returns
null anyway). Alive: dropping `Csrf.verify`'s 64-digit length check — a shorter even-length
token leaves the rest of the decode buffer uninitialised, so the outcome depends on stack
garbage (the added test asserts the contract; it kills the mutant only when the garbage
differs from the MAC tail, which it did not here). The check stays; it is what makes
`verify` independent of that garbage. No defect found.

## 2026-07-10 — adversarial security review

(adversarial security pass, alongside `aaa-gate`/`jwt`/`acme`/
`snmp.usm`/`kv`/`http`/`sealedbox`/`hashdigest`) — `sessions` is server-side auth-adjacent state
(session identity + CSRF): session-fixation and logout-resurrection issues (HIGH) plus an
id-entropy floor were found and fixed; the cross-request race was separately resolved via CAS
(commit `c1bc3d7`).
