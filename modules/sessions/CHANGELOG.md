# sessions — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — docs: SPEC backlog notes that looking a session up by its secret id hashes and compares the id inside ramcache/kv, outside this module's ctgrind rows (from the ct review).

- **2026-10-09** — Constant time: the session id and the CSRF token were hex-encoded through a table indexed by the secret nibble (`newId`'s `"0123456789abcdef"[b >> 4]`, `std.fmt.bytesToHex` in `Csrf.token`). `Csrf.verify` also decoded the presented token, which is the secret token on a legitimate request, with the per-character branching `std.fmt.hexToBytes`. A new private `src/idhex.zig` does branch- and table-free encode/decode, with the hex-validity bit ANDed after the MAC compare instead of branched on first. Accepted inputs are unchanged (either-case hex, exhaustively cross-checked against std). New `src/ctgrind_harness.zig` (targets `csrf`, `newid`): `csrf` went from 8 to 0 in-file contexts in ReleaseFast. New test: a non-hex byte that decodes to the right nibble is rejected. No API change.

- **2026-10-09** — tests: deterministic fuzz driver `SESSIONS_FUZZ` over the existing harnesses (session-record decode, cookie header parse, each also over damaged corpus entries).

- **2026-10-09** — Dead-stack burn: `Csrf.token` and `Csrf.verify` (HMAC-SHA256 under the CSRF key) run their bodies under a 4 KiB per-message `burn.run` (new `src/burn.zig`); new `stackprobe_test.zig` on `testkit.stackprobe`. No signature change.
- **2026-10-04** — Tests: mutation schemata run (48 mutants, 45 killed, 2 equivalent, 1
  alive by design — see SPEC § Verification). Ten new tests: timeouts at their exact
  limits and the rolling `last_seen` refresh, `setData` at `max_session_bytes`, an
  oversized record from a foreign `Store` refused, `maxAgeSeconds` with the idle timeout
  off, `allow_insecure_cookie` on the wire, a regenerate-only new session persisted, a
  closed `KvStore` that can read again still serving nothing, a truncated CSRF token,
  `Csrf.presented`'s empty-header/empty-query/look-alike-name cases, `Csrf.check`
  without a session cookie. No behaviour change.
- **2026-10-01** — **Fix: `KvStore` no longer spins on its lock under a fiber/evented `Io`.**
  It held an io-less spinlock across `kv` writes (an fsync each); a second task of the same
  thread spun on it forever while the holder was suspended in the fsync. It now uses `kv.Lock`
  (`std.Io.Mutex` when the `Db`'s storage has an `Io`). Found by the zig-libs spinlock audit
  that followed the simio kv pilot.
- **2026-09-30** — `KvStore`: a persistent `Store` over a caller-owned `kv.Db`, so sessions
  survive a restart (maturity task C8). Records under `prefix ++ id` (default `"session:"`),
  generation-framed like `RamcacheStore`, CAS under its own lock, `kv` expiry refreshed by
  every save as the backstop for abandoned sessions; fails closed after any `kv` write error.
  New `Clock.realtime` (wall ns) and `Store.VTable.persistent` (default false, so existing
  vtables are unchanged); `Manager.init` returns the new `error.MonotonicClockWithPersistentStore`
  for `Clock.monotonic` over a persistent store, whose timestamps a reboot would put in the
  "future" and keep alive past the absolute timeout. New dependency: `kv`.

- **2026-09-28** — `Csrf`: the private header-then-query token extraction (`presentedToken`) is
  now public as `Csrf.presented(req)`, same extraction order, unchanged. Added
  `Csrf.check(req) bool` — the whole CSRF guard minus the middleware's 403 response: session
  cookie present, a token `presented`, and it `verify`s. Requested by qap M11.4 (2026-09-27):
  qap's own core-only sessions usage had to duplicate `presentedToken` to guard requests without
  going through `router`'s `Csrf.middleware`. `check` does **not** apply the middleware's
  safe-method exemption — it never reads `req.method` — so it cannot silently report a valid
  guard for an unchecked GET; only `middleware` special-cases safe methods. `middlewareRun` now
  calls `c.check` itself for the guarded branch instead of re-deriving the same three conditions,
  so the middleware and `check` cannot drift apart. Purely additive — no existing behavior
  changed.

- **2026-09-13** — **BEHAVIOURAL:** A1 finding LOW#1. The middleware no longer stores a session it
  created for the current request unless the handler called `setData`, the new `Session.keep()`,
  or `Manager.regenerate`; such a request gets no `Set-Cookie`. Before, every cookieless request
  stored a session, so anonymous traffic filled the bounded `RamcacheStore` and evicted logged-in
  users. Pre-auth pages that need the cookie (a `Csrf`-protected login form) must call `keep()`.
  New `Options.persist_untouched_sessions` (default `false`) restores the old behaviour.

- **2026-09-10** — A1 finding LOW#2 (documentation, no code change): documented and pinned
  with an end-to-end test that the `__Host-` cookie-name prefix (OWASP Session Management
  Cheat Sheet) is already adoptable through the existing `Options.cookie_name`/
  `Csrf.cookie_name` fields — this module's defaults (`cookie_domain = null`, `cookie_path
  = "/"`, `secure = true`) already meet the prefix's own requirements. Not made the
  default: combined with the documented `allow_insecure_cookie` dev escape hatch, a
  `__Host-`-named cookie without `Secure` is silently dropped by the browser. See
  `SPEC.md`'s "Cookie hardening" bullet.

- **2026-09-07** — Fuzz reach: neither `fuzzSessionRecordDecode` nor `fuzzCookieParse`
  reached its decoder. Both opened `smith.bytes(&buf)` and then drew the length with
  `smith.valueRangeAtMost`; `bytes` consumes `@min(buf.len, in.len)` octets and a ranged
  draw reads EIGHT more as a little-endian `u64`, returning the range MINIMUM when fewer
  remain, so the length was 0 for every input a corpus can carry — and neither had a
  corpus, so the one input each ever ran was empty. `lookup` got a zero-length record and
  answered `.absent` on its first line; `cookies.find` got an empty header. Measured
  2026-09-07: 1 round each, 0 records decoded, 0 payload octets copied, 0 ids recovered.
  ⚠ The record buffer was also `record_header_len + max_session_bytes` exactly (4112),
  one octet short of the smallest record that reaches `lookup`'s own
  `payload.len > out.data_buf.len` refusal (4113) — structurally unreachable, and a seed
  over the buffer reads back EMPTY, so no corpus could have fixed it. The buffer now
  carries 16 octets of headroom and that seed is in the corpus. Both draws are now one
  `smith.slice`: the record corpus is built at run time against `Env`'s `ManualClock`
  (live, small-payload, max-payload, oversized, absolute-expired, idle-expired,
  `maxInt(i64)` saturating, 15-octet, empty) and the cookie corpus is nine written
  headers around `default_cookie_name`. Guards pin 4 loaded / 2 expired / 3 absent and
  4101 payload octets, and 5 ids found over 124 octets.

- **2026-08-13** — Docs only, no behaviour change: the `addSetCookie` failure handling in
  `Manager.writeCookie` and `Csrf.issue` is now explicit about the whole of
  `SetHeaderError`. The comment named only `HeadersSent`, but the set was
  widened with `error.HeaderBytesExhausted` (a handler that spent the response
  writer's 4 KiB copy budget) and also carries `TooManyHeaders` and
  `InvalidHeader`. The swallow is deliberate and stays, because every case
  fails **closed**: `save` has already persisted the record and `destroy` has
  already deleted it, so a lost rolling refresh leaves the browser's current
  cookie working, a lost new-session cookie means the user is simply not
  logged in, and a lost `Max-Age=-1` clearing cookie is harmless because the
  record behind it is gone. A lost CSRF token cookie means the client cannot
  echo a token, so guarded methods are rejected rather than let through. No
  case leaves a user holding authority they should not have — which is why
  this is stated rather than escalated.
- **2026-08-12** — `Manager.newId` — the source of every session id, including the one
  `regenerate` mints on privilege change — draws through the new `entropy`
  module (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of
  `io.random`. Not breaking: `fill` returns `void`, and `newId` was and
  remains a `void` internal reached from `middleware`, which has no error
  channel either. `std.Io.random` is a CSPRNG whose contract permits a
  silent fallback to a weaker seed (`std/Io.zig:2462`) and the default
  `Io.Threaded` takes it, seeding from pid + wall clock + an ASLR pointer.
  A session id is a bearer token: guessing one *is* the session, so
  predictable ids mean session hijack across every logged-in user at once.
  It now aborts rather than hand out a guessable id. `id_bytes` and the hex
  encoding are unchanged.
- **2026-07-18** — Security audit: one finding fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
