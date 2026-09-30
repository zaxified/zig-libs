# sessions — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
