# sessions — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
