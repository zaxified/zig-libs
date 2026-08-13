# sessions — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
