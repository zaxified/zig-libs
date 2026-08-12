# sessions — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- `Manager.newId` — the source of every session id, including the one
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
