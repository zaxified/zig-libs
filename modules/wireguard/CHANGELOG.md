# wireguard — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- `CookieChecker`'s three random draws — `init` and `refresh` for the
  rotating secret `Rm`, and `createReply` for the `encrypted_cookie`
  XChaCha20 nonce — go through the new `entropy` module (`entropy.fill`,
  i.e. `std.Io.randomSecure`) instead of `io.random`. Not breaking: `fill`
  returns `void`, so all three signatures are unchanged. `std.Io.random` is
  a CSPRNG whose contract permits a silent fallback to a weaker seed
  (`std/Io.zig:2462`) and the default `Io.Threaded` takes it, seeding from
  pid + wall clock + an ASLR pointer. A predictable `Rm` makes every cookie
  forgeable, which is the whole security of the mac2 layer; a repeated
  nonce under one `Rm` leaks the XOR of two cookies. Both now fail closed.
  The deterministic test seams `initWithSecret` and `createReplyWithNonce`
  are untouched, so every KAT and replay test still supplies its own bytes.
