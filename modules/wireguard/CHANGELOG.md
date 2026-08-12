# wireguard — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- `Keypair.generate` now draws its X25519 seed from `entropy.fill`
  (`std.Io.randomSecure`) instead of `io.random`, closing the last
  degrading draw in the module — `CookieChecker`'s secret and nonce were
  already moved. **Not breaking:** no signature changed and no new dep.

  Both handshake initiators (`createInitiation`, `createResponse`) mint
  their per-handshake ephemeral here, and callers use it for peer static
  identities too. The ephemeral is what makes a session's keys
  unrecoverable from the static keys alone; predictable, it hands a
  passive recorder every packet of that handshake's session. The body is
  std's `X25519.KeyPair.generate` with the seed source substituted.

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
