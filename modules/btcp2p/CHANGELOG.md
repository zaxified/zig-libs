# btcp2p — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — Fixed `Message.commandName()`: its receiver was `self: Message`
  (by value), but `command` is a `[COMMAND_LEN]u8` embedded in `Message` itself, so
  the returned slice pointed into the callee's own stack-local copy — dangling the
  instant the function returned. A caller reading the result immediately in the
  same expression could get away with it; one intervening call (e.g.
  `std.debug.print`) was enough to read back poisoned/garbage bytes instead of the
  command. Receiver is now `self: *const Message`. Regression test added
  (`envelope.zig`, "F2 regression").
- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Four
  genuinely external anchors, all byte-exact.
- **2026-07-29** — New module: Bitcoin P2P wire-message codec — the message envelope
  (4-byte network magic for mainnet/testnet3/regtest/signet, 12-byte NUL-padded command,
  little-endian length, double-SHA256 checksum).
