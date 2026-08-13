# btcp2p — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: four findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Verified: Four
  genuinely external anchors, all byte-exact.
- **2026-07-29** — New module: Bitcoin P2P wire-message codec — the message envelope
  (4-byte network magic for mainnet/testnet3/regtest/signet, 12-byte NUL-padded command,
  little-endian length, double-SHA256 checksum).
