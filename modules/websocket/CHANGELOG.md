# websocket — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  6455 §5.7's published test vectors.
- **2026-07-22** — New module: RFC 6455 WebSocket — opening handshake + frame layer
  (masking direction enforced, fragmentation, control frames, UTF-8 validation, close
  codes, per-frame + aggregate size caps), transport-agnostic.
