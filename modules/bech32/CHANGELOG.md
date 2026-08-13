# bech32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against the
  complete official BIP-173 and BIP-350 vector sets, including every invalid vector.
- **2026-07-21** — New module: Bitcoin address encodings — bech32 (BIP173) + bech32m
  (BIP350) generic codec (BCH checksum, HRP expansion, charset), segwit address
  encode/decode.
