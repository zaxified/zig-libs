# bech32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against the
  complete official BIP-173 and BIP-350 vector sets, including every invalid vector.
- **2026-07-21** — New module: Bitcoin address encodings — bech32 (BIP173) + bech32m
  (BIP350) generic codec (BCH checksum, HRP expansion, charset), segwit address
  encode/decode with the consensus rules (witness version 0–16, program 2–40 bytes,
  exactly 20 or 32 for v0, and the variant required to match the witness version), and
  base58 + base58check (double-SHA256 checksum) with P2PKH / P2WPKH-program helpers over
  `ripemd160`'s `hash160`.
