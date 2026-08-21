# lninvoice — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-21** — No behaviour change: recorded why the 65-byte signature `assert` in
  `decode` is an invariant rather than a bounds check (the `data.len < 7 + 104` rejection
  above it makes the slice exactly 104 quintets), so a future fail-open sweep does not
  re-flag it.

- **2026-08-06** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against
  BIP-340's published test vectors.
- **2026-07-28** — RFC 6979 deterministic-nonce ECDSA signing and public-key recovery,
  previously implemented locally here because the sibling `k256` module
  shipped only Schnorr and ECDSA *verify*, moved to `k256.ecdsa_recover`.
  This module now re-exports them, so callers are unaffected and the
  algorithm is unchanged.
