# lninvoice — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-28** — RFC 6979 deterministic-nonce ECDSA signing and public-key recovery,
  previously implemented locally here because the sibling `k256` module
  shipped only Schnorr and ECDSA *verify*, moved to `k256.ecdsa_recover`.
  This module now re-exports them, so callers are unaffected and the
  algorithm is unchanged.
