# xmss — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on `XMSS/xmss-reference` (C,
  Huelsing et al.) (design reference, not a test anchor).
- **2026-07-12** — New module: XMSS — eXtended Merkle Signature Scheme (RFC 8391),
  single-tree, SHA-256 suite (`XmssSha2_10/16/20_256`) — a stateful hash-based
  signature: WOTS+ one-time sigs (chain/base-w/checksum), the L-tree.
