# adaptor — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Modeled on
  `secp256kfun schnorr_fun::adaptor` (Rust, named design ref) (design reference, not a
  test anchor).
- **2026-07-12** — New module: Schnorr adaptor signatures (scriptless scripts / the
  crypto behind Lightning PTLCs + atomic swaps) over BIP340.
