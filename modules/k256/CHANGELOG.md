# k256 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-28** — New `k256.ecdsa_recover` — RFC 6979 deterministic-nonce ECDSA signing
  and public-key recovery (`Q = r⁻¹(sR - eG)`), moved here from the
  sibling `lninvoice` module, which had implemented them locally because
  `k256` shipped only Schnorr and ECDSA *verify*. `lninvoice` re-exports
  them, so its callers are unaffected; the algorithm is unchanged.
- **2026-07-21** — Security audit: three findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against
  BIP340's published test vectors.
- **2026-07-18** — Performance: gained an asm/Montgomery core (part of a collection-wide
  performance campaign that also covered the sibling `p256`/`montint`
  modules; the root changelog records no further detail than this).
