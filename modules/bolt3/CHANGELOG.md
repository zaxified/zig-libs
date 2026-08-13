# bolt3 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: no findings. Verified: Byte-exact vs BOLT#3 Appendix
  E (`derivePublicKey`/`derivePrivateKey`/
  `deriveRevocationPublicKey`/`deriveRevocationPrivateKey`, `root.zig:150-168`) and
  Appendix D.
- **2026-07-12** — New module: Lightning BOLT#3 key derivation — the commitment scheme's
  secp256k1 crypto pocket: per-commitment blinded keys (`basepoint + SHA256(pcp ‖
  basepoint)·G`, public + secret), the split-secret revocation.
