# falcon — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against NIST Round-3 KAT's
  published test vectors.
- **2026-07-11** — New module: Full FN-DSA — Falcon-512 and Falcon-1024 (the NIST PQ
  lattice signature): verification + signing + key generation + all key/signature
  codecs, byte-exact vs the NIST Round-3 KATs for both parameter.
