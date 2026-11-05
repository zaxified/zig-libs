# `keycodec` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-05** — New module: PKCS#8, SEC1, PKCS#1 and SPKI key encodings with constant-time PEM, for EC (P-256/384/521, secp256k1), Ed25519/Ed448, X25519/X448, RSA/RSASSA-PSS, ML-DSA and ML-KEM; type-agnostic (a key is its algorithm plus slices of the caller's DER), so `jwt`, `acme`, `tlsserver` and `mlkem` can share one reader instead of carrying four. Anchored on 33 OpenSSL 3.5.5 keys read into the parts OpenSSL prints and written back byte for byte.
