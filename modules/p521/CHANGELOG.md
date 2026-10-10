# `p521` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — New module: NIST P-521 (secp521r1) — Mersenne field,
  Montgomery scalars, complete-formula group, constant-time ECDH and
  ECDSA-P521 with RFC 6979 nonces, std `P384`/`Ecdsa`-shaped API. Anchored to
  NIST CAVP (186-4 ECDSA SigVer/SigGen/KeyPair/PKV, ECC CDH), Wycheproof
  (ECDH, ECDSA DER + P1363), RFC 6979 A.2.7 and an OpenSSL 3.5.5 oracle.
