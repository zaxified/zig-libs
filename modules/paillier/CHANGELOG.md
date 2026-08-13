# paillier — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Value-exact vs `phe`
  (python-paillier) 1.5.0. Toy key p=11,q=17: n_sq/λ/g/µ and concrete (m,r)→c
  cross-checked (`root.zig:1000,1026`, NOTICE).
- **2026-07-14** — New module: Paillier additively-homomorphic PKE (P. Paillier,
  EUROCRYPT 1999) over `std.crypto.ff`.
