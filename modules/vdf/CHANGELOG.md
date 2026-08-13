# vdf — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: `eval` is byte-exact vs an
  independent Python `pow(5,2T,N)` oracle at T=1/5/1000 over the real RSA-2048 challenge
  modulus (`kat_test.zig:60-123`).
- **2026-07-16** — New module: Wesolowski Verifiable Delay Function over an RSA
  hidden-order group `Z_N*` (Wesolowski, IACR ePrint 2018/623).
