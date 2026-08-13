# rsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — Test-only, neither BREAKING nor BEHAVIOURAL. Removed `test "rsa
  module compiles"`, whose body was `try testing.expect(true)`. It forced nothing —
  this file is already the test root and carries 76 other tests — so all it did was
  make the module's test count larger than its coverage. The fourth and last copy of
  a tautology that came from `modules/_template`, which no longer ships one.

- **2026-07-18** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Byte-exact vs OpenSSL.
  `signPkcs1v15` matches OpenSSL SHA-256/384/512 known answers (`root.zig:2171`).
- **2026-07-10** — New module: Pure-Zig RSA (PKCS#1 v2.2, RFC 8017) over
  `std.crypto.ff`.
