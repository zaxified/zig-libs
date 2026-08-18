# rsa — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-18** — Portability fix (`check-portable`): `eksBlowfishSetup`'s
  `const n = @as(usize, 1) << cost;` (`cost: u6`, the bcrypt_pbkdf expensive-schedule
  round count) failed to compile on a 32-bit target, where `Log2Int(usize)` is `u5` and
  can't hold every value the public `cost: u6` parameter allows. `n` is an iteration
  count, not a memory-sized quantity, so retyped it (and the loop counter `i`) as fixed-
  width `u64` — the direction that keeps `cost`'s full advertised 0..63 range on every
  target, rather than narrowing the type derived from `usize` and silently capping
  `cost` at 31 on 32-bit hosts. Compile-only for every `cost` value already in use here
  (`bcryptHash` always calls it with the hardcoded `cost = 6`); no behavioural test
  added since no exercised input changes result. Verified: `zig build portable-rsa`
  still reports unrelated wasi-surface failures (`os.linux.VDSO`,
  `process.Environ.GlobalBlock.view`) — out of scope for this fix — but the `u5`/`u6`
  diagnostic this fix targeted is gone; `zig build test-rsa --summary all` still 75/76
  (1 pre-existing skip).
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
