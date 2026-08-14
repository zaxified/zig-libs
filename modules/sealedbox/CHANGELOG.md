# sealedbox — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `open` (arbitrary-length, arbitrary-content ciphertext against the fixed KAT
  keypair) — `zig build check-fuzz` no longer names this module. No panic/OOB
  found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Modeled on libsodium `crypto_box_seal` /
  Go `nacl/box` (design reference, not a test anchor).
- **2026-07-07** — New module: NaCl `crypto_box_seal` — anonymous-sender X25519
  public-key encryption (thin over `std.crypto`) + base64/hex key serialization.
