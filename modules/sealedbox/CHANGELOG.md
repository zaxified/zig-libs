# sealedbox — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-23** — **Behavioural:** `seal` returns `error.InvalidBufferSize`
  for an `out` buffer that is not exactly `msg.len + overhead`, where it
  previously used `std.debug.assert`. An assert is compiled out in
  ReleaseFast, so a caller who miscomputed the size got memory corruption in
  the build that matters most and a clean panic only in Debug. `open`, five
  lines below, had always returned an error for the same class of mistake.
  Found by writing this module's first example.

- **2026-08-14** — Test-only: `kat_test.zig` gained a `testing.fuzz` harness on
  `open` (arbitrary-length, arbitrary-content ciphertext against the fixed KAT
  keypair) — `zig build check-fuzz` no longer names this module. No panic/OOB
  found; **neither breaking nor behavioural**.
- **2026-07-18** — Security audit: no findings. Modeled on libsodium `crypto_box_seal` /
  Go `nacl/box` (design reference, not a test anchor).
- **2026-07-07** — New module: NaCl `crypto_box_seal` — anonymous-sender X25519
  public-key encryption (thin over `std.crypto`) + base64/hex key serialization.
