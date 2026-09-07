# sealedbox — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — `fuzzOpen` had only ever opened a zero-length ciphertext. It drew the
  length FIRST with `smith.valueRangeAtMost(u16, 0, 256)` and read the bytes into
  `sealed_buf[0..sealed_len]` afterwards; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM unless that whole word lands inside the
  range, so `sealed_len` was 0 and the `bytes` call that followed copied nothing. `open`
  refused on its `sealed.len < overhead` line, and no other line of the module ever ran from
  the fuzzer. Now one `smith.slice(&sealed_buf)` call, plus an eight-ciphertext corpus (the
  module's own KAT sealed box, three one-bit mutants of it in the ephemeral key / tag /
  message, `overhead` and `overhead - 1` octets of zeros, a full buffer, and the empty input)
  and a corpus guard. Measured: **0 of 8 seeds non-empty, 0 boxes opened and 0 plaintext
  octets before; 7 of 8 non-empty, 1 opened and 46 plaintext octets after.** The file comment
  argued that random input already reaches the authentication-failure path — true, but it
  reaches only that path: nothing random opens, so `open`'s success branch was unreachable
  from this target by construction.
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
