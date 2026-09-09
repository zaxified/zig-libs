# sealedbox — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added, which also puts this module in the `ct` class and therefore in `scripts/ctgrind.sh`. It settles a contradiction the 2026-09-09 ctgrind coverage pass left standing: the pass filed `sealedbox` as a thin wrapper over `std` with nothing of its own to measure, while this module's audit record said the secret-key codecs light up immediately. ⭐ Both were right, about different functions — `seal`/`open` ARE pure `std.crypto.nacl.SealedBox` and are deliberately NOT targets, but `encodeSecretKeyBase64`/`parseSecretKeyBase64`/`encodeSecretKeyHex`/`parseSecretKeyHex` hand 32 bytes that grant full decryption capability to `std.base64` and `std.fmt`, neither of which claims to be constant-time. Measured ReleaseFast with the secret (or, for the parsers, the secret-derived TEXT) marked undefined: **43 / 47 / 8 / 7 in-file contexts**, each with an untainted control row and a no-`-fvalgrind` trap row at 0. ⛔⛔ **These are not artefacts and not merely branches:** 95 of them are reported on a LOAD, and the disassembly shows `movzbl 0x100fde8(%rax),%eax` over a secret byte (the 256-byte `char_to_index`) and `shr $0x34 / and $0x3f / movzbl 0x100ff2e(%r8)` over a secret 6-bit group (the 64-byte alphabet) — secret-indexed table lookups, the cache-timing class of T-table AES. ⚠ Sharpness follows table size, so the 256-byte decode table is the worst of the four and the 16-byte hex table the mildest; the counts are unrolled iterations, not severity. The rows are pinned **as a DEFECT**: the module is not fixed by this entry, and constant-time secret-key codecs remain owed.

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
