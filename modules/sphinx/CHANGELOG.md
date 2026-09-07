# sphinx — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: `fuzzOnionPacketDecode` handed `fromSlice` the
  empty slice on every run, so `fromBytes` — the version check, the SEC1
  public-key decode, and `toBytes` behind them — had never executed from this
  target.** The harness drew `smith.bytes(&buf)` and then
  `smith.valueRangeAtMost(u16, 0, buf.len)`; `bytes` consumes
  `@min(buf.len, in.len)` octets, so the ranged draw found fewer than the
  eight it reads as a little-endian `u64` and returned the range MINIMUM.
  `len` was 0 for every input the ordinary test lane can carry, and
  `fromSlice` refused it at the `bytes.len != packet_len` line. ⭐ This is the
  exact-length shape that makes a short corpus useless: **no seed under 1366
  octets can get past the first line at all**, so the seeds are assembled at
  comptime by a `wire()` helper. 14 of them now cover an accepted packet, both
  SEC1 sign bytes, `UnsupportedVersion`, three distinct `InvalidPublicKey`
  causes (a non-encoding-type prefix, x = 0, x above the field prime), and
  `packet_len` minus one / plus one / plus eight. Measured 2026-09-07: **0 of
  14 seeds arrived non-empty, 0 got past the length gate and 0 parsed before;
  13, 9 and 3 after.**

- **2026-07-18** — Security audit: no findings. Verified:
  `kat_test.zig`/`kat_vectors.zig` carry the official BOLT#4 test vector.
- **2026-07-12** — New module: Lightning BOLT#4 Sphinx onion routing (the mix-net that
  gives Lightning payment privacy).
