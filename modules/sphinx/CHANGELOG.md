# sphinx — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-09** — Licensing: `NOTICE` kind changed from `provenance note` (record only) to
  `third-party attribution` (carries a CONDITION). `src/kat_vectors.zig` embeds BOLT#4's onion test vector verbatim from `lightning/bolts`,
  which is CC-BY 4.0, so attribution is owed and was not being given. ⛔⛔ The repository was
  distributing two opposite answers about one upstream: `lnwire`, `lninvoice` and `k256`
  record `lightning/bolts` as CC-BY 4.0 and attribute it, while this file said BOLT text is
  "not a copyrightable work (merger doctrine)" and needs no entry. Re-verified 2026-09-09
  against commit `152897261850d93c4f4597f39cf22d7d22d6ede6`: all 12 values vendored from `bolt04/onion-test.json` are byte-identical upstream today. The pin is now that
  commit rather than "`master` branch", which is not a pin. CC-BY's
  indicate-modifications condition is discharged (none — the values are the published ones,
  hex-decoded). No code or data changed.

  ⭐ Changing the kind pulled this file under `zig build check-copyleft` for the first time
  — that gate only holds ATTRIBUTION files to the formal `**Copyleft:**` shape — so the
  existing "No GPL/LGPL/AGPL source was consulted" sentence had to become a declared line.
  Declaring a condition honestly is what turned on a check the file had never faced.
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
