# ripemd160 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Test-only: the streaming/one-shot differential had only
  ever compared the EMPTY message, so `update`'s buffer arithmetic — the whole
  point of the target — had never run.** `fuzzStreamingMatchesOneShot` drew
  `len = smith.valueRangeAtMost(u16, 0, msg.len)` and only then
  `smith.bytes(msg[0..len])`, under a comment explaining that the length came
  first "so every mutated byte lands inside `data`". A ranged `Smith` draw
  reads eight octets as a little-endian `u64` and returns the range MINIMUM
  unless that whole word falls inside the range, so `len` was 0 for every
  input the ordinary test lane can carry. With `data` empty the chunking loop
  never executed, the 1..97 chunk size was never drawn, and the oracle
  compared `hash("")` against an `init`/`final` pair that had called `update`
  **zero times**. The harness now draws with one `smith.slice(&msg)` and reads
  its chunk sizes out of the drawn octets through `testkit.fuzz.Cursor`, so
  there is no second draw to go dead on a corpus replay, and carries a
  15-seed corpus built around `block_length`: the official KAT messages plus
  55/56 (the padding-fits vs forces-a-second-block boundary) and 63/64/65.
  Measured 2026-09-07: **0 of 15 seeds arrived non-empty and 0 `update` calls
  were made before; 14 of 15, 168 `update` calls over 1009 octets, 12 of them
  split across more than one call, after.** The buffer also drops 4096 → 256:
  nothing needed 4096, and a seed larger than the buffer reads back empty.

- **2026-08-06** — Security audit: one finding fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Verified: Byte-exact against the
  official RIPEMD-160 test set (Dobbertin/Bosselaers/Preneel appendix, also ISO/IEC
  10118-3).
- **2026-07-21** — New module: RIPEMD-160 (ISO/IEC 10118-3) — std-crypto-style
  `init`/`update`/`final` streaming hash (little-endian length padding, unlike SHA-2's
  BE) + `hash160`.
