# ripemd160 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-15** — **A1 fix campaign, perf pass: `compress`'s 80-round schedule
  unrolled at compile time (`inline for` instead of a runtime `while`
  loop).** Measured A/B, same process, ReleaseFast, 8 KiB input, 5
  interleaved rounds per side: **≈3.0–3.7× faster** (98–113 → 340–362
  MiB/s), bit-for-bit identical digests (checked against two independent
  chaining-state inputs, plus the existing 13-test suite unchanged in both
  Debug and ReleaseFast). No behavioural or API change. See `SPEC.md` §
  Performance and `A1/ripemd160.md` disposition for the numbers.

- **2026-09-10** — **A1 fix campaign: 4 gaps closed, all test-and-doc, no digest
  changed.** (1) A KAT for message length 56 (mod 64) — the first length that
  forces a *second* padding block, the sibling boundary of the existing
  length-55 vector, previously uncovered by any KAT or the fuzz corpus'
  streaming-vs-one-shot oracle (a one-token weakening of `final`'s `< 8` guard
  to `< 7` passed everything else, including 300k+ `--fuzz` runs, while
  returning a wrong digest on exactly this length). (2) `std.debug.assert(d.buf_len
  < 64)` at the top of `final`, plus a streaming test for the one call order
  the existing "exactly fills a block" test didn't try: `final()` called
  *immediately* after the update that fills the buffer, no further `update()`
  in between — reproduced the OOB write (Debug/ReleaseSafe panic, silently
  wrong digest in ReleaseFast) a weakened `update` guard (`>= 64` → `> 64`)
  causes at exactly this call order. (3) An `Hmac(Ripemd160)` test against the
  7 RFC 2286 HMAC-RIPEMD160 vectors — `block_length` had no consumer inside
  the module (`compress`/`update`/`final` all use the literal `64`) and the
  only existing test compared it to its own hardcoded copy, so a consistent
  edit of both sailed through; std's generic `Hmac` genuinely reads
  `block_length`. (4) Docs: `final()` is single-use (same as
  `std.crypto.hash`, never documented); the fuzz target's intro comment read
  in the present tense despite describing a gap the harness two lines below
  it already closed; SPEC's Verification section now names the fuzz target.
  All measured RED (mutation reproduces the exact failure a prior audit
  described) → GREEN (new test/assert catches it, full suite stays green).
  No digest changed for any input — see `A1/ripemd160.md` disposition for the
  RED/GREEN numbers.

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
