# trie — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Tests:** both fuzz harnesses were dead, in two different
  ways, and the mutation one was dead twice.
  `fuzzRandom` filled a buffer with `smith.bytes` and then drew the length with
  `valueRangeAtMost(u16, 0, buf.len)`; a ranged `Smith` draw reads eight octets
  as a little-endian u64 and returns the range MINIMUM when fewer remain, so
  `Frozen.load` got an empty slice and `error.Truncated` on every iteration,
  and with no corpus that was the only input it ever ran.
  `fuzzMutated` drew its flip count with `valueRangeAtMost(u8, 0, 12)` as the
  FIRST draw, so the count was **0**: it re-loaded the pristine index every
  time. Its own comment claimed the fuzzer "spends its time past the magic/CRC
  gate, deep in node traversal" — measured, it applied zero mutations, and 20
  000 iterations reported clean with an escaping bug planted in the traversal.
  ⭐ Fixing the count alone would not have been enough: the frozen header
  carries a CRC-32 over `[0..32)`, so **any** blind flip in the 36-octet header
  comes back as `error.HeaderCorrupt` and the walk is never entered — a
  byte-flipping harness over a CRC-gated format measures the rejection path and
  nothing else. The mutation script now carries a re-seal bit that recomputes
  `header_crc` (and optionally `body_crc`) after the flips, which is what an
  attacker handing over a crafted index does, and is what makes a damaged
  `root_offset` / `node_region_len` / `key_count` reach the bounds-checked walk.
  Both harnesses now take one `smith.slice` draw and carry a corpus (10 whole
  frozen buffers with correctly computed header CRCs, 11 mutation scripts).
  Measured: 0 octets mutated and 0 damaged buffers loaded before; 23 octets
  changed, 5 damaged buffers past `Header.load` into the traverse, 4 refused, 2
  accepted by `loadVerified` after. `Frozen.loadVerified` is now exercised too.

- **2026-08-06** — Security audit: no findings. Modeled on BurntSushi/`fst`, Lucene FST
  (design reference, not a test anchor).
- **2026-07-24** — New module: Prefix index for instant autocomplete over a large static
  string set.
