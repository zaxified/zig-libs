# fuzzysearch — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Tests:** both fuzz harnesses were dead, the mutation one
  twice. `fuzzRandom` filled a buffer with `smith.bytes` and then drew the
  length with `valueRangeAtMost(u16, 0, buf.len)`; a ranged `Smith` draw reads
  eight octets as a little-endian u64 and returns the range MINIMUM when fewer
  remain, so `Frozen.load` got an empty slice on every iteration, and with no
  corpus that was the only input it ever ran. `fuzzMutated` drew its flip count
  with `valueRangeAtMost(u8, 0, 12)` as the FIRST draw, so the count was **0**
  and it re-loaded the pristine index every time — the comment claiming the
  fuzzer "spends its time past the magic/CRC gate, deep in node traversal" was
  false when written. ⭐ And fixing the count alone buys nothing: the `"ZTR1"`
  header carries a CRC-32 over `[0..32)`, so any blind flip in the 36-octet
  header returns `error.HeaderCorrupt` and the Levenshtein walk is never
  entered. The mutation script now carries a re-seal bit that recomputes
  `header_crc` (and optionally `body_crc`) after the flips. Both harnesses take
  one `smith.slice` draw and carry a corpus (11 whole frozen buffers with
  correctly computed CRCs, 11 mutation scripts). Measured: 0 octets mutated and
  0 damaged buffers loaded before; 23 octets changed, 5 damaged buffers past
  `Header.load` into the walk, 4 refused, 2 accepted by `loadVerified` after.

- **2026-08-06** — Security audit: no findings. Modeled on Hanov trie+DP / Lucene
  `FuzzyQuery` / Schulz–Mihov (design reference, not a test anchor).
- **2026-07-24** — New module: Bounded-edit-distance typo-tolerant lookup over a static
  string set — DoS-bounded, the typo-tolerant sibling of `trie`.
