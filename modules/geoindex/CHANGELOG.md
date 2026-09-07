# geoindex — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — **Tests:** both fuzz harnesses were dead, the mutation one
  twice. `fuzzRandom` filled a buffer with `smith.bytes` and then drew the
  length with `valueRangeAtMost(u16, 0, buf.len)`; a ranged `Smith` draw reads
  eight octets as a little-endian u64 and returns the range MINIMUM when fewer
  remain, so `Frozen.load` got an empty slice on every iteration, and with no
  corpus that was the only input it ever ran. `fuzzMutated` drew its flip count
  with `valueRangeAtMost(u8, 0, 16)` as the FIRST draw, so the count was **0**
  and it re-loaded the pristine index every time. ⭐ And fixing the count alone
  buys nothing: the 40-octet header carries a CRC-32 over `[0..36)`, so any
  blind flip in it returns `error.HeaderCorrupt` and the R-tree descent is never
  entered — a byte-flipping harness over a CRC-gated format measures the
  rejection path and nothing else. The mutation script now carries a re-seal bit
  that recomputes `header_crc` (and optionally `body_crc`) after the flips,
  which is what an attacker shipping a crafted index does, and is what makes a
  damaged `root_index` / `node_count` / `node_bytes` reach the bounds-checked
  walk. Both harnesses take one `smith.slice` draw and carry a corpus (14 whole
  frozen buffers with correctly computed CRCs, 11 mutation scripts). Measured:
  0 octets mutated and 0 damaged buffers loaded before; 25 octets changed, 4
  damaged buffers past `Header.load` into the descent, 5 refused, 2 accepted by
  `loadVerified` after. `Frozen.loadVerified` is now exercised too.

- **2026-08-06** — Security audit: no findings. Modeled on Flatbush (mourner/flatbush,
  design reference) (design reference, not a test anchor).
- **2026-07-24** — New module: Static spatial index for bbox + nearest-neighbour queries
  over a large fixed geo-point set — DoS-bounded, frozen zero-copy.
