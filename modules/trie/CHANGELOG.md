# trie — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **Fixes (A1 audit F1–F5).** Five untrusted-input findings
  from the 2026-09-09 audit, closed:
  - **F1 (HIGH):** nothing in the wire format forbade two edges from pointing
    at the same child node, so a buffer under 1 KB could encode 2^60 keys (the
    audit's own reproduction: 1067 bytes, 1142 years to drain). `prefixIterator`
    had no visit budget to guard against it (unlike `topN`, which already had
    one). Added `Frozen.prefixIteratorBounded` / `PrefixIterator.max_visited`
    (new, additive — `prefixIterator` itself is unchanged) so a caller handling
    an untrusted buffer can bound the walk; `next` returns the new
    `error.TooComplex` once the budget is exceeded, instead of continuing
    indefinitely. Measured on a hand-built 20-level DAG buffer (2^20 keys):
    unbounded `prefixIterator` still drains all 1,048,576 keys; the same buffer
    through `prefixIteratorBounded(.., 1000)` aborts after ≤1000 nodes.
  - **F2 (MED):** `loadVerified`'s CRC covers only the declared node region,
    but `nodeAt`'s bounds check was against the whole buffer, so an edge could
    resolve into the trailing padding `Header.load` tolerates (for a
    page-rounded mmap) — bytes `loadVerified` never checked. `Frozen.load` now
    bounds the slice it keeps to exactly `header_size + node_region_len`, so
    the padding is unreachable through any node/edge regardless of CRC.
  - **F3 (MED):** the format's documented "edges sorted ascending by label"
    invariant was unenforced. An out-of-order or duplicate-label node made
    `lookup` (binary search) disagree with `prefixIterator`/`topN` (linear
    index order) on the same buffer, and could hide a key from `lookup`
    outright. `nodeAt` now rejects any node whose edges are not strictly
    ascending, closing all three query paths at the one place they all funnel
    through.
  - **F4 (LOW):** `Builder.insert`'s `@intCast(usize -> u32)` for node/edge ids
    was unchecked — UB in ReleaseFast past ~4.29 billion of either. `freeze`
    already had the matching check on the serialized offset space; `insert`
    now has it too (`BuildError` gained `TooLarge`, additive).
  - **F5 (LOW):** `Selector.consider`'s eviction path divided by `stride`,
    which is 0 whenever `key_buf` is shorter than `results.len`; only reachable
    via a specific, previously-unwritten call-order argument. Now an explicit
    `error.KeyTooLong` instead.
  - F6/F7 (perf/doc) left open — no code defect, just missing numbers in the
    docs; not part of this pass.

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
