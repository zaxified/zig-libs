# trie — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-28** — **Fix (no-panic sweep):** no consumer-reachable panic or UB (independent review of every pub entry point, `~/CML/20261028-panic-sweep/trie-sweep.report.md`). The `max_visited == 0` forms (`prefixIterator`, `range`, `search`, `topN`, `opIterator`) stop with `error.Corrupt` after `buf.len` node decodes — a sub-1 KB DAG-shaped buffer `load` accepts enumerated 2^40+ keys; `Builder`/`SortedBuilder.insert` refuse a key past `max_key_len` (default `max_depth`, new `error.KeyTooLong`; ~350 B of frames per key byte); a `SortedBuilder` whose `insert` failed returns `Finished`; `Header.verifyBody` refuses a buffer cut before the footer; `trie.format` re-exports only what consumers use; `Header.encode` and `NodeView.edge` check their arguments in every build mode.
- **2026-10-24** — **Performance:** `lookup` over format version 3 checks each node's bounds once
  (at its end) instead of field by field, handles the root's empty tail before the walk and a
  node without edges in its own branch, and prefetches the line below the node it moves to
  (its children, written before it); `format.findLabelIn` / `strictlyAscendingIn` match and
  order-check a run of 17..32 labels with one masked 32-byte compare (the "found in the
  first 16?" branch was three quarters of a miss lookup's branch misses). A miss lookup:
  ~1 060 → ~880 instructions; `bench-trie` exact lookup miss 1.35× → 1.15× and hit 1.08× →
  1.02× darts-clone 0.32h — P1. Same answers and errors on every buffer. **Tests:** a
  differential over 26-edge nodes, every truncation of the node region and 1 000 damaged
  buffers (lookup vs the decoder walk); the vector-helper oracle at every slack 0..40.
  **Audit:** independent review (no finding against the code; its two test gaps closed by the
  test above) + 25-mutant run over the changed code (24 killed, 1 equivalent).

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** mutation audit of the format-version-3 code (38/38); the v3 writer's distance width is now the pure `distanceWidth` (same choice), tests for it at every boundary and for tails differing only in their first or last byte.

- **2026-10-24** — **Format:** the writer's default is frozen format **version 3**: version 2
  with each node's edge count and labels ahead of its tail and value, and its children as
  1–4-byte distances back from the node (width in node flag bits 2–3) instead of `u32`
  offsets. Readers read versions 1, 2 and 3; a reader built before this entry reads only 1
  and 2, so write with `StreamOptions.version = .v2` (or `FreezeOptions{ .v2 = .{ .version =
  .v2 } }`) for one. **Performance:** `lookup` walks version 3 in its own loop (the node
  checks of `format.nodeAtV3`, no node view per step) with 16-byte label match and order
  check: `bench-trie` exact lookup hit 1.61× → 1.07× and miss 2.13× → 1.35× darts-clone,
  index 23.1 → 19.5 B/key. P stays 2 (the miss row is over 1.25×). **Tests:** v3 goldens,
  a v3 damage test through `lookup` and the shared decoder, a differential sweep holding
  `lookup` to the decoder walk on 6 000 damaged buffers (a mutant without the label-order
  check fails it), an oracle test for the vector helpers at every length and buffer edge,
  and the format lists of the existing differentials now cover v2 explicitly.

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the all-module `strRepeat` rewrite (`571bf09e`) is reverted here: this module's calls are small (seconds of Sema at most), and the change would have made its fresh audit's `src` hash stale for nothing.

- **2026-10-23** — **Behaviour:** `error.KeyTooLong` from `PrefixIterator.next` /
  `SearchIterator.next` (a `key_buf` too small) now leaves the iterator on that key, so a retry
  with a bigger buffer returns it; before, the key was skipped. Any other error finishes the
  iterator (an `OpIterator` too), and a failed allocation no longer leaves a stray byte in the
  path. **Audit:** independent review + 34-mutant run over the search / set-operation code (33
  killed, 1 equivalent), five new tests from the survivors. **Card:** scope `ahead` (fst panics
  on 84.6 % of damaged indexes with a matching checksum, this module on none; ranked top-N
  pages; key ↔ rank), A1, and the fastest in the field measured: darts-clone's exact lookup is
  2.13× faster on a miss, so P stays 2 and the grade 2. `bench-trie` times darts-clone 0.32h and
  marisa-trie 0.3.1 beside fst (`tools/cpp_bench`); `trie_bench corrupt` is the fst side of the
  robustness claim.
- **2026-10-18** — Ported to Zig 0.17.0: `Fn.params` -> `param_types` in the automaton interface check.
- **2026-10-13** — **core → parity with BurntSushi/fst 0.4 (S2).** New
  `automaton.zig` + `Frozen.search`: every key a byte automaton matches, in
  order, pruned by `canMatch` (also mid-edge in v2) and cut short by
  `willAlwaysMatch`; built-ins `Str`, `Subsequence`, `AlwaysMatch`,
  `startsWith`, `unionOf`, `intersectionOf`, `complementOf`, and any type with
  the five automaton functions (compile-time checked). New `ops.zig` +
  `opIterator`: union, intersection, difference, symmetric difference over up to
  64 indexes with a shared node budget and the contributing values per key.
  `PrefixIterator` gained `nextValue` / `currentKey` (no key copy). Both
  searches are in the differential oracle (naive per-key automaton evaluation,
  naive merge of the oracles; v1, v2, v2 + ordinals), the corrupt-buffer sweep
  and the fuzz harnesses. Comparative benchmark `tools/bench.zig` against fst
  0.4.7 (`zig build bench-trie`); `Performance` not yet measured on the card.
  Wider-than-`u32` values and suffix minimization stay rejected (SPEC).
- **2026-10-04** — **mvp → core.** Frozen **format version 2** is the default:
  path-compressed (a single-child chain is one node whose `tail` holds the
  merged bytes), compact leaves (no `subtree_best`, no edge count), children
  before parents with the root last and the metadata in a 24-byte footer. On
  qap's RÚIAN address index: 397 MB → 70 MB (140 → 24.6 B/key), `topN` mean
  315 µs → 76 µs, every key cross-checked. Version-1 buffers still load and
  answer every query; `freezeWith(gpa, .v1)` still writes one.
  - **New:** `SortedBuilder` (streaming v2 writer over sorted keys to any
    `std.Io.Writer`, memory ∝ longest key), `Builder.freezeWith` /
    `freezeTo`, `freezeFromPairsWith`, `FreezeOptions`; `Frozen.range`
    (`Range`, inclusive/exclusive bounds, budgeted), `prefixesOf` /
    `longestPrefix`, `ordinal` / `keyAt` (with `.ordinals = true`, 4 bytes per
    edge), `QueryOptions.after` (next page of a `topN` ranking),
    `Frozen.rootNode` / `hasOrdinals`; `KeyIterator` names the range iterator
    (same type as `PrefixIterator`), `OrdinalError` adds `NoOrdinals`.
  - **Behaviour change:** `freeze` / `freezeFromPairs` now write version 2 — a
    reader built against an older `trie` refuses it (`UnsupportedVersion`).
    A version-2 buffer must be passed at its exact length (the footer is found
    from the end), unlike v1's tolerated trailing padding.
  - **Verification:** differential over v1 / v2 / v2+ordinals incl. range,
    common prefixes, rank ↔ key and chained `topN` pages; a hand-derived v2
    golden; one targeted damage per v2 load/decode check; a seeded
    corrupt-buffer sweep with pinned reach (2 × 300 000 seeds clean); mutation
    38 mutants, 0 surviving (1 argued equivalent). `fuzzysearch` walks v2.

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
