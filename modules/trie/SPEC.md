# trie — SPEC

A frozen prefix index for instant autocomplete over a large, static string set.
Build from `(key, value)` pairs → freeze to a flat byte buffer → query that
buffer zero-copy from a read-only / mmap'd slice.

## Design decision — A (byte-labelled trie) vs B (minimized FST/DAFSA)

**Chosen: A — a plain byte-labelled trie with per-node `subtree_best` pruning,
serialized to a flat buffer.**

Each node stores its terminal flag + value, the maximum stored value among its
terminal descendants (`subtree_best`), and its outgoing edges as
`{label, child_offset}` pairs sorted by label. Top-N completion is a
lexicographic DFS under the prefix node, feeding every terminal into a
fixed-size best-N selector; `subtree_best` lets the DFS skip any subtree that
cannot beat the current worst-kept value.

Why not B (Lucene-FST / BurntSushi-`fst`-style minimized DAFSA): a minimized
automaton merges common *suffixes* to shrink memory, but

1. it complicates the frozen format and — critically — makes **bounds-checking a
   corrupt/untrusted buffer much harder**, because a minimized graph has shared
   nodes reachable by many paths and no simple monotone offset invariant to lean
   on for provable traversal termination;
2. the top-N-by-value autocomplete query wants a value on the terminal path and
   a per-node max for pruning, which a value-carrying FST (output-labelled
   transducer) can do but at real added design cost;
3. RÚIAN-scale (a few million keys, values = record ids) fits comfortably in RAM
   as an un-minimized trie.

So A trades some memory for a **robust, trivially bounds-checkable frozen format
over untrusted input** and a simpler, obviously-correct top-N. Suffix
minimization is a documented deferred optimization (below) that can be added
behind the same query API and a bumped `format_version` without changing callers.

### Cost model (structure A)

- **Memory (frozen):** header 36 B + per node `1 (flags) + 4 (value) + 4
  (subtree_best) + 2 (edge_count) + 5·edge_count`. One node per distinct byte on
  each distinct path; shared prefixes share nodes, distinct suffixes do not.
- **Build:** O(total key bytes), pointer-chase insert into a growing node pool.
- **`lookup`:** O(key.len) node decodes, **zero allocation**.
- **`topN`:** O(visited) node decodes bounded by `max_visited`, **zero
  allocation** (fixed inline DFS stack + caller-supplied result/key buffers).
- **`prefixIterator`:** borrows a small traversal stack from an allocator
  (typically a reused arena); the frozen index itself is never copied.

## Frozen wire format (version 1)

All integers **little-endian**. The buffer is `header ++ node_region`.

### Header — 36 bytes at offset 0

| off | size | field | meaning |
|----:|-----:|-------|---------|
| 0  | 4 | `magic`         | ASCII `"ZTR1"` |
| 4  | 2 | `version`       | format version = 1 |
| 6  | 2 | `endian_marker` | `0x0102` — detects a wrong-endian / garbage load |
| 8  | 4 | `flags`         | reserved, currently 0 |
| 12 | 4 | `node_region_len` | bytes of the node region |
| 16 | 8 | `key_count`     | number of distinct stored keys |
| 24 | 4 | `root_offset`   | absolute byte offset of the root node |
| 28 | 4 | `body_crc`      | CRC-32 of the node region (checked by `loadVerified`) |
| 32 | 4 | `header_crc`    | CRC-32 of bytes `[0..32)` |

`Header.load` validates magic, version, endian marker, header CRC, and that
`root_offset` lies inside the node region — all O(1), without scanning the body.
`loadVerified` additionally checks `body_crc`.

### Node region — starts at offset 36

A contiguous array of nodes emitted in node-id order. **Invariant:** a child's
id always exceeds its parent's, so every child sits at a **strictly greater
offset** than its parent. The query decoder enforces `child_offset >
parent_offset` (and `< buffer length`); because followed offsets strictly
increase and are bounded, traversal **provably terminates even on a corrupt
buffer**.

Each node:

| size | field | meaning |
|-----:|-------|---------|
| 1 | `flags`        | bit0 = terminal (node ends a stored key) |
| 4 | `value`        | present iff terminal — the caller's stored `u32` |
| 4 | `subtree_best` | max stored value among this node's terminal descendants (incl. itself); drives top-N pruning |
| 2 | `edge_count`   | number of child edges |
| 5·`edge_count` | edges | each `{ u8 label, u32 child_offset }`, sorted ascending by label; `child_offset` absolute, `> this node's offset` |

Edges sorted by label allow a binary search in `findEdge` and make lexicographic
DFS a straight left-to-right edge walk.

## DoS / bounded-work model

The exposed autocomplete surface is `topN(prefix, …, opts)`. A short prefix
(e.g. one byte) can sit above millions of keys. `QueryOptions.max_visited`
(default **50 000**) caps the number of nodes the DFS may decode; on reaching it
`topN` stops and returns `status = .truncated_budget` with a best-effort partial
top-N. `subtree_best` pruning means a well-ranked query typically finishes far
under budget, so the cap rarely bites in practice yet always bounds worst-case
latency. `max_visited = 0` disables the cap and must not be used on
attacker-influenced prefixes. `prefixIterator` is unbounded by nature (it
enumerates everything under the prefix) and is intended for trusted/offline
enumeration, not a request path — a request path should use `topN`.

`max_depth` (4096) caps the DFS/key-reconstruction stack; a key deeper than that
yields `error.KeyTooLong` rather than an unbounded stack. Addresses are far
shorter.

## Threat model — untrusted frozen buffers

A frozen buffer may come from a file outside the process trust boundary
(truncated, bit-flipped, or hand-crafted). Guarantees:

- **Never panics, never reads out of bounds, never loops forever** on any input
  buffer. Every field the query path follows out of the buffer is bounds-checked
  in `format.zig` (`nodeAt`, `NodeView.edge`, `follow`); a bad field yields a
  typed `error.Corrupt`.
- **Header validation** rejects short buffers (`Truncated`), wrong magic
  (`BadMagic`), unknown version (`UnsupportedVersion`), wrong endian
  (`BadEndian`), a corrupt header (`HeaderCorrupt`), and an out-of-region root
  (`MalformedRoot`). `loadVerified` adds `BodyCorrupt` (node-region CRC).
- **Termination** rests on the strictly-increasing bounded-offset invariant, not
  on trusting `edge_count` or any length field — a corrupt `edge_count` can only
  make a node decode fail bounds-checking, never over-read.

CRC-32 is an integrity check against accidental corruption / bit-rot, **not** a
security MAC; it does not authenticate a deliberately-forged buffer. A buffer
from an untrusted producer that survives `loadVerified` is still only guaranteed
*safe to query* (no crash / OOB / hang), not *trustworthy in content*. Sign the
file at a higher layer if producer authenticity matters.

## Verification

- **Differential oracle:** a naive sorted `[]const []const u8` + binary-search /
  linear-prefix-scan reference in the tests answers the same `lookup` / prefix /
  top-N queries; a randomized differential over generated key sets must agree
  exactly, including top-N ordering and tie-break.
- **Adversarial key sets:** empty key, prefix-of-another, duplicates
  (last-write-wins), single-byte, very long, long shared prefixes, multi-byte
  UTF-8 (Czech diacritics), keys differing only in the last byte.
- **Corrupt-buffer fuzz:** the loader + query path are hammered with truncated /
  bit-flipped / wrong-magic buffers and must only ever return a typed error.
- **Positive controls:** hand-malformed buffers and deliberately-broken variants
  demonstrate the differential / robustness checks go RED, proving they have
  teeth.
- **Round-trip:** in-memory answers == answers after build → freeze → load.
- Green in Debug and `-Doptimize=ReleaseFast`; `zig fmt --check` clean;
  `zig build check-catalog` exit 0.

## Build-time memory profile (measured)

Build RSS is **linear** in the key count — no algorithmic blow-up. The builder
keeps the whole trie in **two growable pools**: a node pool and an edge pool.
Each node's children are an intrusive singly-linked sibling list threaded through
the edge pool (`Node.first_edge` heads it, each `Edge.next` chains on); `freeze`
sorts each node's edges by label just before emission. So the entire build is a
handful of pool doublings (~O(log N) allocations total), **not two allocations
per node**. Consequences:

- Build RSS is low and, crucially, **allocator-insensitive** — it does not
  explode under a debug/safety allocator, because the safety allocator now tracks
  ~tens of pool allocations, not millions of per-node ones.
- Descent is a linear scan of a node's sibling list instead of a binary search,
  but child counts are tiny (≤ 256 distinct byte labels, usually a handful), so
  this is not a hot cost.

Measured on this repo's host, synthetic address-like keys:

| keys | frozen buffer | build RSS (freeing GPA) | build RSS (bare arena) |
|-----:|--------------:|------------------------:|-----------------------:|
| 200 k | 8.1 MB | 19 MB (82 B/key) | 62 MB (324 B/key) |
| 400 k | 14.9 MB | 31 MB (82 B/key) | 116 MB (304 B/key) |

≈ 80–300 B build RSS per key (GPA … arena), frozen output ≈ 40 B/key.

**History:** an earlier builder held two grow-by-doubling arrays *per node*
(child labels + child ids). That was ~1 KB transient/key under an arena and
**pathological under a debug/safety allocator** — per-allocation metadata over
millions of tiny allocations inflated RSS ~10× and OOM-killed a ≥1 M-key
benchmark at 22 GB. The two-pool sibling-list build above replaced it, cutting
the arena path ~3.6× (1095 → 304 B/key) and turning the safety-allocator path
from an OOM into the *leanest* path (82 B/key, no leaks). Query API and frozen
format are unchanged (the differential oracle tests pass identically).

## API sharp edge — `topN` key buffer sizing

`topN` shares one `key_buf` across all `results.len` output slots, slicing it
into equal strides of `key_buf.len / results.len`. A completion longer than one
stride returns `error.KeyTooLong`. Callers must therefore size `key_buf` as
**`results.len × longest-expected-completion`**, not just one key. (The single
`prefixIterator` `next(buf)` path has no such multiplier — one key at a time.)

## Deliberately deferred

- **Suffix minimization (DAFSA/FST).** The biggest memory win; deferrable behind
  the same query API + a bumped `format_version`. Un-minimized fits RAM at
  RÚIAN scale.
- **Columnar / SIMD edge scan.** Edges are a sorted `{label,offset}` array; a
  wide first-byte fan-out at the root could use a 256-entry dense jump table.
- **On-disk streaming build** (build larger-than-RAM). Current build holds the
  node pool in memory before freezing.
- **Ranked-prefix cursor / pagination** beyond fixed top-N (e.g. "next N").
- **Approximate / typo-tolerant matching** — that is the sibling `fuzzysearch`
  module's job, not this one; `trie` stays exact-prefix.
- **Value payloads wider than `u32`** — callers store a `u32` record id and
  indirect through their own table.

## Anchoring

**Anchor grade:** class D · oracle n/a

- **Class D** — our own design — no third party exists to agree with, by construction.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** own frozen-index wire format (ZTR1 magic), invented in-repo, no third party
