# fuzzysearch

**Bounded-edit-distance, typo-tolerant lookup** over a large, static string set —
the typo-tolerant sibling of the exact-prefix `trie`. Given a query and a maximum
edit distance `k`, return the stored keys within OSA (restricted
Damerau–Levenshtein) distance `k`, ranked best-first, sub-millisecond over a large
static set, with an explicit visit **budget** as the DoS guard and **no per-query
allocation** (caller supplies the result + key buffers).

The driving consumer is Czech RÚIAN address autocomplete where the user mistypes
("Vaclvske" → "Vaclavske"). The module itself is general — any static string→`u32`
set that needs typo-tolerant lookup.

- **Model after:** the Levenshtein-automaton-over-trie method (Steve Hanov's
  "trie + dynamic-programming row"); Lucene `FuzzyQuery`; the Schulz–Mihov
  universal Levenshtein automaton — the frozen-index fuzzy-match lineage.
- **Platform:** any — pure logic, no OS dependency. **Role:** util.
  **Concurrency:** `reentrant` — a frozen buffer is immutable, so any number of
  threads may search one buffer concurrently with no synchronization.
- **Deps:** `trie` (the index IS a trie buffer — see below).

> **Status: implemented.** Build → freeze → zero-copy load → fuzzy search is
> complete and tested. A brute-force full-matrix OSA oracle (randomized, over
> adversarial key sets — transpositions, single-edit neighbours, multi-byte
> Czech UTF-8, near-identical clusters, duplicates, the empty key/query, the
> exact-`k`-vs-`k+1` boundary) pins the ranked match set; a corrupt-buffer fuzz
> harness pins the untrusted-buffer loader + search path; hand-malformed positive
> controls prove the checkers have teeth. See `SPEC.md` for the design decision
> and the threat model.

Provenance: original work of the zig-libs authors (MIT) — the trie index, the
bounded-edit-distance walk and the ranking. Design references, approach only:
Steve Hanov's published trie + dynamic-programming Levenshtein walk, Lucene's
`FuzzyQuery` (**Apache-2.0**), and the Schulz–Mihov Levenshtein-automaton
papers. No source consulted or copied.

## The index is a `trie`

`fuzzysearch` adds **no wire format of its own**. Its `Builder` / `freezeFromPairs`
are `trie`'s, re-exported, and produce a plain `trie` frozen buffer (magic
`"ZTR1"`). A fuzzysearch index and a trie index are the **same file**: the typo
tolerance lives entirely in this module's *query algorithm* (a Levenshtein
automaton walked over the trie), not in the data. So one frozen buffer serves both
exact `trie` completion and this fuzzy search. Loading validates the trie header
(magic, version, endian marker, header CRC, root offset); every offset the search
follows out of the buffer is bounds-checked by `trie`'s decoder.

## Contracts

- **Keys are arbitrary bytes; edit distance is over BYTES.** A multi-byte UTF-8
  codepoint counts as several byte-edits (replacing `ě` (`0xC4 0x9B`) with `e`
  (`0x65`) is distance 2). Unicode-aware matching (NFC / case-folding /
  diacritic-stripping) is the **caller's** job: fold both the stored keys and the
  query the same way *before* indexing — the same normalization contract as
  `trie`. The empty key and the empty query are both allowed.
- **Metric: OSA (optimal string alignment)** — the *restricted*
  Damerau–Levenshtein distance: insertion, deletion, substitution, and
  transposition of two adjacent bytes, each one edit, under the OSA restriction
  that no region is edited twice. True (unrestricted) Damerau–Levenshtein is a
  documented non-goal (see `SPEC.md`).
- **Ranking is a total order:** distance ascending → stored `u32` value
  descending → key ascending (lexicographic bytes). Keys in a frozen trie are
  distinct, so the top-N is unambiguous.
- **Bounded work / DoS guard:** `search` takes `SearchOptions.max_visited` (default
  50 000) — a node-decode budget. A short query with a large `k` sits above much
  of the set; on hitting the budget the search stops and returns
  `status = .truncated_budget` with a best-effort partial answer. Row-minimum
  pruning means a well-formed query usually finishes far under budget.
  `max_visited = 0` means unbounded — do not use on attacker-influenced queries
  or untrusted buffers.
- **Limits:** query ≤ `max_query_len` (256) bytes → else `error.QueryTooLong`;
  `k` ≤ `max_k` (254) → else `error.DistanceTooLarge`; an indexed key path deeper
  than `max_depth` (1024) bytes → `error.KeyTooLong`. Addresses are far shorter.

## API

```zig
const fuzzysearch = @import("fuzzysearch");

// Build (this is trie's builder — the index is a trie buffer).
var b = try fuzzysearch.Builder.init(gpa);
defer b.deinit();
try b.insert("vaclavske", 100);
try b.insert("namesti", 90);
const buf = try b.freeze(gpa);   // caller owns `buf`; write it to a file / mmap
defer gpa.free(buf);
// or one-shot: const buf = try fuzzysearch.freezeFromPairs(gpa, gpa, pairs);

// Query a frozen buffer (zero-copy; `buf` may be a read-only mmap).
const f = try fuzzysearch.Frozen.load(buf);            // fast: header only, O(1)
// const f = try fuzzysearch.Frozen.loadVerified(buf); // untrusted file: + body CRC

var results: [10]fuzzysearch.Match = undefined;
// key_buf is SHARED across the N result slots: it must hold results.len ×
// (longest matched key). An undersized share yields error.KeyBufTooSmall.
var key_buf: [10 * 128]u8 = undefined;
const r = try f.search("vaclvske", 2, &results, &key_buf, .{});
// r.items ranked best-first: each has .distance (0..=k), .value, .key
// r.status == .complete or .truncated_budget

// Single-pair verification helper (the reference metric).
const d = try fuzzysearch.osaDistance("teh", "the"); // 1
```

A `Match.key` borrows the caller's `key_buf`; it is valid only until that buffer
is reused. `loadVerified` adds a one-time full node-region CRC check for files
crossing a trust boundary; the search is bounds-checked either way.

### Memory & performance (qualitative)

- **Frozen buffer:** a `trie` buffer — compact (~40 B/key); see `trie`'s README
  for the build-time RSS profile (two growable pools, allocator-insensitive,
  linear). `fuzzysearch` ignores the trie's per-node `subtree_best` field (that
  drives `trie`'s value-ranked top-N, not fuzzy distance).
- **Query side allocates nothing.** The DP rows and DFS stack are fixed inline
  arrays (one `u8` DP row per depth on the current path, plus the frame stack).
  The frozen index is never copied. Cost is `O(visited × query.len)` cell
  computations, hard-bounded by `max_visited`; row-minimum pruning skips whole
  subtrees the moment they exceed `k`, which is what keeps a small-`k` query
  sub-millisecond even over a large set. Ship the frozen buffer and never build in
  the request path.
