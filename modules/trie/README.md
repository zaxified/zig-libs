# trie

Memory-efficient **frozen prefix index for instant autocomplete** over a large,
static string set. Build an index from `(key, value)` pairs, **freeze** it to a
flat, self-describing, versioned, little-endian byte buffer, then query that
buffer **zero-copy** from an mmap'd / read-only slice — no per-query allocation
on the exact-lookup and top-N paths.

The driving consumer is a Czech RÚIAN address search: millions of UTF-8 address
strings, a user-typed prefix, and a sub-millisecond "top-N completions" answer.
The module itself is general — any static string→`u32` set that needs prefix
completion.

- **Model after:** BurntSushi/`fst` (Rust), Lucene FST — the frozen-index
  autocomplete lineage. (This build is a byte-labelled trie, not a minimized
  FST/DAFSA; see `SPEC.md` for the A-vs-B decision and the deferred minimization.)
- **Platform:** any — pure logic, no OS dependency (the only clock use is
  test-only benchmarking). **Role:** util. **Concurrency:** `reentrant` — a
  frozen buffer is immutable, so any number of threads may query one buffer
  concurrently with no synchronization.
- **Deps:** none (`std` only).

> **Status: implemented.** Build → freeze → zero-copy load → query is complete
> and tested. A naive sorted-slice oracle differential (randomized, over
> adversarial key sets — prefix-of-another, duplicates, single-byte, very long,
> shared-prefix, multi-byte UTF-8) pins `lookup`, prefix enumeration, and
> top-N ordering; a corrupt-buffer fuzz harness pins the untrusted-buffer
> loader; hand-malformed positive controls prove the checkers have teeth. See
> `SPEC.md` for the wire format field-by-field and the threat model.

Provenance: clean-room. Design references only — BurntSushi/`fst` and Lucene FST
(frozen-index autocomplete *approach*); no third-party source consulted or
copied. See `NOTICE`.

## Contracts

- **Keys are arbitrary bytes, compared bytewise.** Unicode normalization
  (NFC / case-folding / diacritic-stripping) is the **caller's** job: to get
  accent- or case-insensitive matching, fold both the stored keys and the query
  prefix the same way *before* handing them here. The empty key is allowed (it
  marks the root as terminal).
- **Duplicate keys: last write wins.** Inserting the same key twice keeps the
  last value; `key_count` counts distinct keys. In a frozen trie every key is
  therefore distinct.
- **Top-N ranking is a total order:** primary — higher stored `u32` value first
  (descending); tie-break — smaller key first (lexicographic byte order). Since
  keys are distinct this never ties.
- **Bounded work / DoS guard:** `topN` takes a `QueryOptions.max_visited` node
  budget (default 50 000). A one-character prefix over millions of keys stops at
  the budget and returns `status = .truncated_budget` with a best-effort partial
  answer, rather than walking the whole set. `subtree_best` pruning means
  well-ranked queries usually finish far under budget. `max_visited = 0` means
  unbounded — do not use on untrusted prefixes.

## API

```zig
const trie = @import("trie");

// Build.
var b = try trie.Builder.init(gpa);
defer b.deinit();
try b.insert("praha", 100);
try b.insert("plzen", 90);
const buf = try b.freeze(gpa);   // caller owns `buf`; write it to a file / mmap
defer gpa.free(buf);
// or one-shot: const buf = try trie.freezeFromPairs(gpa, gpa, pairs);

// Query a frozen buffer (zero-copy; `buf` may be a read-only mmap).
const f = try trie.Frozen.load(buf);           // fast: header only, O(1)
// const f = try trie.Frozen.loadVerified(buf); // untrusted file: + body CRC

const v = try f.lookup("praha");               // ?u32

var results: [10]trie.Completion = undefined;
// key_buf is SHARED across the N result slots: it must hold results.len ×
// (longest completion). topN slices it into results.len equal strides, so an
// undersized buffer yields error.KeyTooLong. Size it N × max-key, not max-key.
var key_buf: [10 * 128]u8 = undefined;
const top = try f.topN("p", &results, &key_buf, .{});
// top.items ranked best-first; top.status == .complete or .truncated_budget

var it = try f.prefixIterator(gpa, "p");        // lexicographic enumeration
defer it.deinit();
var kb: [256]u8 = undefined;                    // one key at a time: max-key is enough
while (try it.next(&kb)) |c| { /* c.value, c.key */ }
```

A `Completion.key` borrows the caller's `key_buf`; it is valid only until that
buffer is reused. `loadVerified` adds a one-time full node-region CRC check for
files crossing a trust boundary; queries are bounds-checked either way.

### Build-time memory

The frozen buffer is compact (~40 B per key) and the **query side allocates
nothing** on the `lookup` / `topN` paths — that is the deployed hot path and it
is lean. The **build** phase, however, is allocation-heavy: each trie node holds
two independently grown arrays (child labels + child ids), i.e. two allocations
per node, and a large key set is millions of nodes. Consequences the caller must
know when building at RÚIAN scale (millions of keys):

- **Do not build under a debug/safety allocator** (`DebugAllocator`,
  sanitizer-style GPAs). Per-allocation metadata over millions of tiny
  allocations can balloon RSS by an order of magnitude and OOM the process.
  Use `std.heap.smp_allocator` / a plain general-purpose allocator (or
  `page_allocator`) for the build.
- A bare `ArenaAllocator` keeps memory *simple* but *retains* every intermediate
  buffer left behind by array doubling (no reuse), costing ~1 KB transient per
  key. Fine up to a few hundred k keys; for millions prefer a freeing GPA.
- Measured (freeing arena, this repo's host): build RSS grows **linearly** at
  ~1 GB per 1 M keys; the frozen output is ~40 MB per 1 M keys. Freeze is a
  one-time cost; ship the frozen buffer and never build in the request path.

A lower-allocation two-pass builder (exact-size child arrays) is a planned
optimization — see `SPEC.md`.
