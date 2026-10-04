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
  autocomplete lineage. (This build is a path-compressed byte-labelled trie,
  not a minimized FST/DAFSA; see `SPEC.md` for the A-vs-B decision and the
  deferred minimization.)
- **Platform:** any — pure logic, no OS dependency (the only clock use is
  test-only benchmarking). **Role:** util. **Concurrency:** `reentrant` — a
  frozen buffer is immutable, so any number of threads may query one buffer
  concurrently with no synchronization.
- **Deps:** none (`std` only).

> **Status: implemented (scope core since 2026-10-04).** Build → freeze →
> zero-copy load → query is complete and tested. Frozen format **version 2**
> (path-compressed, written by a streaming builder) is the default: the RÚIAN
> address index went from 397 MB to 70 MB (140 → 24.6 B/key) and `topN` got 4×
> faster; version-1 files still load. A naive sorted-slice oracle differential (randomized, over
> adversarial key sets — prefix-of-another, duplicates, single-byte, very long,
> shared-prefix, multi-byte UTF-8) pins `lookup`, prefix enumeration, and
> top-N ordering; a corrupt-buffer fuzz harness pins the untrusted-buffer
> loader; hand-malformed positive controls prove the checkers have teeth. See
> `SPEC.md` for the wire format field-by-field and the threat model.

Provenance: original work of the zig-libs authors (MIT) — the frozen
autocomplete index. Design references, approach only: BurntSushi's `fst` (Rust,
**MIT OR Unlicense**) and Lucene's FST (**Apache-2.0**). No source consulted or
copied.

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

// Next page of a ranking: everything ranked after the last item shown.
const page2 = try f.topN("p", &results, &key_buf, .{ .after = top.items[top.items.len - 1] });

// A lexicographic range (fst's `range`); bounds may be open (null).
var r = try f.range(gpa, .{ .lo = "pl", .hi = "pr" }, 10_000);
defer r.deinit();

// Stored keys that are prefixes of a text (marisa's common-prefix search).
var ps = try f.prefixesOf("prahasever 12");
while (try ps.next()) |c| { /* "praha", "prahasever", … shortest first */ }
const longest = try f.longestPrefix("prahasever 12"); // ?Completion

// Rank ↔ key (marisa's reverse lookup), on a buffer frozen with ordinals.
const obuf = try b.freezeWith(gpa, .{ .v2 = .{ .ordinals = true } });
const o = try trie.Frozen.load(obuf);
const rank = try o.ordinal("praha");           // ?u32, 0-based in sorted order
const back = try o.keyAt(rank.?, &kb);         // ?Completion

// Streaming build from keys already in ascending order — to any writer, in
// memory proportional to the longest key, not to the index (fst's model).
var sb = try trie.SortedBuilder.init(gpa, w, .{}); // w: *std.Io.Writer (a file, a socket)
defer sb.deinit();
try sb.insert("plzen", 90);
try sb.insert("praha", 100);
try sb.finish();
```

`Builder.freezeTo(writer, opts)` streams an unsorted in-memory build the same
way. `freezeWith(gpa, .v1)` still writes version 1 for a reader built against
an older module.

A `Completion.key` borrows the caller's `key_buf`; it is valid only until that
buffer is reused. `loadVerified` adds a one-time full node-region CRC check for
files crossing a trust boundary; queries are bounds-checked either way.

### Build-time memory

The frozen buffer is compact (24.6 B per key on the RÚIAN address index in
version 2) and the **query side allocates nothing** on the `lookup` / `topN` paths — that is the deployed hot path and it
is lean. The **build** phase keeps the whole trie in just **two growable pools** (a node
pool + an edge pool), so a millions-of-keys build is a handful of allocations,
not two per node. That makes build RSS both low and **allocator-insensitive** —
it does not blow up under a debug/safety allocator. Measured on this repo's host
(synthetic address keys): build RSS is **linear**, ~80–300 B per key
(≈ 80–300 MB per 1 M keys, freeing GPA at the low end, bare arena at the high
end). Freeze is a one-time cost — ship
the frozen buffer and never build in the request path. A bare `ArenaAllocator`
still costs a little more than a freeing GPA (it never reuses a pool's old halves
after a realloc), but both are safe at scale; see `SPEC.md` for the numbers.

### Frozen size depends heavily on how much keys share prefixes

Version 2 (2026-10-04) compresses every single-child chain into one node, so
an unshared key suffix costs about its own bytes instead of 16 bytes per byte.
Measured on qap's real RÚIAN indexes (same keys, v1 → v2):

| index | keys | v1 | v2 | v2 + ordinals |
|---|---:|---:|---:|---:|
| addresses | 2 835 455 | 397 MB, 140.0 B/key | **69.7 MB, 24.6 B/key** (5.7×) | 84.4 MB, 29.8 B/key |
| streets | 97 179 | 12.3 MB, 126.9 B/key | **2.5 MB, 25.7 B/key** (4.9×) | 3.1 MB, 31.7 B/key |

The bytes-per-key ratio is still a function of how much the keyset shares
prefixes. Version-1 measurements across corpus shapes (A1 trie F7,
2026-09-11; v2 is smaller on each, most on the long-suffix ones):

| corpus | B/key | × raw key bytes |
|---|---:|---:|
| clustered addresses (this module's target use case) | **18.5** | 0.72x (compression) |
| 6-byte keys, alphabet 256 | 55.7 | 9.28x |
| random hex, 12 chars | **102.9** | 8.57x |

On the target corpus (clustered, prefix-sharing keys) the trie **compresses**
below the raw key bytes. On high-entropy keys with little shared prefix
structure it inflates well past them, because there is almost nothing to
share. **`trie` is the wrong data structure for high-entropy / random keys** —
pick it when keys cluster by prefix, not as a general-purpose key→value store.
