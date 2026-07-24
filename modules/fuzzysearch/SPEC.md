# fuzzysearch — SPEC

Bounded-edit-distance, typo-tolerant lookup over a large, static string set. Build
from `(key, value)` pairs → freeze → query the frozen buffer zero-copy for the
keys within OSA edit distance `k` of a query, ranked. See the README for the
consumer-facing contract; this document is the design rationale and threat model.

## Design decision — Levenshtein automaton over the frozen `trie`

Three structures were on the table (per the brief): (A) a Levenshtein automaton
walked over the frozen `trie`; (B) a standalone BK-tree frozen to a flat buffer;
(C) an n-gram inverted index with a distance-verify pass.

**Chosen: A — a Levenshtein automaton (incremental DP row) walked over the frozen
`trie`, reusing the `trie` wire format verbatim.** Rationale:

1. **It shares `trie`'s frozen zero-copy index and its proven, hard-won
   robustness.** The hardest part of a frozen, untrusted-file-facing index is a
   bounds-checked decoder that provably never panics / over-reads / loops on a
   corrupt buffer. `trie` already has one, plus a **strictly-increasing
   child-offset invariant** that makes traversal termination provable even on a
   hand-crafted cyclic buffer. Reusing it means fuzzysearch inherits all of that
   for free and adds only a query algorithm on top — far less new attack surface
   than a second bespoke wire format (which B and C both require).
2. **It is the natural pairing.** The same frozen buffer serves both `trie`'s
   exact-prefix completion and this fuzzy search; a deployment that ships one
   RÚIAN index gets both query shapes from one file.
3. **It prunes hard.** The DP-row-over-trie method skips a whole subtree the moment
   its row minimum exceeds `k`, and shared key prefixes are visited once. For the
   small `k` typo-tolerance actually uses (1–3), this is what delivers
   sub-millisecond latency over a large set.

Why not **B (BK-tree):** a BK-tree buckets keys by distance to pivots under the
triangle inequality. It is a fine standalone structure, but it needs its **own**
frozen format (and thus its own bounds-checked decoder + fuzz surface), it does
not share the trie index, and its pruning (triangle-inequality bands) is typically
weaker than the automaton's for the short strings and small `k` here. Why not
**C (n-gram index):** an inverted trigram index with a verify pass is excellent at
scale but degenerates for very short keys/queries (few grams), needs a separate
postings format, and the verify pass still needs an exact distance — so it is more
moving parts for no robustness win at RÚIAN scale.

The dep on `trie` was pre-wired for exactly A; A is taken.

### Metric — OSA (restricted Damerau–Levenshtein)

The distance is **optimal string alignment**: insertion, deletion, substitution,
and transposition of two *adjacent* symbols, each one edit, under the OSA
restriction that no substring is edited more than once. This is precisely what a
DP that carries the two previous rows can compute during a trie descent (the
transposition term reads the grandparent row). True (unrestricted)
Damerau–Levenshtein — which allows a transposed pair to be edited again and needs
an alphabet-indexed last-occurrence table — cannot be computed from a fixed number
of previous rows and is a **deliberately deferred** non-goal.

Distance is over **bytes**. A multi-byte UTF-8 codepoint is several byte-edits.
Unicode-aware distance (collation, case-folding, diacritic-insensitivity) is the
caller's obligation, discharged by folding keys and query identically before
indexing — the same contract as `trie`.

### Cost model

- **Build/freeze:** `trie`'s — `O(total key bytes)`, two growable pools; see the
  `trie` SPEC. `fuzzysearch` adds nothing to the build.
- **`search`:** a DFS over trie nodes, each computing a DP row of width
  `query.len + 1`. Work is `O(visited × query.len)` cell updates, hard-capped by
  `max_visited`. Row-minimum pruning bounds `visited` far below the node count for
  small `k`. **Zero allocation** — fixed inline DP-row matrix + DFS stack +
  caller-supplied result/key buffers.

## Frozen wire format

**Reused verbatim from `trie` (format version 1, magic `"ZTR1"`).** `fuzzysearch`
defines no format of its own and adds no bytes. See `trie`'s SPEC for the header
(36 bytes: magic, version, endian marker, flags, node-region length, key count,
root offset, body CRC, header CRC) and node layout (flags/terminal, optional
`value`, `subtree_best`, `edge_count`, sorted `{label, child_offset}` edges) field
by field.

`fuzzysearch` uses every trie field **except `subtree_best`**, which drives
`trie`'s value-ranked top-N pruning and is irrelevant to distance-ranked fuzzy
search; it is read past and ignored. No `format_version` bump is needed — a fuzzy
search over a v1 trie buffer is a pure read-side capability.

## DoS / bounded-work model

The exposed surface is `search(query, k, results, key_buf, opts)`. A short query
with a large `k` sits within edit distance of a large fraction of the set, so an
unbounded walk could touch most of it. `SearchOptions.max_visited` (default
**50 000**) caps the number of trie nodes the DFS may decode; on reaching it the
search stops and returns `status = .truncated_budget` with a best-effort partial
top-N. Row-minimum pruning means a well-formed small-`k` query typically finishes
far under budget, so the cap rarely bites yet always bounds worst-case latency.
`max_visited = 0` disables the cap and **must not** be used on
attacker-influenced queries or untrusted buffers.

Two further bounds keep every allocation-free inline structure finite:
`query.len ≤ max_query_len` (256, else `error.QueryTooLong`) fixes the DP-row
width; `k ≤ max_k` (254, else `error.DistanceTooLarge`) keeps the capped DP cell
(`k+1`) in a `u8`; an indexed key path deeper than `max_depth` (1024) yields
`error.KeyTooLong` rather than overrunning the inline DFS stack. Addresses are far
shorter than any of these.

### Why the pruning is correct

A subtree is skipped the instant its DP-row minimum exceeds `k`. This is safe
because the row minimum is **non-decreasing down every downward path in the trie**
— including with the OSA transposition term (the transposition candidate
`prev_prev[j-2]+1` is itself `≥ min(prev_prev)+1 ≥ min(prev)`, since the row
minimum is monotone one level up by induction). So once a node's row minimum is
`> k`, no descendant can reach a cell `≤ k`, hence none can be a match. DP cells
are capped at `k+1`: any true value `> k` never contributes to producing a `≤ k`
cell, so capping changes neither the match set nor the exact distance of any match
(a match's distance is `≤ k`, hence never capped). The differential oracle
(brute-force full-matrix OSA over every key) independently re-derives the exact
ranked match set and would catch any pruning error.

## Threat model — untrusted frozen buffers

A frozen buffer may come from a file outside the process trust boundary
(truncated, bit-flipped, or hand-crafted). Because the buffer is a `trie` buffer
and every offset is followed through `trie`'s bounds-checked `format.nodeAt` /
`format.follow`, `fuzzysearch` inherits `trie`'s guarantees:

- **Never panics, never reads out of bounds, never loops forever** on any input
  buffer. Header validation rejects short (`Truncated`), wrong-magic (`BadMagic`),
  unknown-version (`UnsupportedVersion`), wrong-endian (`BadEndian`),
  corrupt-header (`HeaderCorrupt`), and out-of-region-root (`MalformedRoot`)
  buffers; `loadVerified` adds a node-region CRC (`BodyCorrupt`). A bad offset the
  search follows yields `error.Corrupt`.
- **Termination** rests on the strictly-increasing bounded-offset invariant, not
  on trusting any length field — a corrupt `edge_count` can only make a node
  decode fail bounds-checking, never over-read; a back-pointing child offset is
  rejected, not looped. The `max_visited` budget additionally caps total work, so
  even a corrupt buffer engineered to fan out cannot hang the search.

CRC-32 is an integrity check against accidental corruption / bit-rot, **not** a
security MAC; a buffer that survives `loadVerified` is only guaranteed *safe to
search* (no crash / OOB / hang), not *trustworthy in content*. Sign the file at a
higher layer if producer authenticity matters. Same posture as `trie`.

## Verification

- **Differential oracle:** a brute-force full-matrix OSA (`distance.zig`) over
  every stored key, ranked identically, answers the same `search` queries; a
  randomized differential over generated key sets, near-miss queries (a stored key
  mutated by 0–3 edits) and `k ∈ {0..3}` must agree exactly on the ranked match
  set, and every reported distance must equal an independent recomputation. The
  oracle's incremental-DP-over-trie and the reference's full-matrix DP are
  separate implementations of the same metric — a genuine cross-check.
- **Adversarial cases:** `k=0` (exact); `k` larger than any key length (all
  match); empty query; empty key in the set; transposition neighbours; single
  substitution/insertion/deletion neighbours; multi-byte Czech UTF-8; duplicate
  keys (last-write-wins); the distance-exactly-`k`-vs-`k+1` boundary; a
  many-matches cluster hitting the budget/truncation path.
- **Corrupt-buffer fuzz:** the loader + search path are hammered with truncated /
  random / bit-flipped-from-valid buffers and must only ever return a typed error.
- **Positive controls:** a corrupted stored value makes `search` disagree with the
  oracle (and trips `loadVerified`'s CRC); a hand-built back-pointing child offset
  yields `error.Corrupt`, not a loop — proving the checks have teeth.
- **Round-trip:** in-memory brute-force answers == answers after
  build → freeze → load.
- Green in Debug and `-Doptimize=ReleaseFast`; `zig fmt --check` clean;
  `zig build check-catalog` exit 0.

No large benchmark is run: correctness is the bar and unit tests stay in the
thousands-of-keys range so `zig build test-fuzzysearch` never balloons.

## Deliberately deferred

- **True (unrestricted) Damerau–Levenshtein.** Needs an alphabet last-occurrence
  table, not computable from a fixed number of trie-descent rows. OSA is the
  documented metric; a real transposition-heavy consumer can revisit.
- **Automaton precompilation (Schulz–Mihov universal automaton).** Precompiling
  the query into a table-driven NFA/DFA can beat the per-node DP row for large
  `k`; the DP-row method is simpler, allocation-free, and ample for the small `k`
  typo-tolerance uses. Swappable behind the same `search` API.
- **Prefix-anchored fuzzy autocomplete** (fuzzy match on the typed prefix while
  still completing) — a hybrid of `trie.topN` and this walk; a plausible next
  feature, not built.
- **Weighted / custom edit costs** (keyboard-adjacency, OCR-confusion weights).
  The metric is fixed unit-cost OSA.
- **Transposition of multi-byte codepoints as a single edit.** Distance is over
  bytes; a codepoint-level metric is the caller's normalization concern.
