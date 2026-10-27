# brotli — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-27** — **Performance:** `.q0`'s command loop is instantiated per hash-table size (9/11/13/15 bits, as google's `BrotliCompressFragmentFastImpl*`): 3–5 % fewer instructions; bench `c_q0_*` 0.92–1.06× google (was 0.99–1.09×; part of it layout). Output byte-identical. No API change.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-23** — **Fix (performance):** `Decompressor` refills its buffer on small reads. Zig 0.17's `defaultReadVec` streams straight into the caller's slice once the buffer has been filled to its end, so every later small `readSlice*` re-entered the decoder for that many octets. Regression test with a negative control. No API change.

- **2026-10-18** — Ported to Zig 0.17.0: comptime `strRepeat`/`arrRepeat` branch quota scaled with length.
- **2026-10-17** — Test-only: the guard-page buffer behind the fuzz harnesses is now `testkit.guard.Guarded` (the same layout; `stream_test.Guarded` re-exports it). **NO CONSUMER-VISIBLE CHANGE.**
- **2026-10-16** — New `parallel.compress(gpa, io, input, opts, .{ .job_size, .threads })`: multithreaded compression of one stream (as rust-brotli's `compress_multi`). Jobs of `job_size` bytes (default twice the window, at least 1 MiB) run on `io`'s concurrent tasks plus the calling thread and join into one ordinary stream; each job sees the window before it (copies across the cut) and starts from a distance ring nothing matches. The bytes depend on `job_size`, never on the worker count; one job is `compressWith`'s bytes; a prefix dictionary compresses in one pass. Cuts cost 0–9 % CPU and ±0.03 % of size at 4 MiB jobs. `gpa` must be thread-safe. Scope line now **parity — google/brotli 1.2.0** (S2): every substantial feature of the field (`~/CML/20261016-brotli-s2/gap-analysis.md`); the remaining speed rows outside the bench and niche features are Backlog R18–R20.
- **2026-10-16** — New `Mode` (`.generic`, `.text`, `.font`; google/brotli's `BROTLI_PARAM_MODE`) in `CompressOptions.mode` and `StreamOptions.mode`, with google's effect (`ChooseDistanceParams`): `.font` writes NPOSTFIX 1 / NDIRECT 12 from `.q4` up, `.q11` also tries that pair where its search does not reach it, `.text` is declarative. Real fonts: `.q6`/`.q9` −0.1…−1.0 % (google −0.1…−0.8 % at q5/q9). `.generic` streams unchanged; new interop variants `font_q4`, `font_q6`, `font_q9`, `font_q11` and `stream_font_q6` blessed by google/brotli 1.2.0.
- **2026-10-16** — `StreamWriter`: a warm writer allocates nothing — the next stream after `reset` makes no allocator call at any level (the block writer's allocations come from an arena the core keeps since the R16 change); new test, and SPEC R1's "not allocation-free yet" closed. New backlog item R17: google's q7–q9 try 10/16 last distances, `.q9` four. Tests and docs only.
- **2026-10-16** — Mutation run over the code of R6, R14 and R16 (30 mutants, schemata: the prepared dictionary's build, `DictRef.search`/`collect`, the dictionary at `.q1`/`.q4`, word ids past a dictionary, `Compressor`/`Core.reinit`, `Core.kindFor`, the five-byte hash): 25 killed by the suite, 5 more after new tests — `DictRef.collect` returns only copies of at least four bytes (a hash-colliding bucket over sixteen letters), `History.shiftPos` at the cut, `WideMatcher` comparing tags on text, a stream's dictionary copied (the caller's buffer overwritten after `init` and `reset`), `Core.reinit` leaving zero counts as `init` (through the output this one was all but invisible: a slot left over either holds a position the new call inserts again or is overwritten before it is read). Tests only.
- **2026-10-16** — Encoder, inputs of 1 MiB and more (R14): `.q6`/`.q9` hash five bytes into google/brotli's 2^15 buckets (**following google/brotli 1.2.0 H6/H68, `hash_longest_match64_inc.h`, MIT**; attribution in NOTICE) where google takes that hasher — a size hint (one-shot: the input) of at least 1 MiB and a window of 19–24 bits; `.q6` 32 slots a bucket, `.q9` 256. Five natural 1.3–5.8 MB inputs vs google: sizes −1.3…+4.7 % → −1.6…+2.8 % (`oui.txt` `.q6` +4.7 → +1.8 %), time `.q6` 0.98–1.25× → 0.96–1.11×, `.q9` 0.83–1.17× → 0.89–1.12×. **Streams of `.q6`/`.q9` changed** for inputs of 1 MiB and more (re-blessed by google/brotli, 789 checks, 0 mismatches); smaller inputs unchanged.
- **2026-10-16** — Prepared dictionaries and a reusable encoder (R6, R16). New `PreparedDictionary` (**ported from google/brotli 1.2.0 `compound_dictionary.c` / `hash.h`, MIT**, attribution in NOTICE): a raw prefix dictionary hashed once into a table of its own, lent to any number of compressions through `CompressOptions.prepared_dictionary`, `StreamOptions.prepared_dictionary` or `dcb.compressPrepared` (its `digest` is the `dcb` header's SHA-256; `dcb.headerFrom`). The dictionary no longer sits in front of the input: it is searched beside the match finder at every lookup, and a raw `dictionary` is prepared per call, so raw and prepared give the same bytes. Against google with its dictionary prepared once (4–32 KiB responses, 16–256 KiB dictionaries): `.q6` 0.98–7.03× → 0.90–0.97× its time at its size (html was +5.8/+8.1 %), `.q4` 1.35–8.25× → 0.83–1.02× and 9–18 % smaller (google's q4 does not search a dictionary), `.q9` 0.10–0.16×, `.q11` 0.70–0.85×. `.q9`/`.q11` use static-dictionary words with a prefix dictionary too; `.q1` searches it (one position a miss), `.q0` does not (google's quality 0). New `Compressor`: `compressWith`'s bytes call after call with the tables, the block writer's buffers and the output buffer kept — under `smp_allocator` 4–64 KiB `.q6` 1.10–1.83× → 0.89–1.11× google's time, and memory flat where one-shot calls grow (**Zig 0.16 `smp_allocator` leaks** on a buffer grown through its size classes, one thread: `.q4` +41 KB a call on a 4 KiB input; SPEC R16). `tableSize` lost its `dict_len` argument; `Effort.searchesDictionary`. **Streams with a prefix dictionary changed** at every level but `.q0` (re-blessed by google/brotli, 789 checks, 0 mismatches); streams without one unchanged.
- **2026-10-16** — Mutation run over the code since the last one (the `.q11` zopfli parse, R16, R14; 48 mutants): 46 killed, 2 equivalent (the smoothing's first limit offset — `256·c − ⌊256·S/3⌋` never falls in the 20 between +400 and +420 — and an all-zero stride's mean), after new tests: a fifth smoothing histogram pinned to google (`>=` at the streak bound), `MinCopyLen`'s length buckets, `chooseDistParams`' search order, the 0.2-bit threshold of the thirteen contexts, a stream with a 1 MiB `size_hint` giving `compressWith`'s bytes, and google's rule that a ring length an earlier short code reached is not tried at a later one (`relaxRingHits`, split out of the parse loop for it). Streams unchanged.
- **2026-10-16** — Encoder, inputs of 1 MiB and more (R14): `.q6`/`.q9` model literals with google/brotli's thirteen static contexts where its test says they pay (**ported from google/brotli 1.2.0 `ShouldUseComplexStaticContextMap`, MIT**; `StreamWriter` with `size_hint` ≥ 1 MiB alike), and `.q9`'s match table may grow to 16 MiB (was 4 MiB; google q9 32 MiB). Five natural inputs of 1.3–5.8 MB vs google: sizes +1.0…+7.1 % → −1.3…+4.7 %, `.q9` time 1.16–1.64× → 0.83–1.17×; `.q6` now 0.98–1.25× (the contexts cost it 3–12 %). **Fix:** a meta-block with no literals under two or more literal contexts (a block that is one copy of earlier text, Cyrillic or other multi-context input) failed and was stored uncompressed. **Streams of `.q6`/`.q9` changed** for inputs past 512 KiB (re-blessed by google/brotli, 789 checks, 0 mismatches).
- **2026-10-16** — Encoder: meta-block codes are built from counts smoothed for their run-length coded header, **ported from google/brotli 1.2.0 `BrotliOptimizeHuffmanCountsForRle` (`entropy_encode.c`), MIT** (attribution in NOTICE; pinned to google's own function by a test), at `.q4` and up as google does from quality 4: on fonts the code headers were 3.5× google's (64 KiB slice at `.q6`: 2 403 → 686 B, google 686). `.q6` skips through literal runs and bounds inserts inside runs as google's `CreateBackwardReferences` does, and both `.q6` and `.q9` take two-byte copies at the second-last distance too. Bench payloads: font `.q6` 118 465 → 117 002 B, `.q9` 117 868 → 115 737, `.q11` 101 326 → 101 155; text, html, json ±0.1 %. Time (R16): `.q6` on 4–64 KiB inputs 0.93–1.45× → 0.87–1.10× google's (both on glibc's malloc), font payload −30 %; `.q9` font −10 %. Also faster, output unchanged: the Huffman keys are Shell-sorted (as google; `std.sort.pdq` swapped them through byte stores), the code-length code needs no decoder table, `bitsEntropy` keeps four sums, distance histograms and contexts are cleared and costed only as wide as used, the context map's best try is spliced instead of rewritten, distance short codes come from google's nibble tables, `.q4` fills no symbol arrays for a split it does not make (`.q4` html −3 %). Bench: every row within 1.07× of google/brotli (was 1.10×). **Streams of `.q4`, `.q6`, `.q9` and `.q11` changed** (re-blessed by google/brotli, 789 checks, 0 mismatches).
- **2026-10-16** — Encoder `.q11`: the shortest-path parse is now google/brotli's zopfli — copies are tried from the eight cheapest earlier copy ends, each with its own distance ring, where it kept one path per position — plus NPOSTFIX/NDIRECT chosen per meta-block and the nearest 2- and 3-byte copies as candidates. At quality 11's size on fonts (NotoSansEthiopic 103 706 → 98 537 B, q11 98 632; NotoSansMono +2.2 % → +0.86 %) and below it on text (`alice29.txt` 46 903 → 46 378, q11 46 487), in 0.40–1.0× its time. Output of `.q11` changes (re-blessed by google/brotli).
- **2026-10-16** — Mutation run over the `.q0` port and the branch-free decoder refill (31 of 32 killed, 1 equivalent): a `HotBits.top` test from every bit count, a `q0ShouldMerge` test at its bound, and five interop entries blessed by google/brotli — shapes `lengths`, `random_8000_copy`, `alice_3000`, `alice_65536` and the first streamed `.q0` encoding (`stream_q0`).
- **2026-10-16** — Decoder: the command loop's refill before a command header or distance is branch-free (it was a third of the branch misses on text) and the loop takes `self` and the output `noalias`: text decoding 1.14× → 1.02× google's, others 0.92–1.01×. Every bench row is now within 1.08× of google/brotli (P2).
- **2026-10-16** — `.q0` is google/brotli's quality 0, **ported from google/brotli 1.2.0 `c/enc/compress_fragment.c`, MIT** (attribution in NOTICE): one pass that writes each match as found, a literal code from the block's bytes, the command and distance codes of the previous meta-block. Time 1.2–1.55× → 0.98–1.07× google's q0 (bench); sizes now within ±0.1 % of q0's (the old design's were 0–16 % smaller, at 1.2–1.55× the time). `.q0` no longer copies from a raw prefix dictionary (google's quality 0 does not either). `.q1` unchanged.
- **2026-10-15** — Mutation run over the code added since 2026-10-04 (28 mutants: hot literal loop, refill, copy slack, R15, R16, greedy splitter): 26 killed, 2 equivalent, after six new tests — a hand-built stream whose command header needs a second refill near the end of the input (decoded from the bytes before an unreadable page; `stream_test.Guarded` is now `pub`), `findWord` past the farthest distance code, the splitter's 256-type cap and last-type preference, `chooseStaticContexts` at both thresholds. Tests only.
- **2026-10-15** — Fuzz driver: the input and `decompressInto`'s exact-size output sit flush against an unreadable page, so a read or write past them by the decoder's unchecked hot loop faults at once (planted over-reads caught at seed 36; before, invisible to the differential verdicts); dictionaries built once per process, 3× the runs per second. 360 000 runs clean. Tests only.
- **2026-10-15** — `.q6`/`.q9`/`.q11` size the match finder's table to the input: 2–8 slots a byte (`Effort.slotsLog`) up to the old cap, instead of one bucket a byte, which gave a 16 KiB input `.q6`'s whole 2 MiB and a 4 KiB one `.q9`'s 4 MiB — fresh pages every call under an allocator that unmaps them (R16). Inputs of 4–16 KiB: `.q6` 1.7–3.1× faster, `.q9` 1.2–5.2×; 64 KiB 1.1–1.3×; sizes ±0.3 %; inputs from 128 KiB (`.q6`/`.q9`) unchanged. `compressWith` sizes the table for at most the window (`encoder.tableSize`, shared with `StreamWriter`, so a stream without a flush stays `compressWith`'s bytes). Fixtures re-captured; libbrotli 1.2.0 accepts all 737.
- **2026-10-15** — `.q9` uses static-dictionary words where the hash finds no copy (R15), as google/brotli's qualities 5–9 do (`Matcher.findWord`; new `dictionary_hash.zig`, the bucket table **ported from google/brotli 1.2.0 `dictionary_hash.c`, MIT**, attribution in NOTICE, built at comptime and pinned to google's table by SHA-256): `alice29.txt` 51 361 → 50 994 B (q9 51 054), html −0.6 %, json −0.26 %, `cp852-utf8` 541 → 500, fonts ±0.1 %; time ≈ unchanged (instructions ±1 %). `.q6` streams are unchanged — the same search cost it 5–10 % of its time (R15 in SPEC). The hot match-finder functions are 64-byte aligned: their placement had moved `.q6` by 5–10 % between unrelated builds on the measuring host.
- **2026-10-15** — Decoder speed, after google/brotli's (`decode.c`): a run of literals that needs no check — within the insert and the block, and what the input holds at 15 bits each — is decoded in a loop of its own into a local pointer with the tables and the two context bytes in locals (inserts of 8 literals or more); every prefix-code root is 8 bits wide (short codes repeated), so a symbol is masked with a constant; the hot loop decodes through the entries' pointer, not the `Table`. vs google/brotli 1.2.0 (bench, into a buffer): text 1.155× → 1.13×, font 1.14× → 0.98×, json 0.96× → 0.91×, html 1.00× → 0.99×. Output unchanged; damaged streams checked under valgrind (1 024 truncations/mutations of the reference streams, both decode paths; a loosened input bound is caught).
- **2026-10-15** — `.q6`/`.q9` build the meta-block as google/brotli's qualities 4–9 do (new `greedy_split.zig`, **ported from google/brotli 1.2.0, MIT**, attribution in NOTICE): greedy one-pass block splitting of literals, commands and distances and a static UTF8 literal context map of one to three contexts chosen from sampled bigram entropy, no clustering (the clustered model and iterative splitter stay at `.q11`). `.q6` on binary data compares a bucket's 32 slot tags in one vector operation (H58's idea, tags kept in the slots); the writer skips literal contexts when each block type has one code. vs google/brotli 1.2.0 (bench): `.q9` font 1.89× → 0.72×, text 1.02× → 0.91×; `.q6` font 1.42× → 1.03×, html 1.10×, text 1.05×. **Streams of `.q6`/`.q9` changed** (re-blessed by libbrotli 1.2.0, 737 checks, 0 mismatches); sizes now near the reference's (`alice29.txt` `.q6` 52 275 vs q6 51 967; font `.q9` 117 940 vs 114 948) — smaller inputs lose what static-dictionary words would win (`cp852-utf8` 436 → 542 B, q6 482; SPEC R15).
- **2026-10-15** — New levels `Effort.q0` and `Effort.q1` (R13): google/brotli's two fastest qualities, own design — one candidate per lookup, the first match taken, a step that grows through data that stopped matching, commands resolved during the parse, one code per category, and a block that would not shrink stored without being written. `fromQuality(0)`/`(1)` now give them (were `.q4`). vs google/brotli 1.2.0 (bench payloads): `.q1` 0.84–0.97× q1's time at about its size; `.q0` 0.97–1.55× q0's time, 0–16 % smaller. Every level: prefix codes are built without the decoder's table and with one sort of packed keys (streams unchanged). Interop corpus: q0/q1 streams blessed by libbrotli 1.2.0.
- **2026-10-15** — **BREAKING (rename):** `Effort` levels are named after the google/brotli quality they stand in for: `.fast` → `.q4`, `.best` → `.q9`, `.max` → `.q11`; `.default` stays (a declaration, = `.q6`). The old names read as Go's `BestSpeed`/`BestCompression`, which they were not. New `Effort.fromQuality(0..11)` (nearest level at or above; 0..3 → `.q4`) and `Effort.quality()`. The bench now pairs `.qN` with quality N by name and prints the quality closest in size as a check; info rows `c_q4_vs_q0_*`/`c_q4_vs_q1_*`. Streams unchanged (interop fixture relabelled, digests identical).
- **2026-10-15** — Encoder speed on binary data (R12): the deep match finder's slots carry an 8-bit tag of their position's hash while positions fit in 24 bits, and in a block that looks binary (control bytes text has not) a lookup skips slots of another tag without touching the data — on a font 66 slots visited per lookup, 11 with the same first four bytes; a stream whose history passes 16 MiB drops the tags once. Below 16 384 literals a literal context mode is clustered only when its unclustered entropy plus the least header cost can still beat the best so far (same choice as clustering all three). The context histograms are cleared with vector stores. vs google/brotli 1.2.0: `font` `.best` 2.61× → 1.85× q9, `.default` 1.48× → 1.36× q6, `.max` 0.31× → 0.27× q11; text rows ≤ 1.09× (`.best` text 1.08× → 1.02×). Streams unchanged.
- **2026-10-15** — Encoder speed on binary data: the literal context mode is chosen by the unclustered context entropy when a block has 16 384 literals or more (only the winner is clustered; it picked what clustering all three picks on every block measured), and `.default` skips through long literal runs as `.fast` does. Bench payload `font` (200 KB, `interop_corpus.fontLike`) added: `.default` 2.34× → 1.44× google q6 there, `.best` 2.6× q9 (open), `.fast` 0.60× q4, `.max` 0.32× q11; text payloads unchanged (≤ 1.08×). `.default` streams changed on binary data (re-blessed by libbrotli 1.2.0).
- **2026-10-15** — Encoder: block splitting at `.best` and `.max` (RFC 7932 §6; R12): literals, insert-and-copy symbols and distances each in blocks of up to 32 types with codes of their own, a context mode and map per literal block type; context maps written with zero-run codes and move-to-front when shorter (every effort). Fonts: NotoSansMono-Thin `.best` 221 779 → 208 252 B (q9: 216 149), `.max` 213 980 → 202 202 B (q11: 197 771); a generated font-shaped payload `.best` 112 340 → 103 651 B (q9: 114 773). Text ±0.5 %. Time: `.best` +30 % on text. New interop shape `font_like` (`interop_corpus.fontLike`). **Streams changed** (re-blessed by libbrotli 1.2.0).
- **2026-10-15** — **Decoder and encoder fix (interop):** the UTF8 literal context mode classed the byte two positions back as 2 for 0xD0..0xDF, where libbrotli classes it 0 (16 of the 2048 entries of the shared context table). google/brotli's streams of UTF-8 text in Cyrillic, Armenian, Hebrew, Arabic, Syriac or Thaana (lead bytes 0xD0..0xDF) from quality 5 up were refused (`InvalidDictionary`) or decoded to wrong bytes, and our own streams of such text were misread by every other decoder (browsers). The table is now pinned to libbrotli's by digest; a generated seven-script UTF-8 input (`tools/gen_utf8_mix.py`, `testdata/utf8-mix`) joins the interop corpus both ways (reference streams at q5/q9/q11, and our four efforts). Found while splitting blocks on fonts (R12).
- **2026-10-15** — Encoder: copies of two bytes at the last distance (an implicit-distance command; `.max` also at the other ring distances, priced exactly). google/brotli leaves thousands of them in fonts (q11: 4 396 on NotoSansMono-Thin, we had none). NotoSansMono-Thin `.default` 222 665 → 221 136 B, `.max` 216 315 → 213 980 B; `alice29.txt` even. **Streams changed** (re-blessed by libbrotli 1.2.0).
- **2026-10-15** — Encoder fix: the encoder's copy of the decoder's distance ring was `{d, d, d, d}` after every push (an array literal assigned in place read `last[0]` after overwriting it), so short codes 1–3 and 10–15 were never used and the matcher's ring probes saw one distance. Streams were valid (only codes 0 and 4–9 were emitted, and those depend on the last distance alone) but larger. Now fixed and tested; the matcher tries all four ring distances; literal context mode SIGNED is tried alongside UTF8 and LSB6 for blocks that are not nearly all ASCII. Fonts (R12): NotoSansMono-Thin `.default` 230 674 → 222 665 B, `.max` 225 308 → 216 315 B; text even (`alice29.txt` `.default` 51 467 → 51 320 B). **Streams changed** for every effort (re-blessed by libbrotli 1.2.0).
- **2026-10-15** — Decoder speed: the command loop keeps the bit reader in locals (`HotBits`) with a branch-free refill while 16 input bytes are at hand, and hands a command to the general path near the end of the input or a chunk. vs google/brotli 1.2.0: json 0.91×, html 1.01×, text 1.15× (were 1.09–1.21×). Same results and errors (differential fuzz driver, 60 000 runs).

- **2026-10-15** — Encoder: `.max` 1.02–1.47× → 0.43–0.77× the time of google/brotli q11 (bench payloads): the dictionary search tries only the prefixes a position can start with, rejects a word by its folded first four bytes and picks the transform cuts from the matched length; the distance code is computed instead of scanned (every effort gains). The block writer re-makes every dictionary word as the decoder will and refuses a parse whose word would differ. `.max` streams changed slightly (≤ 16 candidates per position; re-blessed by libbrotli 1.2.0).

- **2026-10-15** — Encoder: new `Effort.max` (R2) — a shortest-path parse of every block priced from the block's own statistics (a greedy parse and two refits; the shortest as written wins), static-dictionary words with 113 of the 121 transforms (identity, OMIT_LAST_n, UPPERCASE_FIRST/ALL, with their prefixes and suffixes), up to 48 candidate copies per position. `alice29.txt` 46 935 B: 0.96 % behind google/brotli q11 (46 487), 1.1 % below q10; several times `.best`'s time. Every effort now also picks per block how many codes the four distance contexts (copy length 2, 3, 4, 5+) share — `.default` 51 467 → 51 327 B, `.best` 50 736 → 50 536 B on `alice29.txt`: **those streams changed** (re-blessed by libbrotli 1.2.0; still valid for every decoder). Additive API.

- **2026-10-15** — Decoder: serialized shared dictionaries (R7, RFC 9841 §5) — `parseSharedDictionary`, `Options.shared_dictionary`: custom word lists and transforms (incl. ShiftFirst/ShiftAll), context-chosen pairs, an LZ77 part. Transform triplets in google/brotli's byte order (prefix, operation, suffix), which differs from RFC 9841's text. Anchored on 15 streams of google/brotli 1.2.0 built with BROTLI_EXPERIMENTAL (interop `--brotli-src`), committed under `testdata/ref/serial/`. Additive API.

- **2026-10-15** — Encoder speed back: the dictionary support in the match finders is a comptime switch, so a search without a dictionary is the loop it was before (the per-candidate test had cost `.best` +20–27 %, `.default` +7–12 % since the R6 encoder). vs google/brotli 1.2.0: fast 0.96–1.12× (q4), default 0.97–1.04× (q6), best 0.70–0.86× (q9), decoder 1.09–1.21×. Streams unchanged.

- **2026-10-15** — Decoder: the fill bits after the last meta-block must be zero (RFC 7932 §9.2) — **behaviour change**: such a stream (e.g. the single byte `0xff`) is now `InvalidPadding`, as google/brotli refuses it; it used to decode. New `Options.metadata` (R10): callbacks receive metadata meta-blocks' bytes. The streaming decoders give the bit reader's read-ahead back to the source at the end of the stream (R11; source buffer ≥ 16 bytes), so `in` is left exactly after the stream and streams decode back to back.

- **2026-10-15** — New `Decompressor` (R9): a pull `std.Io.Reader` over a stream's decompressed bytes, decoding as reads need it (the decoder suspends mid-command and at meta-block ends); `err` holds the cause of a `ReadFailed`. `decompressStream` is now a loop over it (same results; output goes out as the reader hands it). The decoder is one resumable logic for all four entry points; measured cost on `d_*` against before: +4–9 %. Additive API.

- **2026-10-14** — Encoder: large-window streams (RFC 9841 §6) with `window_bits` 25..30 (`max_large_window_bits`; `CompressOptions`, `StreamOptions`) — the header, the large distance alphabet; blessed by libbrotli 1.2.0 (a copy from 17 MiB back). Completes R8. Streams at 10..24 unchanged. Additive API.

- **2026-10-14** — Decoder: large-window streams (RFC 9841 §6) with `Options.large_window` (off by default, as google/brotli): WBITS up to 62 (30 on 32-bit targets), the 62-bit distance alphabet read with google/brotli's limit of distances below 2^31. Six libbrotli large-window streams (copies from 17 MiB back) committed under `testdata/ref/large/` and replayed. Additive API.

- **2026-10-14** — Encoder: raw prefix dictionaries (`CompressOptions.dictionary`, `StreamOptions.dictionary`) — sizes within libbrotli's q5–q9 at `.default`, below q9 at `.best` on the interop dictionary cases; 15 of our dictionary streams blessed by libbrotli 1.2.0 and replayed. New `brotli.dcb` (RFC 9842 `Content-Encoding: dcb`: header, compress, decompress; errors `NotDcb`, `DictionaryMismatch`). Completes R6. Streams without a dictionary unchanged. Additive API.

- **2026-10-14** — Decoder: raw prefix dictionaries (RFC 9841 §3.2, what RFC 9842 `dcb` uses) — `Options.dictionary`, in `decompress`, `decompressInto` and `decompressStream`. The interop program gains a second reference, libbrotli itself (`tools/c_oracle/shared_oracle.c`, built with `zig cc`; the Python binding cannot attach a dictionary): 20 of its raw-dictionary streams are committed under `testdata/ref/dict/` and decoded by all three decoders in the replay test. Additive API.

- **2026-10-14** — New `StreamOptions.size_hint` (R3): the stream's match-finder table sized for the expected length instead of the window (a short response no longer allocates and clears 1–2 MiB); with the exact length the stream equals `compressWith`'s bytes for any input. `reset` keeps the table while its size stays. Additive API.

- **2026-10-14** — New `StreamWriter.writeMetadata(bytes)` (R5): a flush, then metadata meta-blocks (up to 16 MiB each) that decoders skip — google/brotli's `EMIT_METADATA`. Interop corpus: a `stream_metadata` variant, blessed by google/brotli 1.2.0 (326 checks, 0 mismatches). Additive API.

- **2026-10-14** — New `compressInto(gpa, out, input, opts)` (no output allocation; `error.OutputTooLarge` only when the stream `compressWith` gives does not fit) and `maxCompressedSize(n, opts)` (exact: incompressible input reaches it) — R4. Streams unchanged. Additive API.

- **2026-10-14** — New `StreamWriter` (R1): a `std.Io.Writer` that compresses into one stream — `flush` byte-aligns everything so far with an empty metadata meta-block (as google/brotli's flush), `finish` ends the stream, `reset` starts the next on the same table and history; without flushes the bytes `compressWith` gives with the same options. New `CompressOptions.window_bits` (10..24; null keeps the old choice, 16 or 21) and `StreamOptions.window_bits` (default 22); `min_window_bits`/`max_window_bits`. `compressWith` and the stream share one encoder core. Interop corpus: encoding variants (windows 10/15/17/24, two streamed with flushes) blessed by google/brotli 1.2.0 (322 checks, 0 mismatches); the 135 existing streams unchanged. Additive API.

- **2026-10-14** — Encoder: `.fast` is an algorithm of its own (`FastMatcher` + `buildCommandsFast`): 4 slots per bucket of a 6-byte hash, a slot picked by the position's bits (an insert is one store, no per-bucket count), the last distance tried first, a lazy step only for matches under 32 bytes, every fourth position inserted inside copies over 32 bytes, growing steps (up to 16) through literal runs over 64 bytes, the literal price from every fourth byte. A context-free block writes two literal codes per bit-writer call. vs google/brotli 1.2.0 q4: fast 1.24–1.40× → 0.96–1.12×; sizes json 31 507 → 31 139, html 17 341 → 17 023, text 54 642 → 55 580 B (q4: 31 748 / 17 370 / 55 504); interop corpus at `.fast` +0.38 % in total (`alpha2_flat` +9.6 %: six hashed bytes over a two-letter alphabet). `.default`/`.best` streams byte-identical. Interop fixtures re-blessed (294 checks, 0 mismatches). No API change.

- **2026-10-14** — Encoder: `.default` and `.best` try the last two distances before the hash bucket (a copy there costs no distance bits; from 3 bytes) — `html` −5 % at both (default 15 364 → 14 546 B, now smaller than q6), `json` −1 %; the match finder prefetches the next position's bucket; a block whose literals are ≥ 95 % ASCII clusters for the UTF8 context mode only (no stream of the interop corpus changed). Bench: the effort ↔ quality pairing is now computed each run (closest sizes), it was a fixed table. vs google/brotli 1.2.0: fast 1.24–1.40× (q4), default 1.02–1.06× (q6), best 0.75–0.91× (q9). Interop fixtures re-blessed (294 checks, 0 mismatches). No API change.

- **2026-10-14** — Encoder faster (bench vs google/brotli 1.2.0 at the paired quality: fast 1.47–1.50× → 1.34–1.48×, default 1.47–1.88× → 1.07–1.17×, best 1.05–1.60× → 0.77–0.95×). The match finder is a bucketed hash (each bucket keeps its last 8/32/256 positions) instead of a hash chain, whose walk was a chain of dependent loads; its table is 2^17/2^19/2^20 slots by effort. A block with several literal codes prices its one-code alternative on exact bits instead of writing it, and length codes come from a table. Compressed sizes move by under 0.3 % (`alice29.txt` default 51 467 → 51 536 B); interop fixtures re-blessed by the reference (294 checks, 0 mismatches). No API change.

- **2026-10-14** — Survey refreshed against google/brotli 1.2.0, RFC 9841 and RFC 9842: `## Compared with` updated, gaps R1–R11 filed in *Backlog* (streaming encoder, raw prefix dictionaries and `dcb`, large window, pull reader, serialized dictionaries for decoding, a q11-class `.max` effort). Docs only.

- **2026-10-11** — New `decompressInto(gpa, out, input, options)`: decode into the caller's buffer
  (`OutputTooLarge` when it does not fit), no output allocation. The differential fuzz driver checks it
  against the other two decoders, with an exact-size buffer and one byte short. Bench: `d_<payload>`
  now pairs it with the reference's preallocated-buffer decode (1.03–1.15×). The allocating
  `decompress` is printed as `d_<payload>_alloc`, for information only.

- **2026-10-11** — Decompression faster again (vs google/brotli: 1.49–1.78× → 1.12–1.28×): short
  back-references are 16/32-byte moves into slack the output keeps instead of `memcpy` calls, the
  bit reader refills only when short of bits, and code tables are built with `@bitReverse`. No API
  change.

- **2026-10-11** — Speed (bench vs google/brotli 1.2.0: 1.41–3.38× → 1.04–1.88×, P3). Decoder:
  two-level prefix tables (8-bit root), an 8-byte bit-reader refill, `memcpy` back-references, one
  output reserve per insert and one growth per meta-block. Encoder: the single-literal-code
  alternative of a block is written to a scratch writer instead of re-writing the winner (output
  byte-identical), the bit writer flushes 32 bits at a time, the match finder no longer clears its
  `prev` chain and fills `head` in vector stores (Zig 0.16's `memset` is byte-wise without libc), and
  match lengths are compared 8 bytes at a time. No API change.

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-brotli`): **1.41–3.38× google/brotli** — over 2×, P4. Card stays `not measured` with the numbers in *Backlog* until the module is sped up (owner 2026-10-10: a consumed module must grade 3 or better). Tooling only, no code change.

- **2026-10-04** — Builds for 32-bit and Windows: `meta.targets` is now linux64, linux32 (mips32,
  big-endian, soft-float) and windows. Window and table-size exponents are `u5` (a 32-bit `usize`
  shifts by a `u5`; they never exceed 24), and the interop corpus generator took its remainder in
  `usize`, so a 32-bit target generated different input than the reference judged. The whole
  suite passes on big-endian mips32 under qemu-mips. No change on 64-bit.

- **2026-10-04** — Fix (BEHAVIOURAL): a meta-block whose commands produced more than MLEN bytes
  (an insert, a copy or a dictionary word running past the declared length) was accepted and
  decoded to more bytes than MLEN. RFC 7932 section 9.2 requires exactly MLEN; the reference decoder
  rejects such streams, and `decompress`/`decompressStream` now fail with `InvalidLength`. Malformed
  streams that used to decode now fail; valid streams are unaffected. Found by the mutation run below.
- **2026-10-04** — Tests: dated mutation run (132 switches, 110 killed, 22 equivalent; see SPEC).
  New `src/crafted_test.zig` (hand-built RFC 7932 streams, cross-checked with the python reference
  decoder: metadata blocks, header guards, simple/complex prefix-code bounds, block-type switching,
  trivial-literal detection, dictionary and transform limits, window edge 1008/1009, MLEN overshoot,
  ring wrap in the streaming decoder, read-ahead contract), `transformWord` semantics tests
  (UPPERCASE_FIRST/ALL, OMIT_FIRST/LAST 1..9), a WBITS table test, and a `buildComplex` completeness test.

- **2026-09-30** — **Encoder: effort levels and a stronger encoder** (maturity task C19, second half).
  New `compressWith(gpa, input, .{ .effort = .fast | .default | .best })`, `CompressOptions`, `Effort`;
  `compress` = `.default`. Matches are scored by the bits they save (the block's literal entropy
  against the distance's cost) rather than by length, and reach 65 535 bytes (was 512); distance
  short codes and implicit-distance commands mirror the decoder's ring of recent distances; literal
  context modelling (UTF8/LSB6, clustered to ≤ 16 codes, checked on real bits against one code) at
  `.default` and `.best`. `alice29.txt`: 54 605 → 51 467 (default) / 50 736 (best) bytes, reference
  q5 52 809, q9 51 054; `zeros` 651 → 27. ⚠ `compress` output bytes change (still valid `br`,
  re-blessed by google/brotli): the interop fixture now blesses every shape at all three efforts
  (135 streams, `interop_blessed.zig` gains an `effort` field).

- **2026-09-30** — **Streaming decoder: `decompressStream(gpa, reader, writer, options)`** (maturity
  task C19, first half). Memory is the window — grown from 64 KiB only as far as the output needs —
  never the whole output; output reaches the writer at every meta-block end. The one-shot and the
  streaming decoder share one decoding core (`DecoderOf(Sink)`) and one bit reader, and a new
  deterministic differential fuzz driver (`BROTLI_FUZZ`) holds them to the same verdict on damaged
  streams. Also, for both: per-meta-block tables are freed at every meta-block instead of at the end
  (a long stream's tables no longer accumulate). New `StreamError`; `decompress`'s behaviour is
  unchanged (all interop replays pass as before).

- **2026-09-09** — The nine source files without an SPDX header have one: MIT, matching the
  two that already did. 229 of 231 modules carry the header on `root.zig`, and this was one
  of the two that did not — awkwardly, the module that carries an attribution CONDITION for
  its vendored `src/testdata/` corpus. The condition is unchanged and still lives in NOTICE;
  what changed is that each source file now states its own terms.

- **2026-09-07** — Fuzz reach: `fuzzDecompress` decompressed the EMPTY SLICE and nothing
  else, ever. The fourteen google/brotli reference streams were `@embedFile`d into
  `fuzz_seed_corpus` and indexed with `smith.index(...)` — but the array was **never
  handed to `std.testing.fuzz` as a `.corpus`**, so outside `--fuzz` the target ran the
  one input a corpus-less target gets: the empty one, whose every draw collapses to a
  minimum. Traced 2026-09-07: `index(14)` → 0 (`empty.compressed`, 1 octet),
  `boolWeighted(1, 4)` → false, `valueRangeAtMost(u16, 0, 1)` → 0, so `keep` = 0, no
  extension, no point damage, `decompress(allocator, buf[0..0], …)`. The keep/extend/
  damage generator and its two paragraphs of measured design justification never ran in
  the ordinary lane at all; the `@panic`-probe reachability claim was made under `--fuzz`
  and says nothing about it. The generator is gone and the reference streams are now the
  corpus they were always meant to be — a fuzzer handed real streams mutates them, which
  is what the generator was approximating. ⚠ The buffer was also 1024 octets while three
  of this module's own reference streams are 10 004, 50 096 and 50 100, so the largest
  inputs it owns could not have passed through its own harness even with the corpus wired
  up; the buffer is now 51 200 and those three are in the corpus. A corpus guard pins
  19 non-empty seeds, 18 decoded, 2 refused and **981 867 output octets** (0 before).

- **2026-09-06** — **The module no longer ships foreign source, and its test suite no
  longer needs `python3`.** `src/reference_interop.zig` — which embedded a Python
  driver and spawned `python3 -c` from inside `test-brotli` — is gone. The live
  comparison against the reference implementation (google/brotli via the Python
  `brotli` C extension) is now a standalone program, `tools/interop.zig` +
  `tools/reference.py`, run by `zig build interop-brotli` and compile-checked by
  `zig build check-interop`; it is never built by `test-brotli` and never by
  `zig build`. Consumer-visible: `zig build test-brotli` runs 53 tests with **no
  skips** where it previously ran 54 with 4 skipped on any machine without the
  package (i.e. all of CI). `zig build interop-brotli -- --capture` freezes what the
  reference did into two committed fixtures: `src/testdata/ref/*.br`, 24 streams the
  reference compressed (five qualities on `alice29.txt` as before, plus three window
  sizes and q1/q11 over the rest of the corpus — decoder coverage rises from 5 cases
  to 24), and `src/testdata/interop_blessed.zig`, which pins the SHA-256 of the exact
  stream google/brotli accepted for each of the 45 input shapes the sweep covers. An
  encoder change that alters any output now fails `test-brotli` until it is re-blessed
  against a real google/brotli. New `src/interop_corpus.zig` holds the shapes and the
  stream matrix both sides share, exposed as `brotli.interop_corpus` solely so the
  out-of-tree program can reach them; it is not part of the compression API. See
  `NOTICE` for the attribution the new `src/testdata/ref/` files carry.
- **2026-08-06** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 7932 Appendix A's
  published test vectors.
- **2026-07-29** — The encoder now actually compresses. It was store-mode only (ratio
  ~1.0); it now does LZ77 backward references plus a per-meta-block
  Huffman code for literals, insert-and-copy commands and distances, with
  the store path kept as an automatic per-block fallback whenever a
  compressed block would not come out smaller. `alice29.txt`
  152 089 -> 54 605 bytes (2.8x), between reference `brotli` quality 1 and
  5; incompressible input costs the same as it does the reference.
  `compress` keeps its signature and its "fails only on allocation,
  output is always a valid `br` body" guarantee. Not implemented (each
  costing ratio): block splitting, literal context modelling,
  static-dictionary references, `NPOSTFIX`/`NDIRECT` tuning, and distance
  short codes. Validation is anchored on the reference implementation
  rather than on this module's own decoder: `src/reference_interop.zig`
  decompresses everything the encoder emits with google/brotli (Python
  `brotli`) across a property sweep of input shapes, and skips loudly
  when python3 or the package is missing.
