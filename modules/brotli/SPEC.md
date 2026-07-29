# brotli — SPEC

Pure-Zig Brotli (RFC 7932) codec. std-only, no external dependencies.

## Scope & honesty

- **Decoder — the deliverable.** Complete, byte-exact RFC 7932 decompression,
  validated against the google/brotli reference vectors (see Validation).
- **Encoder — a real, if unambitious, compressor.** LZ77 backward references
  plus a per-meta-block Huffman code for literals, insert-and-copy commands and
  distances, with a store-mode fallback for blocks that would not shrink. It
  lands between reference `brotli` quality 1 and 5 on text (see Encoder).

## Decoder — RFC 7932 feature completeness

All of the following are fully implemented:

- **Stream header**: window bits (WBITS 10..24; the large-window extension is
  explicitly rejected as `InvalidWindowBits`).
- **Meta-block structure**: `ISLAST`, `ISLASTEMPTY`, `MNIBBLES`/`MLEN`,
  `ISUNCOMPRESSED`, and metadata meta-blocks (`MSKIPLEN`, skipped); the
  "no leading-zero final nibble/byte" rules are enforced.
- **Uncompressed meta-blocks**: byte-boundary jump (padding must be zero) then
  literal copy.
- **Huffman codes**: both *simple* (1..4 symbols, incl. the 4-symbol
  tree-select) and *complex* (run-length-coded code-length alphabet with the
  fixed prefix code, `REPEAT_PREVIOUS`/`REPEAT_ZERO` 16/17, `HSKIP` 0/2/3).
  Codes are read LSB-first (canonical codes are bit-reversed into a flat lookup
  table). Kraft completeness is enforced; the single-symbol degenerate code is
  handled.
- **Block-type/count machinery** for literals, insert-and-copy commands, and
  distances (type ring buffer of 2, the `+1`/`+2` decode, block-length prefix
  code).
- **Literal context modeling**: all four context modes (LSB6, MSB6, UTF8,
  SIGNED) via the 2048-byte context lookup table; literal + distance context
  maps with RLE-of-zeros and inverse-move-to-front; the "trivial literal block
  type" fast path.
- **Command decoding**: the 704-symbol insert-and-copy alphabet via the
  generated command LUT (insert/copy length offsets + extra bits, implicit vs
  explicit distance).
- **Distance model**: `NPOSTFIX`/`NDIRECT`, direct distances, the interleaved
  regular-distance ranges, and the 16 short codes over the ring buffer of the
  last four distances (including the "double distance-ring-buffer roll"
  compensation for dictionary items).
- **Static dictionary**: RFC 7932 Appendix A word list (122 784 bytes, embedded
  as `dictionary.bin`) + Appendix B transforms (121 transforms, prefix/suffix
  pool, OMIT_FIRST/OMIT_LAST/UPPERCASE_FIRST/UPPERCASE_ALL). Word length,
  transform index and post-transform length-0 checks are enforced.

A subtle correctness point that this module gets right: a **distance block
switch re-selects** the distance htree for the current distance context (the
reference recomputes `dist_htree_index` inside the switch), not only on the
following command.

### Dictionary / transform provenance

`dictionary.bin`, the context lookup table, the transform table and the
prefix/suffix pool are **normative constants** of RFC 7932 (Appendices A/B/C).
They are reproduced verbatim (byte-identical to google/brotli, MIT-licensed).
`offsets_by_length` is derived from the Appendix A `size_bits_by_length` table
at comptime and asserted to cover the embedded data exactly.

## Encoder — what it does

One meta-block per 1 MiB of input. Each block is attempted as a **compressed**
meta-block and kept only if it came out strictly smaller than storing those
bytes verbatim; otherwise it is rolled back out of the bit writer and re-emitted
as an **uncompressed** meta-block. Implemented:

- **LZ77**: a hash chain over 4-byte hashes (chain depth 8) with one lazy-match
  step, minimum match 4, maximum match 512. Matches may reach back across
  meta-block boundaries (the decoder's history is the whole output) but never
  past the end of the current block, so `MLEN` always matches the bytes the
  commands produce exactly.
- **Prefix codes**, built from the block's own symbol frequencies: *simple*
  codes (3.4) for alphabets of 1..4 used symbols — the only legal encoding when
  there is exactly one, since a one-symbol *complex* code can never reach the
  Kraft equality the decoder demands — and *complex* codes (3.5) above that,
  including the `REPEAT_PREVIOUS` (16) / `REPEAT_ZERO` (17) run-length codes.
- **Length-limited Huffman**: code lengths are bounded (15 for the data
  alphabets, 5 for the code-length alphabet) by raising a floor under the symbol
  counts and rebuilding until the tree fits. Once the floor passes every count
  all weights are equal and the tree is balanced, so this always terminates.
- **Window bits**: 16, or 21 when the input is longer than 65 520 bytes.

Deliberately *not* implemented, each costing some ratio:

- No block splitting — `NBLTYPES` is always 1 for all three categories.
- No literal context modelling — the context map is all zeros, so the literal
  code is context-free.
- No static-dictionary references.
- No `NPOSTFIX`/`NDIRECT` tuning (both 0).
- **No distance short codes.** Codes 0..15 index the decoder's ring buffer of
  recent distances; every distance emitted is an explicit code (>= 16), and no
  implicit-distance command symbol is ever used. That costs a few bits per
  repeated distance and buys the encoder freedom from having to mirror the
  decoder's ring-buffer state exactly.

### Measured ratios

Ours vs. the reference implementation at several qualities (bytes):

| input | raw | **ours** | ref q0 | ref q1 | ref q5 | ref q11 |
|---|---|---|---|---|---|---|
| `alice29.txt` | 152 089 | **54 605** | 65 795 | 60 292 | 52 809 | 46 487 |
| `monkey` | 843 | **417** | 535 | 464 | 426 | 405 |
| `cp852-utf8` | 706 | **536** | 618 | 566 | 482 | 362 |
| `zeros` | 262 144 | **651** | 196 | 47 | 13 | 14 |
| `random_org_10k.bin` | 10 000 | **10 004** | 10 004 | 10 004 | 10 004 | 10 004 |

`zeros` is where the missing distance short codes and the 512-byte match cap
show most: long runs are cheap for the reference and merely very cheap here.
Incompressible input costs the same as it does the reference — both store it.

### Worst-case bound

The store-mode fallback is a real, tested path, not a safety net that never
fires: a compressed block is kept only when `w.bitPos() < store_bits`, and any
block the encoder cannot encode at all (a give-up error rather than a bad
stream) is stored too. So `compress` is never more than a few bytes of framing
larger than its input, and `compress` itself never fails except on allocation.

## DoS / safety posture

- **Output cap**: `decompress(gpa, input, .{ .max_output = N })` bounds the
  decompressed size (default 256 MiB). Brotli's window + 122 KB dictionary make
  decompression bombs cheap, so every append is checked against the cap and
  returns `error.OutputTooLarge` on breach.
- **No panics on malformed input**: every failure is a typed `BrotliError`
  (truncation, reserved bits, bad padding, malformed Huffman, bad context map,
  bad distance/dictionary reference, …). Fuzzed with hostile random inputs and
  with a batch of truncations of a real stream; both Debug and ReleaseFast.
- Allocator is always explicit; per-meta-block scratch (Huffman tables, context
  maps) lives in an arena that is freed when decoding finishes.

## Validation

- **Decoder, byte-exact** vs google/brotli reference vectors
  (`tests/testdata/*.compressed` ↔ plaintext): empty stream, `x`, `xyzzy`,
  `10x10y`, `64x`, `quickfox` (static dictionary), `quickfox_repeated`,
  `ukkonooa`, `zeros`, `zerosukkanooa`, `monkey`, `backward65536` (large
  window), `random_org_10k.bin` (incompressible), `compressed_file`,
  `cp852-utf8`, `cp1251-utf16le`, and `alice29.txt` (152 KB, complex Huffman +
  multiple distance block types). Additional non-embedded vectors
  (`mapsdatazrh` 285 KB, `compressed_repeated` 144 KB) were checked externally.
  This covers uncompressed meta-blocks, simple + complex Huffman, static-
  dictionary references, the distance ring buffer, and block switching.
- **Malformed batch**: truncations + hostile random inputs never panic and
  always return a typed error; the output cap is enforced.
- **Encoder, anchored outside this repository.** A writer and a reader can
  share a misreading of RFC 7932 and still round trip perfectly, so a
  self round-trip proves nothing on its own. `src/reference_interop.zig` pushes
  every stream this encoder emits through the **reference** implementation
  (google/brotli, via the Python `brotli` C extension) and asserts the original
  bytes come back — over a property sweep of input shapes: empty, single byte,
  one-byte runs sized around the insert/copy length-code boundaries (1..6, 9,
  10, 63..65, 1000, 22 593..22 595), 1..5-symbol alphabets both flat and skewed
  (every simple-code shape plus the first complex one), all 256 byte values,
  incompressible random, text at and either side of the 65 520-byte window-bits
  switch, and multi-meta-block streams that mix compressed and stored blocks in
  both orders. The same file also runs the *other* direction: our decoder
  against reference output at qualities 0/1/5/9/11. All of it **skips loudly**
  (never silently, never as a failure) when python3 or the `brotli` package is
  missing.
- **One-off randomized sweep** (not part of the suite, reproducible from the
  seed): 600 generated inputs across nine shapes and four size classes (up to
  200 KB, 20.3 MB of plaintext in total) compressed and then decompressed by
  the reference implementation — zero rejections, zero mismatches, aggregate
  ratio 3.06x.
- **Writer unit tests** against the decoder's own primitives (`BitReader`,
  `huffman.zig`, `tables.zig`): the fixed code-length prefix code is asserted to
  be the exact inverse of `tables.code_length_prefix_*`; the `16`/`17` repeat
  chains are replayed through the decoder's repeat recurrence for every length
  3..2000; run-length-coded code lengths replay back to the original lengths
  (hand-picked and 300 random complete codes); a complete complex code survives
  a bit-level write/read round trip; every prefix-code shape (1..N used symbols,
  all three alphabets) round-trips header *and* symbols; length-limited Huffman
  is checked for Kraft equality and the depth limit; and the command/distance
  code tables are checked against `tables.cmd_lut` and for gap-free coverage of
  every insert length, copy length and distance.
- **Mutation-tested.** Deliberately breaking the writer — reversing the
  code-length prefix bit order, dropping one code from a repeat chain, emitting
  a distance or a copy length one off, loosening the fallback comparison,
  writing MLEN before MNIBBLES, reordering the tree groups, writing the distance
  before the literals, swapping the insert/copy extra bits, using a wrong HSKIP,
  ignoring the decoder's early stop in the code-length header, raising a code
  length limit past what the format can express, and reversing simple-code
  symbol order — each turns the suite red. One mutation was chosen specifically
  to stay *consistent* between writer and reader (perturbing `reverseBits` in
  the shared `huffman.zig`): it leaves every self round-trip green and is caught
  only by the reference decoder — which is exactly why that anchor exists.
- All tests pass in **Debug** and **ReleaseFast** (`zig build test-brotli`
  [`-Doptimize=ReleaseFast`]).
