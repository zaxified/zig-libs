# brotli — SPEC

Pure-Zig Brotli (RFC 7932) codec. std-only, no external dependencies.

## Scope & honesty

- **Decoder — the deliverable.** Complete, byte-exact RFC 7932 decompression,
  validated against the google/brotli reference vectors (see Validation).
- **Encoder — a valid but non-compressing v1.** It emits a conformant
  `Content-Encoding: br` stream in *store mode* (uncompressed meta-blocks). It
  round-trips and is accepted by real decoders, but its ratio is ~1.0. A real
  LZ77 + entropy encoder is deliberately out of scope for v1 (see Encoder).

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

## Encoder — quality / ratio (honest)

The encoder writes the WBITS header, then one or more **uncompressed**
meta-blocks (each ≤ 16 MiB, the `MLEN` limit), then an empty final meta-block.
This is fully RFC-7932-valid `br`: no LZ77, no Huffman, **ratio ≈ 1.0** plus a
few bytes of framing per 16 MiB. It exists so a server can emit a valid `br`
body today; it is *not* a competitive compressor.

**Follow-up (not done):** a real encoder — literal/insert-copy commands with
per-block Huffman codes and LZ77 backward references (optionally the static
dictionary) — to get actual compression. The decoder already supports every
feature such an encoder would need.

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
- **Encoder**: round-trips (`decompress(compress(x)) == x`) over empty,
  incompressible-random, highly-repetitive, and text inputs, incl. a > 16 MiB
  multi-block input. Its output is also accepted by the **reference** brotli
  (google/brotli C library via python `brotli`), proving interop.
- All tests pass in **Debug** and **ReleaseFast** (`zig build test-brotli`
  [`-Doptimize=ReleaseFast`]).
