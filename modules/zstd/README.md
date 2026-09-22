# zstd

**Zstandard (RFC 8878) compressor** for levels 1–10 and the negative ("fast")
levels, emitting **exactly the bytes libzstd 1.5.7 emits** for the same input
and level. Decoding is not here: `std.compress.zstd.Decompress` already does
it. This module is the half std lacks.

It is a port of libzstd's `fast`, `dfast`, `greedy`, `lazy`, `lazy2` and
`btlazy2` match finders (`greedy`..`lazy2` with both the hash-chain and the
row-based search, `btlazy2` with its lazily sorted binary tree),
one-shot frame and block driver, block pre-splitter, and Huffman/FSE entropy
encoders. Pure Zig,
no C, no libc.

- **Levels:** 1–10 (0 means the default, 3), and negative levels down to
  -131072 (lower values are clamped, as libzstd does). **11 and up are
  refused** with `error.LevelUnsupported`: for some input sizes they select
  the optimal parsers (`btopt`, `btultra`, ...), which are not ported yet.
  There is no silent downgrade.
- **Output:** one frame, content size in the header, optional content checksum
  (`checksum = true`). Byte-identical to `ZSTD_compress2()` with the same
  level and checksum setting — pinned by the golden test on a 56-case corpus at
  twelve levels, both checksum settings (1344 frames).
- **Speed:** about 1.2–1.5× libzstd's time on the same input (process wall
  time, ReleaseFast, 4–13 MB inputs; see SPEC.md). Memory: the match tables for
  the chosen level (at most 16 MiB + 4 MiB, at level 10 on inputs over
  256 KB) plus about 0.5 MiB of block buffers, allocated per call and freed
  before it returns.
- **Platform:** any (no OS calls). **Role:** codec. **Concurrency:** reentrant.

Provenance: a translation of libzstd v1.5.7 C source (BSD licence), so this
module carries the required attribution in [`NOTICE`](NOTICE). The byte-exactness
claim rests on libzstd itself, run by the recipe in [`tools/`](tools/README.md).

## API

```zig
const zstd = @import("zstd");

// Allocate the frame (caller owns it).
const frame = try zstd.compressAlloc(gpa, data, .{ .level = 3 });
defer gpa.free(frame);

// Or into your own buffer, which must hold compressBound(data.len) bytes.
var buf = try gpa.alloc(u8, zstd.compressBound(data.len));
const n = try zstd.compress(gpa, buf, data, .{ .level = 1, .checksum = true });
// buf[0..n] is the frame.

// Decode with std:
var in: std.Io.Reader = .fixed(frame);
var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{});
```

`gpa` backs only the per-call match tables and block buffers; everything is
freed before `compress` returns.

Errors: `LevelUnsupported` (level > 10), `NoSpaceLeft` (`dst` below
`compressBound`), `InputTooLarge` (over `max_input_size`, 3500 MiB — libzstd
would start rescaling its indices there, which is not ported), `OutOfMemory`.

## Tests

`zig build test-zstd` (all three release lanes). The load-bearing one is
`src/golden_test.zig`: every corpus input (`src/testdata/corpus.zig`,
generated, so the repository stores none) is compressed at levels -5, -1 and 1–10
with and without checksum, and each frame's length and SHA-256 must equal
what libzstd 1.5.7 produced (`src/testdata/goldens.zig`, written by
`tools/gen-goldens.sh`). The corpus is built for coverage: each size tier of
the level table, RLE blocks, literal and match lengths past 0xFFFF, both
pre-splitters, offsets beyond the window, and cases constructed so that
specific decisions are marginal (see SPEC.md, *Anchoring*).

`src/fuzz_test.zig` round-trips arbitrary input through std's decoder; unit
tests cover the FSE normalisation, Huffman depth limiting, bit writer and
parameter selection.
