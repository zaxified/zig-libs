# bzip2

The `.bz2` format — and the raw stream ZIP method 12 carries — in pure Zig: a **compressor that
emits, byte for byte, what libbzip2 1.0.8 emits** at the same level, and a **streaming decompressor**
with block and stream CRC checks, concatenated streams, bzip2 0.9.0's randomised blocks, typed
errors and a decompression-bomb cap.

- **Model after:** libbzip2 1.0.8 (Julian Seward). **Platform:** any. **Role:** codec.
  **Concurrency:** reentrant (every `Encoder` / `Decoder` is its own state). **Deps:** none
  (std-only, pure Zig — no C, no libc).
- **Memory:** both sides grow with the data, up to one block. Decoding holds the block's symbols
  (4 bytes each: 3.6 MB at `-9`) plus about 25 KB of tables; encoding at level `n` needs about
  `7.5 * n * 100 000` bytes for a full block (about 7 MB at `-9`) and a few kilobytes for a small
  input. Nothing is allocated up front but the small tables.

Provenance: translated from libbzip2 1.0.8 (BSD-style licence), the block sort, the Huffman
construction, the MTF / table-selection stage and the block assembly decision for decision, the
decoder re-built around a pull `std.Io.Reader` — see [NOTICE](NOTICE) for the file-by-file map and
the licence, and [SPEC.md](SPEC.md) for the format, the parity claim and its evidence.

## Decompress

```zig
const bzip2 = @import("bzip2");

// A slice: every stream in it, concatenated ones too. Caller owns the result.
const plain = try bzip2.decompress(gpa, compressed, .{ .max_output = 64 << 20 });
defer gpa.free(plain);

// From a std.Io.Reader (its buffer must be non-empty) to a std.Io.Writer, one block in memory:
const n = try bzip2.decompressStream(gpa, &in, &out, .{});

// Or a Reader to pull from (ZIP method 12, an HTTP body, a pipeline stage):
var r = try bzip2.DecompressReader.init(gpa, &in, &buf, .{});
defer r.deinit();
const line = try r.reader.takeDelimiter('\n');
// On error the reader reports error.ReadFailed and `r.err` holds the bzip2.DecodeError.
```

`DecodeOptions`: `max_output` (bomb cap, default 256 MiB, `null` = unbounded: more output is `error.OutputTooLarge`), `multi_stream`
(default on: bzip2, Python's `BZ2File` and libzip read until the input ends),
`ignore_trailing_garbage` (default off: bytes after the last stream are `error.TrailingData`).
The decoder reads up to 8 bytes ahead of the end of the last stream.

## Compress

```zig
const z = try bzip2.compress(gpa, input, .{ .level = 9 });    // levels 1..9, work_factor 30
defer gpa.free(z);

// Streaming, as a std.Io.Writer:
var sw = try bzip2.StreamWriter.init(gpa, &out, &buf, .{ .level = 6 });
defer sw.deinit();
try sw.writer.writeAll(chunk);
try sw.finish();      // trailer; does not flush `out`
```

`EncodeOptions`: `level` (block size 100 kB × level) and `work_factor` (libbzip2's, 0 = its default
30: how much work the main block sort may spend before the fallback sort takes over — it changes
the bytes only through which sort breaks ties between equal rotations, exactly as in libbzip2).
The bytes do not depend on how the input was cut into writes. `compressInto` writes into a caller's
buffer, `compressBound(n)` bytes always fit.

## Not here

No multithreaded (pbzip2 / lbzip2 style) block compression, no `bzip2recover` (finding intact
blocks in a damaged file), no sync-flush marker. See SPEC.md.

Tests: `zig build test-bzip2` (golden replays of libbzip2's bytes, decoder error paths, fuzz
harnesses at 4000 seeds); `BZIP2_FUZZ=<runs>` runs the deterministic fuzz driver;
`zig build interop-bzip2` compares live against libbzip2 and Python's `bz2`
(`tools/README.md`); `zig build bench-bzip2` against libbzip2.
