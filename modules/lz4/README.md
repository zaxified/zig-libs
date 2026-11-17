# lz4

The LZ4 **block format** and the LZ4 **frame format** (`.lz4`) in pure Zig: a compressor with
LZ4's default fast matcher and its acceleration knob, and a decompressor for frames — block and
content checksums, content size, linked or independent blocks, every block size, skippable frames,
the legacy `lz4 -l` frame, concatenated — and for raw blocks, with typed errors and a
decompression-bomb cap.

- **Model after:** liblz4 1.10.0 and its `lz4` CLI (Yann Collet). **Platform:** any. **Role:**
  codec. **Concurrency:** reentrant (no shared state). **Deps:** none (std-only; xxHash32 is
  `std.hash.XxHash32`, checked against the CLI's checksums).
- **Memory:** the compressor uses a 16 KiB hash table on the stack and writes into the caller's
  buffer (`compress` allocates exactly the frame bound once). The frame decoder grows its output
  block by block; a block reserves at most `min(block maximum, 255 × its stored size, what is left
  of max_output)`, never a size the header merely declares.

Provenance: clean-room from the LZ4 block and frame format documents (LZ4 v1.10.0); liblz4's
decoder and lz4_flex consulted for which inputs to accept, no code copied — see [NOTICE](NOTICE)
(provenance note) and [SPEC.md](SPEC.md) for the behaviour choices and their sources.

## Frames

```zig
const lz4 = @import("lz4");

// Every frame of a .lz4 file (skippable and legacy frames too). Caller owns the result.
const plain = try lz4.decompress(gpa, file_bytes, .{ .max_output = 64 << 20 });
defer gpa.free(plain);

// Into a caller's buffer when the size is known (Arrow IPC's LZ4_FRAME buffers): dst.len is the
// cap, output past it is error.OutputTooLarge; returns the decoded length. Allocates nothing.
const got = try lz4.decompressInto(frame_bytes, dst, .{});

// One frame; liblz4's defaults (64 KiB linked blocks, no checksums) unless told otherwise.
const z = try lz4.compress(gpa, plain, .{ .content_checksum = true, .block_size = .max4MB });
defer gpa.free(z);

// Into a caller's buffer: compressBound(n, opts) bytes always fit.
const n = try lz4.compressInto(plain, buf, .{});
```

`DecodeOptions`: `max_output` (bomb cap, default 256 MiB, `null` = unbounded; a header declaring
more is refused up front), `multi_frame` (default on, as the CLI and lz4_flex; off = the first
frame only, anything after it `error.TrailingData`), `ignore_trailing_garbage` (default off: junk
after the last frame is `error.TrailingData`, as the CLI; with `multi_frame` off it ignores what
follows the first frame, as python-lz4), `verify_checksums` (default on; the CLI's `--no-crc`).

`EncodeOptions`: `block_size` (`.max64KB` … `.max4MB`), `independent_blocks`, `block_checksum`,
`content_checksum`, `content_size`, `acceleration` (1 = LZ4's default level; higher is faster; `LZ4_compress_fast`'s knob — liblz4's
frame API maps a negative `compressionLevel` L to acceleration `1 - L`).

## Blocks

```zig
// Arrow / Parquet LZ4_RAW style: the uncompressed size is known.
const out = try gpa.alloc(u8, uncompressed_len);
const got = try lz4.decompressBlock(compressed, out); // error.OutputTooSmall if it does not fit
var zbuf: [lz4.compressBlockBound(4096)]u8 = undefined;
const zn = try lz4.compressBlock(data, &zbuf, .{});
```

`decompressBlock` may write scratch bytes into `dst` past the decoded length (liblz4 does too).

## Not here

No LZ4 HC levels (the decoder reads their output), no dictionaries, no streaming
`std.Io.Reader`/`Writer` (whole buffers only), no `lz4` command-line program. See SPEC.md.

Tests: `zig build test-lz4` (hand-built frames, CLI goldens, a byte-at-a-time block model the
fuzzer judges against, 3000 fuzz seeds per run); `LZ4_FUZZ=<runs>` runs the deterministic fuzz
driver on the test binary; `zig build interop-lz4` compares live against the lz4 CLI and liblz4
(`tools/README.md`); `zig build bench-lz4` against `lz4 -b`.
