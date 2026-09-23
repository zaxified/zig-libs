# zstd

**Zstandard (RFC 8878) compressor** for every level — 1–22 and the negative
("fast") levels — emitting **exactly the bytes libzstd 1.5.7 emits** for the same input
and level. Decoding is not here: `std.compress.zstd.Decompress` already does
it. This module is the half std lacks.

Not yet a full libzstd replacement — that is the goal: one-shot
compression is complete, streaming (`Stream`, `ZSTD_compressStream2`'s bytes
for the same calls) covers every level too, and `FrameWriter` is a
`std.Io.Writer` that emits one frame per flush; the stable-buffer and
context-reuse parts of the streaming API, a decoder with dictionaries,
dictionaries themselves, multithreading and the advanced parameters are
queued in [SPEC.md](SPEC.md) (*Backlog / deferred*, with costs). Note that
std's decoder defaults to an 8 MB window: frames of levels 20–22 on large
inputs need its `window_len` raised.

It is a port of every libzstd strategy: `fast`, `dfast`, `greedy`, `lazy`,
`lazy2` (with both the hash-chain and the row-based search), `btlazy2` (its
lazily sorted binary tree), and the optimal parsers `btopt`, `btultra` and
`btultra2`; plus the one-shot frame and block driver, the block pre-splitter
and post-splitter, long-distance matching (which libzstd switches on by
itself at level 22 for inputs over 64 MB), and the Huffman/FSE entropy
encoders. Pure Zig, no C, no
libc.

- **Levels:** 1–22 (0 means the default, 3), and negative levels down to
  -131072 (lower values are clamped, as libzstd does). Above 22 is
  `error.LevelUnsupported` where libzstd would quietly clamp to 22.
- **Output:** one frame, content size in the header, optional content checksum
  (`checksum = true`). Byte-identical to `ZSTD_compress2()` with the same
  level and checksum setting — pinned by the golden test on a 56-case corpus
  (2029 frames: every case at levels -5…10 with and without checksum, cases up
  to 600 KB at levels 11–22, 14 cases found by mutation testing at the one
  level each pins, 15 compressed with long-distance matching switched
  on by hand, and 13 with index overflow correction run often), and against
  libzstd at level 22 on 64–140 MB inputs and on a 4.4 GB input past the
  3500 MiB index limit.
- **Speed:** about 1.2–1.5× libzstd's time on the same input up to level 10
  (process wall time, ReleaseFast, 4–13 MB inputs), 0.9–1.4× at levels 13–19
  (single runs on a loaded machine; see SPEC.md). Level 19 compresses about
  2 MB/s; level 22 about 2.4 MB/s on a 70 MB input (libzstd: 2.5). Memory:
  the match tables for the chosen level, allocated per call and freed before
  it returns — 64 + 16 MiB at level 19 on inputs over 256 KB, up to 256 +
  64 MiB at level 21 on inputs over 64 MB, and 512 + 128 MiB plus a 64 MiB
  long-distance table at level 22 on inputs over 64 MB (about 820 MB peak on
  a 70 MB input, as libzstd) — plus about 0.8 MiB of block buffers and parser
  state.
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

Streaming into any `std.Io.Writer` (an HTTP body, a file), one independent
frame per buffer fill and per flush:

```zig
var buf: [64 * 1024]u8 = undefined; // frame size when nobody flushes
var fw: zstd.FrameWriter = try .init(gpa, out, &buf, .{ .level = 3 });
defer fw.deinit();
try fw.writer.writeAll(chunk);
try fw.writer.flush(); // what is buffered becomes a frame on `out`
try fw.finish(); // the last frame; `out` itself is not flushed
```

Frames share no history, so frequent small flushes cost ratio. On
`error.WriteFailed`, `fw.err` names our own cause (`OutOfMemory`); null
means `out` failed.

Streaming as libzstd streams — one frame, history kept across flushes, the
same bytes `ZSTD_compressStream2` produces for the same sequence of calls
(every level):

```zig
var s = try zstd.Stream.init(gpa, .{ .level = 3 }); // .pledged_size = n puts the size in the header
defer s.deinit();
var out_buf: [64 * 1024]u8 = undefined;
var in: zstd.InBuffer = .{ .src = chunk };
while (in.pos < in.src.len) { // .continue: buffer input, emit whole blocks
    var o: zstd.OutBuffer = .{ .dst = &out_buf };
    _ = try s.compressStream2(&o, &in, .@"continue");
    try sink.writeAll(out_buf[0..o.pos]);
}
// .flush / .end: repeat until the return value (bytes still held back) is 0
var end: zstd.InBuffer = .{ .src = "" };
while (true) {
    var o: zstd.OutBuffer = .{ .dst = &out_buf };
    const left = try s.compressStream2(&o, &end, .end);
    try sink.writeAll(out_buf[0..o.pos]);
    if (left == 0) break;
}
```

Its memory is the level's tables plus an input buffer of one window and one
block (2.1 MB at level 3 with an unknown size; at level 22 without a pledged
size the window is 128 MB and long-distance matching is on, about 1 GB in
all, as libzstd). Errors: `LevelUnsupported`,
`SrcSizeWrong` (a pledged size not met), `FrameEnded` (a call after the end;
a new frame needs a new `Stream`), `InvalidBuffer`, `OutOfMemory`.

Errors: `LevelUnsupported` (level > 22), `NoSpaceLeft` (`dst` below
`compressBound`), `OutOfMemory`. There is no input size limit: past 3500 MiB
the indices are rescaled as libzstd does (the whole input still has to be in
memory, and so does its `compressBound`).

## Tests

`zig build test-zstd` (all three release lanes). The load-bearing one is
`src/golden_test.zig`: every corpus input (`src/testdata/corpus.zig`,
generated, so the repository stores none) is compressed at levels -5, -1 and
1–10 with and without checksum, and — up to 600 KB, without checksum — at
11–22; each frame's length and SHA-256 must equal what libzstd 1.5.7 produced
(`src/testdata/goldens.zig`, written by `tools/gen-goldens.sh`). The corpus
is built for coverage: each size tier of the level table, RLE blocks, literal
and match lengths past 0xFFFF, both pre-splitters, the post-splitter, offsets
beyond the window, long-distance matching (switched on by hand through a
test seam, as it only switches itself on above 64 MB), and cases constructed
so that specific decisions are marginal (see SPEC.md, *Anchoring*). The module is `heavy` in `build.zig`:
its tests run at ReleaseSafe when Debug is asked for (Debug takes ~2 min 15 s,
ReleaseSafe ~1 min with the build); `-Dstrict-debug` forces Debug.

`src/stream_test.zig` does the same for streaming: 54 cases, each a schedule of calls
(pledged and unknown sizes, flushes, 50-byte outputs, windows down to 1 KB
so libzstd's input buffer wraps, index overflow correction run often, long-distance
matching switched on by hand; 24 of them found by mutation testing) over
corpus inputs at levels -5 … 22, with and without checksum — 470 streams,
each equal in length and SHA-256 to what `ZSTD_compressStream2` produced
(`src/testdata/stream_goldens.zig`, `tools/zstream.c` driving libzstd).

`src/fuzz_test.zig` round-trips arbitrary input through std's decoder; unit
tests cover the FSE normalisation, Huffman depth limiting, bit writer and
parameter selection.
