# brotli

Pure-Zig **Brotli** (RFC 7932) — a byte-exact decompressor plus a real
compressing encoder. std-only, no external dependencies. This is the modern
`Content-Encoding: br` companion to `std.compress.flate` (gzip): `std` ships no
Brotli, so an HTTPS server that wants `br` needs this.

- **Decoder:** complete RFC 7932 — bit stream, meta-blocks (compressed /
  uncompressed / metadata), simple + complex Huffman, block-type/count
  machinery, the four literal context modes + context maps, the
  postfix/direct/ring-buffer distance model, and the normative **static
  dictionary** (Appendix A, 122 784 bytes) + **transforms** (Appendix B).
  Byte-exact against the google/brotli reference vectors.
- **Encoder:** LZ77 backward references + a per-meta-block Huffman code for
  literals, insert-and-copy commands and distances, with literal context
  modelling (`.default`/`.best`), distance short codes, and an automatic
  **store-mode fallback** so the output is never meaningfully larger than the
  input. ~3x on English text (`alice29.txt` 152 089 -> 51 467 at `.default`),
  between reference `brotli` quality 5 and 9. No block splitting, no
  static-dictionary references, no optimal parse — see `SPEC.md`.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** explicit
  allocator; decode output is caller-owned, per-meta-block scratch is arena-freed.
- **Safety:** bounded output (`max_output` DoS cap, default 256 MiB); malformed
  input never panics — always a typed `BrotliError`.

Provenance: the decoder logic is clean-room from RFC 7932. `dictionary.bin`, the
context lookup table, and the transform / prefix-suffix tables are **normative
RFC 7932 constants** (Appendices A/B/C), reproduced verbatim (byte-identical to
google/brotli, MIT). Test data: `src/testdata/` reproduces google/brotli's own
`tests/testdata/` corpus verbatim — 17 input/`.compressed` pairs, copied rather
than generated — so this module carries required attribution in
[`NOTICE`](NOTICE), which is where the obligation lives.

## API

```zig
const brotli = @import("brotli");

// Decompress a complete stream (caller owns the returned slice).
const out = try brotli.decompress(gpa, input, .{});          // default cap 256 MiB
const out = try brotli.decompress(gpa, input, .{ .max_output = 8 << 20 });

// Into your own buffer (a known size, or one buffer reused): no output
// allocation; OutputTooLarge when it does not fit. `gpa` holds the tables.
const got = try brotli.decompressInto(gpa, buf, input, .{});  // a prefix of buf

// Streaming: reader in, writer out. Memory is the window (≤ 16 MiB, and
// only as much as the output needs), not the output.
const n = try brotli.decompressStream(gpa, &body_reader, &file_writer, .{});

// Pull: a std.Io.Reader over the decompressed bytes, decoding as you read.
var d = brotli.Decompressor.init(gpa, &body_reader, &buf, .{});
defer d.deinit();
const line = try d.reader.takeDelimiterInclusive('\n');   // ReadFailed? see d.err
// Errors: brotli.StreamError = BrotliError + ReadFailed + WriteFailed.

// Compress. Fails only on allocation — blocks that will not shrink are
// stored verbatim, so the result is always a valid `br` body.
const br = try brotli.compress(gpa, data);                    // effort .default
defer gpa.free(br);
// .fast (≈ reference q4), .default (≈ q6), .best (≈ q9, for content
// compressed once and served many times); window_bits 10..24 (default: 16
// for inputs up to 64 KiB, else 21).
const br_best = try brotli.compressWith(gpa, data, .{ .effort = .best });

// A raw prefix dictionary (RFC 9841), and Content-Encoding: dcb (RFC 9842):
// the decoder needs the same bytes.
const delta = try brotli.compressWith(gpa, app_v2_js, .{ .dictionary = app_v1_js });
const v2 = try brotli.decompress(gpa, delta, .{ .dictionary = app_v1_js });
const body = try brotli.dcb.compress(gpa, app_v2_js, app_v1_js, .{});  // header + stream
const back = try brotli.dcb.decompress(gpa, body, app_v1_js, .{});     // DictionaryMismatch?

// Into your own buffer: maxCompressedSize is always enough (exact for
// incompressible input); a smaller one fails only if the stream does not fit.
const into = try brotli.compressInto(gpa, buf, data, .{});     // a prefix of buf

// Streaming: a std.Io.Writer. flush() makes everything so far decodable at
// the other end; finish() ends the stream; reset() starts the next one on
// the same table and history (a server compressing response after response).
var sw = try brotli.StreamWriter.init(gpa, &socket_writer, &buf, .{ .effort = .fast });
defer sw.deinit();
try sw.writer.writeAll(chunk);
try sw.writer.flush();
try sw.finish();

// Errors: brotli.BrotliError (TruncatedInput, InvalidHuffman, InvalidDistance,
// InvalidDictionary, OutputTooLarge, InvalidPadding, ...).
```

## Tests

`zig build test-brotli` (and `-Doptimize=ReleaseFast`). Decodes 17 embedded
reference vectors byte-exact (empty, static-dictionary, complex-Huffman
`alice29.txt`, incompressible, large-window, …), a malformed/truncation batch
that must never panic, and output-cap enforcement.

On the encoder side the tests are anchored **outside this repository**: every
stream it produces has been decompressed by the reference implementation
(google/brotli via Python `brotli`), across a property sweep of 45 input shapes
— empty, single byte, one-byte runs sized around the length-code boundaries,
1..5-symbol alphabets flat and skewed, every byte value, incompressible random,
text, and multi-meta-block streams mixing compressed and stored blocks.

That comparison is a separate program, not part of the suite:

```bash
zig build interop-brotli                 # live, needs `pip install brotli`
zig build interop-brotli -- --capture    # re-freeze the fixtures from it
```

The suite itself is **hermetic** — no python3, no subprocess, no skip path. It
replays what the capture froze: `src/testdata/ref/*.br` are 24 streams the
reference compressed (five qualities on `alice29.txt`, three window sizes, and
both extremes of quality over the rest of the corpus) which our decoder must
turn back into the plaintext, and `src/testdata/interop_blessed.zig` pins the
digest of the exact stream google/brotli accepted for each of the 45 shapes. An
encoder change therefore fails the suite until it is re-blessed against a real
google/brotli — which is the point of an anchor.
The writer's own pieces — the complex-prefix-code header, the `16`/`17` repeat
chains, length-limited Huffman, and the command/distance code tables — are unit
tested against the decoder's own `BitReader`, `huffman.zig` and `tables.zig`.
