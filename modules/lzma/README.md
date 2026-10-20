# lzma

LZMA1, LZMA2 and the `.xz` and `.lzma` containers in pure Zig: a **compressor that emits, byte for
byte, what liblzma 5.8.1 (XZ Utils) emits** at the same preset, in all four framings, and a
**streaming decompressor** with a dictionary cap, an output cap and typed errors. It is what ZIP
method 14 (LZMA) and method 95 (XZ) carry.

- **Model after:** XZ Utils liblzma 5.8.1 (0BSD). **Platform:** any. **Role:** codec.
  **Concurrency:** reentrant (every `Encoder` / `Decoder` is its own state). **Deps:** none
  (std-only, pure Zig — no C, no libc).
- **Memory:** decoding holds the dictionary (what the header asks for, rounded up to 16 bytes; at
  most `max_dict`, 64 MiB by default, and never more than the output can fill) plus about 30 KB of
  model. Encoding is liblzma's: about `1.5 x dict` of window plus the match finder's tables
  (preset 1: 9 MiB, 3: 32 MiB, 6: 94 MiB, 9: 674 MiB — the numbers of `xz -v`).

Provenance: the encoder (window, match finders, range encoder, fast and optimal parsers, LZMA2
chunker, presets) is a translation of liblzma 5.8.1 (0BSD), decision for decision; the decoder is
written from the format and checked against liblzma — see [NOTICE](NOTICE) for the file map and the
licence, and [SPEC.md](SPEC.md) for the formats, the parity claim and its evidence.

## Decompress

```zig
const lzma = @import("lzma");

// A slice: every stream in it, concatenated ones too. Caller owns the result.
const plain = try lzma.decompress(gpa, compressed, .xz, .{ .max_output = 64 << 20, .max_dict = 16 << 20 });
defer gpa.free(plain);

// From a std.Io.Reader (its buffer must be non-empty) to a std.Io.Writer:
_ = try lzma.decompressStream(gpa, &reader, &writer, .lzma_alone, .{});

// As a pull std.Io.Reader:
var r = try lzma.DecompressReader.init(gpa, &reader, &buf, .xz, .{});
defer r.deinit();
while (try r.reader.takeDelimiter('\n')) |line| { ... }
```

`Format` says what the bytes are: `.xz`; `.lzma_alone` (the 13-byte-header `.lzma` file);
`.{ .lzma1 = .{ .props, .uncompressed_size, .allow_eopm } }` (raw LZMA1, the properties out of band —
ZIP method 14: `Lzma1Props.fromBytes` reads the 5 bytes after ZIP's 4-byte header, the size is
the entry's, `allow_eopm` is general-purpose bit 1); `.{ .lzma2 = .{ .dict_size } }` (raw LZMA2
chunks to the `0x00` end byte).

`xz` support: concatenated streams and stream padding, block header sizes (present or not), block
padding, the index checked against the blocks, CRC-32, CRC-64 and SHA-256 checks verified.
Refused by name, not misread: BCJ and delta filters (`error.UnsupportedFilter`) and check types
other than those four (`error.UnsupportedCheck`).

A failure is a typed `DecodeError` (`BadMagic`, `BadHeader`, `BadFooter`, `BadIndex`,
`UnsupportedFilter`, `UnsupportedCheck`, `DictTooLarge`, `CorruptData`, `CheckMismatch`,
`TruncatedInput`, `TrailingData`, `OutputTooLarge`, `ReadFailed`, `OutOfMemory`); the decoder
never panics on any input and stays failed after its first error. `max_dict` is the guard against
a hostile header (the dictionary is allocated before decoding); `max_output` stops a bomb one byte
over.

## Compress

```zig
// xz's preset 6, one .xz block with a CRC-64:
const z = try lzma.compress(gpa, input, .xz, .{});

// A streaming writer, preset 9 extreme, SHA-256 check:
var sw = try lzma.StreamWriter.init(gpa, &out_writer, &buf, .xz, .{
    .lzma = lzma.preset(9, true),
    .check = .sha256,
});
defer sw.deinit();
try sw.writer.print("{d}\n", .{42});
try sw.finish();

// ZIP method 14: raw LZMA1 with an end marker, then write the 9 header bytes yourself.
var o = lzma.preset(6, false);
const raw = try lzma.compress(gpa, input, .lzma1, .{ .lzma = o });
```

`preset(level, extreme)` returns liblzma's options for `-0` ... `-9` / `-9e`; every field
(`lc`, `lp`, `pb`, `dict_size`, `mode`, `mf`, `nice_len`, `depth`) can be changed after. The
output depends on the input and the options only, not on how the input was cut into writes.
`compressInto` writes into a buffer (`compressBound(n)` bytes always fit). `EncodeFormat` is `.xz`
(one LZMA2 block, sizes unknown in the block header — what `xz` and Python's `lzma` write),
`.lzma_alone`, `.lzma1` (end marker, no header) or `.lzma2`.

Not here: multi-threaded or multi-block `.xz` output, BCJ / delta filters, preset dictionaries,
sync-flush, LZMA1 without the end marker. See SPEC.md.

Run `zig build example-lzma` / `zig build run-example-lzma` for a complete round trip.
