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
  literals, insert-and-copy commands and distances, with an automatic
  **store-mode fallback** so the output is never meaningfully larger than the
  input. ~2.8x on English text (`alice29.txt` 152 089 -> 54 605), between
  reference `brotli` quality 1 and 5. No block splitting, no context modelling,
  no static-dictionary references, no distance short codes — see `SPEC.md`.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** explicit
  allocator; decode output is caller-owned, per-meta-block scratch is arena-freed.
- **Safety:** bounded output (`max_output` DoS cap, default 256 MiB); malformed
  input never panics — always a typed `BrotliError`.

Provenance: the decoder logic is clean-room from RFC 7932. `dictionary.bin`, the
context lookup table, and the transform / prefix-suffix tables are **normative
RFC 7932 constants** (Appendices A/B/C), reproduced verbatim (byte-identical to
google/brotli, MIT).

## API

```zig
const brotli = @import("brotli");

// Decompress a complete stream (caller owns the returned slice).
const out = try brotli.decompress(gpa, input, .{});          // default cap 256 MiB
const out = try brotli.decompress(gpa, input, .{ .max_output = 8 << 20 });

// Compress. Fails only on allocation — blocks that will not shrink are
// stored verbatim, so the result is always a valid `br` body.
const br = try brotli.compress(gpa, data);
defer gpa.free(br);

// Errors: brotli.BrotliError (TruncatedInput, InvalidHuffman, InvalidDistance,
// InvalidDictionary, OutputTooLarge, InvalidPadding, ...).
```

## Tests

`zig build test-brotli` (and `-Doptimize=ReleaseFast`). Decodes 17 embedded
reference vectors byte-exact (empty, static-dictionary, complex-Huffman
`alice29.txt`, incompressible, large-window, …), a malformed/truncation batch
that must never panic, and output-cap enforcement.

On the encoder side the tests are anchored **outside this repository**: every
stream it produces is decompressed by the reference implementation (google/
brotli via Python `brotli`), across a property sweep of input shapes — empty,
single byte, one-byte runs sized around the length-code boundaries, 1..5-symbol
alphabets flat and skewed, every byte value, incompressible random, text, and
multi-meta-block streams mixing compressed and stored blocks. Those tests skip
loudly (never silently, never as a failure) when python3 or the `brotli`
package is unavailable; run with `ZIG_LIBS_VERBOSE_SKIP=1` to see the reason.
The writer's own pieces — the complex-prefix-code header, the `16`/`17` repeat
chains, length-limited Huffman, and the command/distance code tables — are unit
tested against the decoder's own `BitReader`, `huffman.zig` and `tables.zig`.
