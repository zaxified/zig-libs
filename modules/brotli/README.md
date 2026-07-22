# brotli

Pure-Zig **Brotli** (RFC 7932) — a byte-exact decompressor plus a minimal,
valid encoder. std-only, no external dependencies. This is the modern
`Content-Encoding: br` companion to `std.compress.flate` (gzip): `std` ships no
Brotli, so an HTTPS server that wants `br` needs this.

- **Decoder:** complete RFC 7932 — bit stream, meta-blocks (compressed /
  uncompressed / metadata), simple + complex Huffman, block-type/count
  machinery, the four literal context modes + context maps, the
  postfix/direct/ring-buffer distance model, and the normative **static
  dictionary** (Appendix A, 122 784 bytes) + **transforms** (Appendix B).
  Byte-exact against the google/brotli reference vectors.
- **Encoder:** emits a valid `br` stream in **store mode** (uncompressed
  meta-blocks). Round-trips and is accepted by real decoders, but does **not**
  compress (ratio ≈ 1.0). A real compressing encoder is future work — see
  `SPEC.md`.
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

// Compress (store mode — valid `br`, but no compression).
const br = try brotli.compress(gpa, data);
defer gpa.free(br);

// Errors: brotli.BrotliError (TruncatedInput, InvalidHuffman, InvalidDistance,
// InvalidDictionary, OutputTooLarge, InvalidPadding, ...).
```

## Tests

`zig build test-brotli` (and `-Doptimize=ReleaseFast`). Decodes 17 embedded
reference vectors byte-exact (empty, static-dictionary, complex-Huffman
`alice29.txt`, incompressible, large-window, …), a malformed/truncation batch
that must never panic, output-cap enforcement, and encoder round-trips incl. a
> 16 MiB multi-block stream whose output is also accepted by reference brotli.
