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
