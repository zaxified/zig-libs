# csvstream

Streaming RFC 4180 CSV reader that **preserves byte offsets**. Every record
comes out with the absolute file offset of its first byte, so a consumer can
seek straight back to the exact source span (drill-down, `--trace`-style source
locators, error reporting). Streams arbitrarily large files in **bounded
memory** — peak is the chunk size, not the file size.

- **Model after:** RFC 4180 + byte-offset-preserving streaming.
- **Platform:** any. **Role:** codec. **Concurrency:** reentrant (no shared
  state). **Deps:** none (std-only, pure Zig — no C/libc).

Provenance: original work of the zig-libs authors (MIT). Two layers — an
in-memory `LineIterator`/`splitFields` core (pinned by 22 oracle tests) and a
record-aligned `ChunkReader` — composed by `StreamReader`. No third-party code.

## Two layers, one record model

Both layers emit the same `LineSlice { bytes, byte_offset, unbalanced_quote }`.

### In-memory (standalone) — you already hold the bytes

```zig
const csv = @import("csvstream");

var it = csv.LineIterator.init(buf, '"', base_offset); // quote 0 disables quoting
while (it.next()) |rec| {
    // rec.bytes is the logical line (CR stripped); rec.byte_offset is
    // base_offset + the record's start within buf.
    var fbuf: [32][]const u8 = undefined;
    const fields = try csv.splitFields(rec.bytes, &fbuf, ',', '"', alloc);
    _ = fields;
}
```

### Streaming — file → records with absolute offsets, bounded memory

```zig
var f = try dir.openFile(io, "big.csv", .{});
defer f.close(io);

var sr = try csv.StreamReader.init(io, alloc, f, .{ .quote = '"' });
defer sr.deinit();

while (try sr.next()) |rec| {
    // rec.byte_offset is the ABSOLUTE file offset of rec.bytes[0].
    // Borrow contract: rec.bytes is valid only until the next `next()` that
    // advances into a new chunk — copy out anything you must retain.
}
```

`StreamReader` composes a record-aligned `ChunkReader` (file → chunks, each
ending on the last `\n` in its window) with a per-chunk `LineIterator`. Because
every chunk ends on a `\n`, no record spans a chunk boundary, so offsets compose
cleanly. `ChunkReader` is exposed too, for callers who want the raw record-
aligned chunks (e.g. to hand each block to a parallel worker).

## Quoting semantics (RFC 4180 + "lazy quotes")

RFC 4180 quoting: a field wrapped in `quote` may contain the delimiter; a
doubled `""` inside a quoted field is one literal quote. **Deviation:** a `\n`
*always* ends a record — quoted fields may NOT span physical lines (à la Go
`encoding/csv` LazyQuotes). A stray/unbalanced quote is therefore a one-line
problem (flagged by `LineSlice.unbalanced_quote`) instead of swallowing the rest
of the file — which is also what makes every `\n` a safe chunk boundary for
bounded-memory streaming. Quoting still protects the *delimiter* within a line.

## Tests

`zig build test-csvstream` (headless; green in Debug and
`-Doptimize=ReleaseFast`). 29 tests: `line.zig` carries the 22 verbatim oracle
tests, `stream.zig` the 6 file/streaming + integration tests (offsets index the
exact source bytes across a multi-chunk file; a positional re-read proves
seek-back), and `root.zig` carries a dark-tests aggregator
(`test { _ = line; _ = stream; }`) so both submodules' tests run — a bare
re-export would not pull them in.

## Deferred (not implemented in v1)

A spec-complete CSV toolkit would still add, as discrete backlog items:

- **Configurable delimiter/quote per stream.** `splitFields` takes a delimiter,
  and `LineIterator`/`StreamReader` take a quote char, but the delimiter is not
  yet a `StreamReader` option (records are split lazily by the caller); expose a
  reader-level `delimiter`. Also: distinct quote vs escape char (RFC 4180 uses
  the same char; some dialects use `\`).
- **Header-row handling.** No built-in header capture / name→index map /
  name-based field access. Callers wire their own (a `parseCsvHeader` was left
  out deliberately — it is app policy, not codec).
- **Typed field coercion.** Fields are `[]const u8`; no int/float/bool/date
  parsing or per-column schema.
- **CSV writing.** Read-only. No RFC 4180 quoting-on-output (that concern lives
  in the sibling `csvsafe` module for injection-guarding, but not general
  record writing).
- **BOM handling.** A leading UTF-8/UTF-16 BOM is not detected or stripped.
- **Strict RFC 4180 mode.** Optional opt-in to (a) multi-line quoted fields
  (spanning `\n`) and (b) a trailing-delimiter emitting a final empty field —
  both currently deviate by design (see the `splitFields` trailing-delimiter
  test and the lazy-quotes note above).
- **Field-count validation.** No per-record arity check against the header/first
  row.
