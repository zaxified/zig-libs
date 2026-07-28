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
in-memory `LineIterator`/`splitFields` core (pinned by dedicated oracle tests) and a
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

`StreamReader.Options.delimiter` (new) is threaded through to
`StreamReader.nextFields(buf, alloc)` — a convenience that does `next()` +
`splitFields` in one call, using the reader's own configured
delimiter/quote, so callers who want split fields don't repeat the delimiter
at every call site. `next()` itself stays delimiter-agnostic (whole-record
bytes only), unchanged.

A leading UTF-8 BOM is detected and stripped automatically on the first
chunk of `StreamReader.next()`; the standalone `stripBom(bytes)` covers
in-memory callers driving `LineIterator` directly.

## Writing (RFC 4180 quoting-on-output)

```zig
var buf: [256]u8 = undefined;
var w = std.Io.Writer.fixed(&buf);
try csv.writeRecord(&w, &.{ "alice", "hello, world", "30" }, .{});
// -> "alice,\"hello, world\",30\r\n" (comma-bearing field auto-quoted)
```

`writeField`/`writeRecord` quote a field only when it actually contains the
configured delimiter, quote char, CR, or LF, doubling any embedded quote char
(RFC 4180 §2 rule 7). `WriteOptions` configures `delimiter`, `quote` (`0`
disables quoting, mirroring the reader's convention), and `line_terminator`
(`.crlf` — the RFC 4180 default — or `.lf`). Stateless and streaming to any
`*std.Io.Writer`, same style as the sibling `csvsafe` module's `writeSafe`.

Note: a writer-emitted field with an embedded `\n`/`\r` is valid RFC 4180, but
this module's own reader cannot re-parse it back into one record (see
"Quoting semantics" above) — that's a permanent, documented asymmetry, not a
bug.

## Header-row handling (opt-in)

```zig
var fbuf: [16][]const u8 = undefined;
const header_fields = try csv.splitFields(header_rec.bytes, &fbuf, ',', '"', alloc);
var header = try csv.Header.init(alloc, header_fields);
defer header.deinit();

const row_fields = try csv.splitFields(row_rec.bytes, &fbuf, ',', '"', alloc);
const name = header.get(row_fields, "name"); // ?[]const u8
try header.validateArity(row_fields); // error.FieldCountMismatch if ragged
```

Not wired into `StreamReader` automatically — capturing (or skipping) the
header row stays app policy; `Header` just holds the name→index bookkeeping.

## Typed field coercion (opt-in)

```zig
const age = try csv.parseInt(u32, row_fields[1]);
const price = try csv.parseFloat(f64, row_fields[2]);
const active = try csv.parseBool(row_fields[3]); // "true"/"false"/"1"/"0"
```

Thin wrappers, no trimming (fields stay verbatim — see "spaces are preserved"
in the tests); trim first if your source pads fields.

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
`-Doptimize=ReleaseFast`). Tests span `line.zig` (verbatim oracle cases
+ `stripBom`), `stream.zig` (file/streaming + integration, incl. BOM-strip and
`nextFields`/delimiter), `writer.zig` (RFC 4180 quoting incl. two positive
controls + a file round-trip through `StreamReader`), `header.zig` (`Header`
capture/lookup/arity), and `coerce.zig` (typed parsing). `root.zig` carries a
dark-tests aggregator (`test { _ = line; _ = stream; _ = writer; _ = header; _ =
coerce; }`) so all submodules' tests run — a bare re-export would not pull them
in.

## Deferred (not implemented)

Two items remain deliberately out of scope:

- **Distinct quote-vs-escape char.** RFC 4180 reuses the same char for both
  quoting and escaping; some dialects (`\`-escaped) use a different one. Would
  touch `splitFields`/`LineIterator` and the writer's escaping together, and no
  concrete consumer needs a non-RFC dialect yet.
- **Strict RFC 4180 opt-in mode:** (a) multi-line quoted fields spanning `\n`
  and (b) a trailing-delimiter emitting a final empty field — both currently
  deviate by design (see the `splitFields` trailing-delimiter test and the
  lazy-quotes note above). (a) in particular would force a real parser
  rewrite: the bounded-memory chunking design leans on "every `\n` is a safe
  record boundary," so it stays deferred rather than bolted on.

Everything else previously listed here (configurable delimiter, header-row
handling, typed field coercion, CSV writing, BOM handling, field-count
validation) is now implemented — see the sections above.
