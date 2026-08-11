# zipstream

Streaming **ZIP** archive reader and writer. The reader walks the central
directory once, then streams each member's *decompressed* bytes on demand. No
whole-archive or whole-entry buffering — memory use is O(one decompression
window) regardless of archive or entry size. The writer (`ArchiveWriter`)
appends one member at a time (`addEntry` then `finish()`), streaming
local-header+data straight to the caller's output as each entry is added.

- A streaming ZIP reader; an .xlsx is a ZIP of XML
  parts, and it streams zipped `.csv` members without exposing ZIP internals
  to the caller.
- **Model after:** the ZIP central-directory layout in APPNOTE.TXT (the
  public PKWARE ZIP spec) — behavior only, no third-party source.
- **Platform:** `any` (pure `std.Io`/`std.zip`/`std.compress.flate`, no OS-
  specific code). **Role:** codec (reader + writer).
  **Concurrency:** reentrant — one `Archive` owns one file cursor; no
  globals, no shared state between instances.
- **Deps:** none (std only — `std.zip` for the wire structs/central-directory
  walk, `std.compress.flate` for Deflate, `std.hash.Crc32` for the writer's
  per-entry checksum).

Provenance: original work of the zig-libs authors (MIT). The wire
format is the public PKWARE ZIP spec (APPNOTE.TXT) — no third-party source
involved; no NOTICE entry needed.

## Why

`std.zip` in the standard library only offers whole-archive `extract()` to a
directory. `zipstream` gives you the two primitives extract() is built from —
walk the central directory, stream one entry's bytes — as reusable pieces:
open once, look members up by name, stream any one of them through a
caller-owned window buffer, keep the rest of the archive untouched on disk.

## API

```zig
const zipstream = @import("zipstream");

var archive: zipstream.Archive = undefined;
try archive.init(io, gpa, file); // file already open; not closed by deinit
defer archive.deinit();

// Look a member up (or walk archive.entries directly).
const entry = archive.find("data/report.csv") orelse
    archive.findSuffix("report.csv") orelse return error.MissingMember;

// Stream its decompressed bytes through a caller-owned window.
var window: [std.compress.flate.max_window_len]u8 = undefined;
var er: zipstream.EntryReader = undefined;
try er.init(&archive, entry, &window);
while (true) {
    const n = try er.reader().readSliceShort(buf);
    if (n == 0) break;
    // consume buf[0..n]
}
// Finish (or abandon) this EntryReader before opening the next one — both
// share the Archive's single file cursor.
```

`Archive` and `EntryReader` hold internal self-pointers (the file reader's
`interface`, the inflate stream's input handle) — initialize both in place
via a `*Self` and never move them after `init`.

### Writing

```zig
var aw: std.Io.Writer.Allocating = .init(gpa); // or a file's buffered writer
defer aw.deinit();

var zw = zipstream.ArchiveWriter.init(gpa, &aw.writer);
defer zw.deinit();

try zw.addEntry("hello.txt", "hello, world\n", .{ .method = .store });
try zw.addEntry("data/report.csv", csv_bytes, .{ .method = .deflate });
try zw.finish();
// aw.writer.buffered() now holds a complete, valid ZIP archive.
```

`ArchiveWriter` is not self-referential (unlike `Archive`/`EntryReader`) — it
may be moved freely. Entry names are gated through `isSafeEntryName` on the
way in, so a zip-slip name (`../..`, absolute, drive-relative) is rejected at
`addEntry` rather than written. Classic (non-zip64) format only — see
"Ceiling" below.

## Design notes

- **Local header, not central.** Data offsets are resolved by reading the
  *local* file header directly (its own filename/extra lengths), so a
  central-vs-local `version_needed` mismatch some writers emit (seen from
  real-world producers) never matters — nothing needs patching.
- **Directory entries are skipped** during the central-directory walk (any
  name ending in `/`, or empty after backslash normalization) — `Archive`
  only ever lists members with content.
- **Bounded memory.** The archive's own bookkeeping is O(entry count) (one
  name arena); streaming an entry is O(one window) — `std.compress.flate`'s
  window for Deflate, or the caller's buffer size for Store.
- **Decompression-bomb cap.** `EntryReader.init` refuses an entry whose
  declared uncompressed size exceeds `zipstream.default_max_output`
  (**1 GiB**) with `Error.ZipEntryTooLarge`, before any byte is decompressed;
  the running Deflate output is additionally clamped to that declared size.
  `EntryReader.initMax` takes the cap explicitly for callers that legitimately
  need larger (or much smaller) entries. Note this is an absolute *size* cap,
  not a compression-*ratio* cap.
- **CRC-32 is verified on read.** `reader()` accumulates a running CRC-32 over
  every decompressed byte and compares it against the entry's
  central-directory checksum at end-of-stream; a mismatch fails the read with
  `error.ReadFailed` (the `std.Io.Reader` vtable has no room for a dedicated
  error) with `EntryReader.crcMismatch()` set, so tampered content is never
  delivered as if it were valid.

## Ceiling (documented, not a bug)

- **zip64 reading is supported** (archives/entries over 4 GiB, or archives
  with more than 65535 central-directory records) — `std.zip.Iterator`
  itself resolves the zip64 EOCD/locator and each entry's zip64 extra field
  before `Archive`/`EntryReader` ever see the (already 64-bit) sizes/offsets.
  **zip64 *writing* is not implemented** — `ArchiveWriter` emits classic
  (non-zip64) archives only, and returns `Error.ZipWriteTooLarge` rather than
  silently truncating a field that would overflow the 32/16-bit format.
- **No encrypted entries** — `std.zip.Iterator` already rejects these on
  read (`error.ZipEncryptionUnsupported`); `ArchiveWriter` doesn't offer
  encryption either.
- **Store + Deflate only** — the two methods ordinary zip tools and Excel
  emit, for both reading and writing. Any other read method (bzip2, LZMA,
  ...) is `error.UnsupportedCompressionMethod`.

## Deferred (not built)

- zip64 **writing** (reading is fully supported — see "Ceiling" above)
- Encrypted entries (no consumer needs them; legacy ZipCrypto is
  cryptographically broken and not worth adding even read-only)
- Compression methods beyond Store/Deflate (bzip2, LZMA, ...)

## Testing

`buildZip` in the test file constructs real ZIP byte streams in-code (same
`std.zip` structs the production walk parses, so the layout can't drift),
covering:

- multi-entry archives, directory-entry skipping, `find`/`findSuffix`
- shared-file-cursor streaming across consecutive entries
- a Store + Deflate mix in one archive (Deflate bytes produced via
  `std.compress.flate.Compress`, raw container, then decoded back through
  `EntryReader` and compared byte-for-byte)
- an empty archive (zero members)
- a truncated archive (central directory/EOCD missing) — `Archive.init`
  returns `error.ZipNoEndRecord` cleanly
- a corrupted local file header signature — `EntryReader.init` returns
  `Error.ZipBadFileOffset` cleanly
- a central-directory size that lies beyond the physical file (simulated
  truncation/corruption of just one entry's bookkeeping) — reading it out
  hits `error.EndOfStream` cleanly instead of looping or over-reading
- `buildZip64` hand-builds a zip64-escaped archive (0xFFFFFFFF placeholders +
  real sizes/offset in a zip64 extra field, plus a zip64 EOCD + locator ahead
  of the classic EOCD) for both Store and Deflate members — exercises
  `std.zip.Iterator`'s zip64 path without a multi-gigabyte fixture
- `ArchiveWriter`: a Store + Deflate archive written by this module round-trips
  byte-for-byte back through its own `Archive`/`EntryReader`, with the written
  CRC-32/sizes cross-checked independently via `std.zip.Iterator` directly (so
  a wrong field can't hide behind a lenient reader); `addEntry` rejects
  zip-slip names
