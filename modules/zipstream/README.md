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
involved. Test data is a different question and is answered separately:
`src/testdata/write_golden.zip` holds only text this repo wrote, but
`src/testdata/xlsx_sample.xlsx` is LibreOffice's own output and a majority of
its bytes are LibreOffice's default theme and style boilerplate, not ours.
That is recorded in [`NOTICE`](NOTICE) as a provenance note — a record, not a
condition.

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

Modification time and Unix mode per entry:

```zig
try zw.addEntry("bin/run.sh", script, .{
    .mtime = 1727700007, // Unix seconds, UTC
    .mode = 0o755,       // unzip restores it
});
```

`mtime` goes into the DOS date/time fields (clamped to 1980..2107, even
seconds) and, for a time from 1970 to 2106 (unsigned 32-bit), into an Info-ZIP
extended-timestamp (`UT`) extra field carrying the exact UTC instant. Without
`mtime` the entry gets 1980-01-01 00:00:00 — fixed, so the output stays
reproducible. `mode` marks the entry as made on Unix with `S_IFREG | mode` in
its external attributes. On read, `Entry.mtime` (the `UT` time if present,
else the DOS fields read as UTC; null for an invalid DOS date) and
`Entry.mode` (Unix hosts only) report the same.

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

## Since 2026-10-20 (S2)

```zig
// Any positional source: a file (`Archive.init`), memory, or your own.
var ms: zipstream.MemorySource = .{ .bytes = bytes };
try archive.initSource(gpa, ms.source(), .{ .list_directories = true, .legacy_names = .cp437 });

// Each EntryReader has its own cursor: several open at once, from several
// threads (pread). Encrypted entries and other methods:
try er.open(&archive, entry, &window, .{ .password = "secret" }); // WinZip AES or ZipCrypto
defer er.deinit(); // needed for methods beyond Store/Deflate (zstd)

// Writing: streamed members (data descriptor), zip64, zstd, AES, comments.
const w = try zw.beginEntry("big.xml", .{ .method = .zstd, .encryption = .{ .password = "p", .io = io } });
try w.writeAll(chunk); // … as the data arrives
try zw.endEntry();
try zw.addDirectory("docs", .{});
try zw.addSymlink("docs/latest", "v2.txt", .{});
zw.comment = "built 2026-10-20";

// Extraction with a zip-slip guard, a total-size cap and a symlink policy.
try zipstream.extractAll(&archive, io, dest_dir, .{ .symlinks = .skip, .max_total = 1 << 32 });
```

- **zip64** read and write (automatic past 4 GiB / 65 534 entries;
  `force_zip64`; `allow_zip64 = false` restores the classic-only refusal).
- **Methods:** Store, Deflate, Zstandard (93, via `zstd`), bzip2 (12, via `bzip2`),
  LZMA (14) and XZ (95, via `lzma`) — the compressors byte-identical to libbzip2 /
  liblzma, checked against Python `zipfile` both ways; any other through a
  `Codec` (`Archive.Options.codecs`, `AddEntryOptions.codec`) — Go's
  `RegisterDecompressor`.
- **Encryption:** WinZip AES-128/192/256 read (AE-1/AE-2) and write (AE-2);
  ZipCrypto read only (broken, never written). Checked against 7-Zip and
  Info-ZIP (`tools/crypto_fixtures.sh`).
- **Entries:** comments (entry and archive), raw extra field, directories
  (`list_directories`), symlinks (`isSymlink`), Info-ZIP Unicode Path names,
  optional CP437 decoding of legacy names.
- **Speed:** CRC-32 via the hardware-backed `crc32` module; 0.31–1.07× Go
  `archive/zip` (`zig build bench-zipstream`).

## Ceiling (documented, not a bug)

- Deflate64 (9), PPMd (98) and the legacy PKZIP methods are listed and refused
  (`error.UnsupportedCompressionMethod`); a consumer can register its own `Codec`.
- No in-place editing of an existing archive (append, delete, rename).

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
  this module's own zip64 central-directory path without a multi-gigabyte fixture
- `ArchiveWriter`: a Store + Deflate archive written by this module round-trips
  byte-for-byte back through its own `Archive`/`EntryReader`, with the written
  CRC-32/sizes cross-checked independently via `std.zip.Iterator` directly (so
  a wrong field can't hide behind a lenient reader); `addEntry` rejects
  zip-slip names
