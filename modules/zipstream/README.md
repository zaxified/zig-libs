# zipstream

Streaming **ZIP** archive reader: walk the central directory once, then
stream each member's *decompressed* bytes on demand. No whole-archive or
whole-entry buffering — memory use is O(one decompression window) regardless
of archive or entry size.

- **Status:** `extract` — a streaming ZIP reader; an .xlsx is a ZIP of XML
  parts, and it streams zipped `.csv` members without exposing ZIP internals
  to the caller.
- **Model after:** the ZIP central-directory layout in APPNOTE.TXT (the
  public PKWARE ZIP spec) — behavior only, no third-party source.
- **Platform:** `any` (pure `std.Io`/`std.zip`/`std.compress.flate`, no OS-
  specific code). **Role:** codec (reader only — no ZIP writing).
  **Concurrency:** reentrant — one `Archive` owns one file cursor; no
  globals, no shared state between instances.
- **Deps:** none (std only — `std.zip` for the wire structs/central-directory
  walk, `std.compress.flate` for Deflate).

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

## Ceiling (documented, not a bug)

- **No zip64** — archives or entries over 4 GiB (32-bit central-directory
  fields only). `std.zip.Iterator` itself won't reject a zip64 archive at
  this layer's call sites; treat totals near 4 GiB as unsupported.
- **No encrypted entries** — `std.zip.Iterator` already rejects these
  (`error.ZipEncryptionUnsupported`).
- **Store + Deflate only** — the two methods ordinary zip tools and Excel
  emit. Any other method (bzip2, LZMA, ...) is
  `error.UnsupportedCompressionMethod`.
- **Read-only** — no ZIP writing.

## Deferred (not built)

- zip64 (archives/entries > 4 GiB)
- Encrypted entries
- Compression methods beyond Store/Deflate (bzip2, LZMA, ...)
- ZIP writing

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
