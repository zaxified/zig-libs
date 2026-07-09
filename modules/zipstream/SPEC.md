# zipstream — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Streaming ZIP archive reader: walk the central directory once, then stream each member's
*decompressed* bytes on demand — no whole-archive or whole-entry buffering. `Archive.init` opens a
file (already open, not closed by `deinit`) and walks the central directory once; `EntryReader.init`
streams one entry's bytes through a caller-owned window buffer. Local header, not central: data
offsets are resolved by reading the *local* file header directly (its own filename/extra lengths), so
a central-vs-local `version_needed` mismatch some real-world writers emit never matters — nothing
needs patching. Directory entries are skipped during the central-directory walk (any name ending in
`/`, or empty after backslash normalization) — `Archive` only ever lists members with content.
Bounded memory: the archive's own bookkeeping is O(entry count) (one name arena); streaming an entry
is O(one window) — `std.compress.flate`'s window for Deflate, or the caller's buffer size for Store.
`Archive` and `EntryReader` hold internal self-pointers (the file reader's `interface`, the inflate
stream's input handle) — must be initialized in place via a `*Self` and never moved after `init`; both
share the `Archive`'s single file cursor, so one `EntryReader` must finish (or be abandoned) before
the next opens. Reentrant — one `Archive` owns one file cursor; no globals, no shared state between
instances. Std-only: `std.zip` for the wire structs/central-directory walk, `std.compress.flate` for
Deflate. Extracted from the authors' bxp project (`bxp-core/src/zipstream.zig`); wire format is the
public PKWARE ZIP spec (APPNOTE.TXT) — see NOTICE.

## Threat model / out of scope
Untrusted-archive hardening: a corrupted local file header signature → `EntryReader.init` returns
`Error.ZipBadFileOffset` cleanly (never over-reads); a central-directory size that lies beyond the
physical file (simulated truncation/corruption of just one entry's bookkeeping) hits
`error.EndOfStream` cleanly instead of looping or over-reading; a truncated archive (missing central
directory/EOCD) → `Archive.init` returns `error.ZipNoEndRecord` cleanly. Documented ceiling, not a
bug: **no zip64** (archives/entries over 4 GiB — 32-bit central-directory fields only;
`std.zip.Iterator` itself won't reject a zip64 archive at this layer's call sites, so treat totals
near 4 GiB as unsupported); **no encrypted entries** (`std.zip.Iterator` already rejects these,
`error.ZipEncryptionUnsupported`); **Store + Deflate only** — any other method (bzip2, LZMA, …) is
`error.UnsupportedCompressionMethod`; **read-only**, no ZIP writing. Not a security boundary beyond
crash/DoS resistance on malformed archives — path handling of member names is the caller's
responsibility if extracting to disk (this module never writes files).

## Verification
`buildZip` in the test file constructs real ZIP byte streams in-code (the same `std.zip` structs the
production walk parses, so the layout can't drift), covering: multi-entry archives, directory-entry
skipping, `find`/`findSuffix`; shared-file-cursor streaming across consecutive entries; a Store +
Deflate mix in one archive (Deflate bytes produced via `std.compress.flate.Compress`, raw container,
decoded back through `EntryReader` and compared byte-for-byte); an empty archive; a truncated archive
(central directory/EOCD missing); a corrupted local file header signature; a central-directory size
lying beyond the physical file. 7 tests. Run: `zig build test-zipstream`.

## Backlog / deferred
zip64 (archives/entries > 4 GiB); encrypted entries; compression methods beyond Store/Deflate (bzip2,
LZMA, …); ZIP writing. (README "Deferred (not built)"; also listed in PLAN.md wave-3 findings.)

## Status
`extract · any · codec (reader only) · reentrant` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.
