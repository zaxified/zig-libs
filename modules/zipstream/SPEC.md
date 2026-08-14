# zipstream — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — own code; wire format is the public PKWARE ZIP spec).

## Design & invariants
Streaming ZIP archive reader **and** writer. Reader: walk the central directory once, then stream each member's
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
Deflate. Original work of the zig-libs authors (MIT); wire format is the public PKWARE ZIP spec
(APPNOTE.TXT) — no third-party source, no NOTICE entry needed.

Writer: `ArchiveWriter.addEntry(name, data, .{.method=...})` per member, then `finish()`. Each
`addEntry` writes that member's local file header + data straight to the caller's `*std.Io.Writer`
immediately (Store passthrough or `std.compress.flate.Compress` for Deflate); `finish()` appends the
central directory + EOCD. Because the local file header (written before the payload) needs the final
`compressed_size`, `addEntry` buffers one entry's *compressed* copy in memory before writing it — never
the whole archive, and never more than the caller already handed in via `data`. Entry names are gated
through the same `isSafeEntryName` zip-slip predicate the reader documents, so this module can never
itself produce a zip-slip archive. Not self-referential (unlike `Archive`/`EntryReader`) — no in-place
`*Self` init needed. Classic (non-zip64) format only: offsets/sizes/entry-count must fit the 32/16-bit
ZIP fields, else `Error.ZipWriteTooLarge` before anything corrupt is written — zip64 *writing* stays in
the backlog (below); zip64 *reading* is fully supported (see next paragraph).

zip64 (archives/entries beyond the classic 32-bit fields — > 4 GiB, or > 65535 central-directory
records): supported for **reading**. `std.zip.Iterator` (Zig 0.16 std) itself parses the zip64 EOCD +
zip64 EOCD locator and each entry's zip64 extra field (`ExtraHeader.zip64_info`) before this module's
`Archive`/`EntryReader` ever see the resolved (64-bit) sizes/offsets — `Archive.init`'s own hostile-CD
pre-validation loop only inspects the always-16-bit `filename_len`/`extra_len`/`comment_len` fields, so
it's zip64-agnostic and needed no change. Verified in-repo by `buildZip64` (SPEC "Verification" below),
which forces the zip64 escape path on a small member (0xFFFFFFFF placeholders + real sizes relocated
into the zip64 extra field) purely to exercise the parsing deterministically, without a multi-gigabyte
fixture.

## Threat model / out of scope
Untrusted-archive hardening: a corrupted local file header signature → `EntryReader.init` returns
`Error.ZipBadFileOffset` cleanly (never over-reads); a central-directory size that lies beyond the
physical file (simulated truncation/corruption of just one entry's bookkeeping) hits
`error.EndOfStream` cleanly instead of looping or over-reading; a truncated archive (missing central
directory/EOCD) → `Archive.init` returns `error.ZipNoEndRecord` cleanly. A **decompression bomb** is
bounded twice: `EntryReader.init` refuses up front (`Error.ZipEntryTooLarge`) any entry whose declared
uncompressed size exceeds `default_max_output` (1 GiB — an absolute size cap, not a ratio cap;
`EntryReader.initMax` takes the cap explicitly), and the running Deflate output is clamped to the
declared size, so a stream that expands past its own central-directory bound is cut off there rather
than read unbounded. **Content integrity** is checked, not assumed: `reader()` accumulates a CRC-32 over
every decompressed byte and compares it against the entry's *central-directory* checksum (authoritative
even under a post-data data descriptor, where the local header's copy is zero) at end-of-stream — a
mismatch fails the read with `error.ReadFailed` and `EntryReader.crcMismatch()` set. zip64 archives/entries (> 4
GiB, or > 65535 records) are read correctly — not a ceiling, see "Design & invariants" above. Documented
ceiling, not a bug: **no encrypted entries** (`std.zip.Iterator` already rejects these,
`error.ZipEncryptionUnsupported`); **Store + Deflate only** — any other method (bzip2, LZMA, …) is
`error.UnsupportedCompressionMethod`. `ArchiveWriter` writes classic (non-zip64) archives only — an
entry/archive that would overflow the 32/16-bit ZIP fields is refused with `Error.ZipWriteTooLarge`
before anything is written, same "clean typed error, never silent truncation" discipline as the reader.
Not a security boundary beyond crash/DoS resistance on malformed archives — path handling of member
names is the caller's responsibility if extracting a *read* archive to disk (this module's reader never
writes files); `ArchiveWriter` gates entry names through the identical `isSafeEntryName` zip-slip
predicate on the way in, so the module itself can't be tricked into emitting a zip-slip archive.

## Verification
`buildZip` in the test file constructs real ZIP byte streams in-code (the same `std.zip` structs the
production walk parses, so the layout can't drift), covering: multi-entry archives, directory-entry
skipping, `find`/`findSuffix`; shared-file-cursor streaming across consecutive entries; a Store +
Deflate mix in one archive (Deflate bytes produced via `std.compress.flate.Compress`, raw container,
decoded back through `EntryReader` and compared byte-for-byte); an empty archive; a truncated archive
(central directory/EOCD missing); a corrupted local file header signature; a central-directory size
lying beyond the physical file. `buildZip64` similarly hand-builds a zip64-escaped archive (0xFFFFFFFF
placeholders + real sizes/offset relocated into the zip64 extra field, plus a zip64 EOCD + locator ahead
of the classic EOCD) on a small member, covering both Store and Deflate through that path. Writer tests
round-trip `ArchiveWriter`'s output (Store + Deflate) back through this module's own `Archive`/
`EntryReader` byte-for-byte, cross-check the written CRC-32/sizes independently via `std.zip.Iterator`
directly (so a wrong field written by `ArchiveWriter` can't hide behind a lenient reader), and confirm
`addEntry` rejects zip-slip names.

`write_golden_test.zig` freezes what used to be an ad hoc, uncommitted check: a small
`ArchiveWriter`-produced archive (`testdata/write_golden.zip`, 327 bytes, Store + Deflate entries) was
verified once against the real `unzip`/`zipinfo` (`unzip -t` clean, `zipinfo -v` confirms CRC-32/sizes/
EOCD/central-directory offsets, `unzip -p` byte-exact for both entries) and committed. `ArchiveWriter`
is asserted to reproduce those exact bytes offline (no subprocess); local-header-vs-central-directory
consistency, CRC-32, sizes, and the end-of-central-directory record are each asserted directly against
the frozen bytes, and this module's own `Archive`/`EntryReader` are asserted to decode them back to the
original plaintext. `std.zip.Iterator`'s agreement is kept as an extra internal-consistency check but
is not counted as the external oracle (see that file's doc comment for the reasoning). Run: `zig build
test-zipstream`.

## Backlog / deferred
zip64 **writing** (`ArchiveWriter` is classic-format only — zip64 reading is fully supported, see
"Design & invariants"; not worth the extra-field/EOCD64 bookkeeping until a real >4 GiB or
>65535-entry write use case shows up); encrypted entries (no consumer needs authoring/reading
password-protected members, and ZipCrypto's legacy stream cipher is cryptographically broken — not
worth building even for read-only support; AES per WinZip AE-x would be a genuine but currently
unneeded addition); compression methods beyond Store/Deflate (bzip2, LZMA, …) — Store/Deflate are the
two methods ordinary zip tools and Excel emit, no observed producer needs the rest. (README "Deferred
(not built)".)

## Status
`extract · any · codec (reader + writer) · reentrant` + deps: none (std only) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** writer bytes cross-checked live via std.zip.Iterator; real unzip/zipinfo check was ad hoc, not standing

**How it got there.** The anchoring work landed. DONE 23312c0: unzip/zipinfo agreement was PROSE ONLY; now a committed archive
