# zipstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security re-audit, two further findings fixed, plus a doc correction.
  The delivered 1 GiB `default_max_output` ceiling was pinned by nothing — both
  bomb-cap tests passed `initMax` their own explicit values, so raising the shipped
  default was invisible; a test now asserts the literal. And `fuzzArchiveInit` called
  `Archive.init` then `deinit` without ever opening an `EntryReader`, so the CRC check,
  the output cap and the local-vs-central `data_off` computation were never fuzzed; the
  harness now reads every parsed entry and asserts it reached them. The README's design
  notes and SPEC's threat model, which still described the module as if the
  decompression-bomb cap and the CRC verification did not exist, were corrected — the cap
  is an absolute size cap, not a compression-ratio cap. Tests and docs only; no API or
  behaviour change.
- **2026-08-09** — **BEHAVIOURAL, not breaking** — members are integrity-checked on read.
  `Entry` carries `crc32`, taken from the central directory (the local header's copy is
  zero when the writer used a post-data data descriptor, as real streaming writers do), and
  `EntryReader.reader()` now accumulates a running CRC-32 over every decompressed byte and
  compares it at end-of-stream. A corrupted or tampered member that previously read to the
  end as valid data now fails. Because `std.Io.Reader`'s vtable has a fixed error set with
  no room for a dedicated variant, the failure surfaces as `error.ReadFailed`; the new
  `EntryReader.crcMismatch()` tells that apart from an underlying I/O failure.
- **2026-08-05** — The reader gained an external anchor: a real foreign-tool-produced
  `.xlsx` fixture is asserted against in-tree, and the tar/zipstream agreement with the
  system tools is frozen as captured bytes instead of being skipped when the tool is
  absent. Tests only.
- **2026-07-21** — **ZIP writing.** New `ArchiveWriter` (`init` / `addEntry` / `finish`)
  streaming to any `*std.Io.Writer`: Store and Deflate, CRC-32 per member, local header +
  data per entry, central directory and EOCD on `finish()`, headers written little-endian
  regardless of host byte order. Entry names on the write side go through the same
  `isSafeEntryName` guard as the read side (`error.ZipUnsafeEntryName`), and the classic
  32/16-bit ZIP fields are overflow-guarded (`error.ZipWriteTooLarge`) — the writer emits
  no zip64 records. Separately, zip64 on **read** was confirmed to work: Zig 0.16's
  `std.zip.Iterator` resolves the zip64 EOCD, locator and per-entry extra field to 64-bit
  before this module sees it, so the module's previously documented "no zip64" ceiling was
  stale and was corrected.
- **2026-07-21** — **BEHAVIOURAL, not breaking** — two extraction-safety audit findings
  fixed. Entry names were surfaced verbatim, so a consumer doing `create(entry.name)`
  inherited the classic zip-slip traversal; the extraction contract is now stated on the
  module and on `Entry.name`, and `isSafeEntryName` is offered as a ready predicate
  (it rejects empty names, absolute paths on either separator, Windows drive/UNC prefixes
  and any `..` segment). And the Deflate path had no output bound at all, unlike the Store
  path — a decompression bomb could expand without limit; `EntryReader.initMax` now refuses
  an entry whose declared uncompressed size exceeds the caller's cap
  (`error.ZipEntryTooLarge`) and clamps the running output, with `EntryReader.init`
  delegating at the new `default_max_output` of 1 GiB.
- **2026-07-19** — Security audit (CRIT). `std.zip.Iterator.next` advances by
  `46 + filename_len + extra_len + comment_len` evaluated in `u16`, which a
  central-directory header with `filename_len >= 65490` overflows — a panic in
  Debug/ReleaseSafe, a silent misparse in ReleaseFast — and it was reachable straight
  through `Archive.init` on an untrusted archive, before this module's own name-length
  guard. `Archive.init` now walks the central directory itself in `u64` arithmetic first
  and rejects any header whose advance would exceed `u16` with
  `error.ZipBadCentralDirectory`, so the overflow can never be reached. The audit raised
  six findings in total and all six were fixed; the other five are the entries above.
- **2026-07-09** — New module: streaming ZIP reader, lifted from a sibling project. Walks
  the central directory once and exposes each member as an on-demand reader over its
  decompressed bytes, so a consumer's memory ceiling is O(one decompression window)
  regardless of archive or entry size; the local file header is read directly to locate the
  data, which sidesteps the central-vs-local `version_needed` mismatch some writers emit.
  Store and Deflate only — any other method is `error.UnsupportedCompressionMethod`.
  Documented ceiling at this point: no zip64, no encrypted entries, no other compression
  methods, and read-only (no ZIP writing).
