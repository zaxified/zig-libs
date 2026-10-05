# zipstream — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-05** — **Fixes and behaviour changes** found by a Go archive/zip differential oracle
  (`tools/go_oracle/`, replayed by `src/go_oracle.zig`, re-taken by `zig build interop-zipstream`;
  Info-ZIP unzip 6.0 as the tiebreaker). The central directory is now this module's own walk, not
  `std.zip.Iterator`: an entry with an unsupported method or the encryption flag is **listed** and
  refused when opened (`error.UnsupportedCompressionMethod`, new `error.ZipEncryptedEntry`, new
  `Entry.encrypted`) — before, one such member made the whole archive unreadable; a malformed extra
  field no longer refuses the archive (the SPEC already promised that); archives with a prepended stub
  whose offsets were not adjusted (self-extractors), disk numbers set, or an off directory size are
  read, as unzip and Go read them; an empty member name is listed (only a trailing '/' is a directory).
  A stored entry whose compressed and uncompressed sizes differ is refused when opened
  (`error.ZipBadCentralDirectory`); it was read to the uncompressed size, past the member. Times: the
  `UT` mtime is read as UNSIGNED 32-bit (2100 came back as 1963; Go, zipinfo and 7-Zip read it
  unsigned), NTFS (0x000a), PKWARE Unix (0x000d) and `UX` (0x5855) mtimes are read, the last time
  record wins; `ArchiveWriter` writes `UT` for 1970..2106 (it stopped at 2038). `ArchiveWriter` sets
  general-purpose bit 11 (UTF-8) for a non-ASCII UTF-8 name; without it Go flagged the name non-UTF-8
  and unzip showed it in code page 437. ASCII-only archives are byte-identical to before. A missing
  end record is `error.ZipNoEndRecord` (new member of `Error`, same name std used). Anchor grade
  MIXED → EXTERNAL. **Consumer note:** code that caught `UnsupportedCompressionMethod` (or std's
  `ZipEncryptionUnsupported`) from `Archive.init` to skip a whole archive now gets it from
  `EntryReader.init` for that one entry instead (bxp `pipeline.zig` does the former).

- **2026-10-04** — **Tests:** mutation run (37 schemata mutants, 36 killed, 1 equivalent;
  7 new tests). Pins the central-directory pre-check's exact edge and its own errors (bad
  signature, unsupported method), backslash normalisation, the Unix-host rule for `mode`,
  the `UT` mtime flag, the bomb cap at exactly `max_output`, the deflate clamp to the
  declared size, `DosDateTime.toUnix` range and leap-year checks, the 65 535-entry writer
  limit and the writer's permission-bit mask. No code change.

- **2026-09-30** — **Entry modification time and Unix mode, write and read.** `AddEntryOptions.mtime`
  (Unix seconds → DOS fields + Info-ZIP `UT` extra field) and `.mode` (host Unix + `S_IFREG|mode`
  attributes); `Entry.mtime` / `Entry.mode` on read (`UT` preferred over the DOS fields); new
  `DosDateTime` (`fromUnix`, `toUnix`, `min`, `max`). ⚠ **Output bytes change:** without `mtime` the
  writer now stores 1980-01-01 00:00:00 instead of a zero date (which is not a valid date — every unzip
  tool showed garbage). Anything that pinned `ArchiveWriter` output byte-for-byte differs in four bytes
  per entry; the module's own golden was recaptured and re-verified with `unzip -t`/`zipinfo`. New
  anchors: a writer archive with `mtime`/`mode` checked by zipinfo and Python `zipfile`, and two
  Info-ZIP-made archives (DOS-only, and `UT` + `ux`) read back by this module (`src/mtime_test.zig`).

- **2026-09-07** — Fuzz reach: `fuzzArchiveInit`'s fuzzed half never ran. It opened
  `smith.bytes(&buf)` and then drew the length with `smith.valueRangeAtMost`, which
  returns the range MINIMUM once `bytes` has eaten the input, so the length was 0 — and
  with no corpus the one input the target ever ran was empty. Path 1 therefore wrote a
  ZERO-BYTE file for `Archive.init` to refuse, and path 2's mutation count
  `smith.valueRangeAtMost(u8, 0, 24)` was likewise 0, so it walked the PRISTINE archive
  with **not one octet mutated**, on every run. The F8 fix — "start from a real archive
  and apply a handful of random byte mutations" — was right about the shape and bought
  nothing, because the draw choosing the mutation count was collapsed. Both paths take
  the same thing (the octets of a zip file), so the harness now draws them byte-first in
  one `smith.slice` and the "mutated valid archive" idea moved into a corpus built from
  this module's own `ArchiveWriter`: the Store+Deflate archive as written, a corrupted
  member CRC, a corrupted deflate stream, a broken EOCD signature, a central-directory
  offset past the end of the file, a half-truncated archive, a bare 22-octet EOCD, and
  the empty file. ⚠ The F8 regression test used to drive the harness off 64 PRNG-filled
  buffers — a DIFFERENT input distribution from the one the `--fuzz` target replays,
  which is why it could not notice that the target itself ran a single empty input. It
  now measures the corpus the harness actually gets, and pins `EntryReader` openings at 6
  (three walkable archives, two members each).

- **2026-08-18** — Portability fix (`check-portable`), test-only: a corrupted-entry test
  allocated `a.alloc(u8, lying_entry.uncompressed_size)` directly; `uncompressed_size`
  stays `u64` in production deliberately (zip64 entries can legitimately exceed a 32-bit
  `usize` — that's what the real `entry.uncompressed_size > max_output` guard exists to
  reject before any real allocation happens), so it fails to compile as an allocation
  count on a 32-bit target. This test sets it to a small literal (`1 << 20`) itself a few
  lines up, so the value is always in-range here; added a documented `@intCast` rather
  than touching the field's production type. Compile-only, identical semantics — no new
  test. Verified: `zig build portable-zipstream` and `zig build test-zipstream
  --summary all` (32/32) both green.
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
