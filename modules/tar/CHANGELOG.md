# tar — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — tests: deterministic fuzz driver `TAR_FUZZ` over the existing harnesses (`reader`, plus `mutated`: a `Writer`-built archive, damaged, because random octets never pass `verifyChecksum`).
- **2026-10-05** — **Fixes** found by a Go archive/tar differential oracle (`tools/go_oracle/`,
  replayed by `src/go_oracle.zig`, re-taken by `zig build interop-tar`): GNU/star base-256 is now read in
  every numeric field, not only `size` — a uid over 2 097 151 from `tar --format=gnu` was read as 0
  (root), a negative or far-future mtime as 0. A numeric field holding anything but octal digits and
  padding (`12x4567`, an `8`, a sign, an inner space) is now `error.BadHeader`; it was read as 0. A
  base-256 id that does not fit `u32` (negative, ≥ 2^32) is `error.BadHeader`, as GNU tar refuses it. A
  NUL-typeflag entry whose name ends in `/` is now `.dir` with no content (GNU tar and Go agree; it was
  an empty `.file`). `packTarGz` and `packDir` no longer trip `flate.Compress`'s assertion on a
  destination writer with a buffer of 8 bytes or less (`std.Io.Writer.Allocating.init`, an unbuffered
  file): such a writer gets an internal 4 KiB staging pass-through; output is byte-identical. A pax
  `mtime` with an empty fraction (`1.`) is accepted as whole seconds (GNU tar and Go do). Anchor grade
  MIXED → EXTERNAL.

- **2026-10-04** — **Tests:** mutation run (53 schemata mutants, 51 killed, 2 equivalent;
  16 new assertions in 10 tests). Pins the size-overflow guards on the 'g' and pax `size`
  paths, the per-entry scope and deletion (`size=`) of pax records, digit-only pax lengths
  and values, typeflag '7' as a file, an empty GNU 'L' payload refused, GNU-magic atime
  bytes not taken as a prefix, both checksum forms, the exact ustar name/prefix limits and
  the 8 GiB size-encoding boundary. No code change.

- **2026-09-30** — **Additive** (C17): pax `uid`, `gid` and `mtime` records are honoured on read
  and pax 'x' headers can be written. `Entry` gains `mtime_nsec: u32 = 0` (also on `OwnedEntry`;
  `mtime` stays whole seconds, floor semantics: -1.25 s is `mtime = -2`, `mtime_nsec = 750_000_000`).
  The reader takes `uid`/`gid` (decimal, must fit `u32`) and `mtime` (`[-]sec[.frac]`, fraction cut at
  nine digits) from a pax header over the ustar fields, as `path`/`linkpath`/`size` already did; an
  empty value deletes the keyword, a repeated one is last-wins, a non-numeric or over-range value is
  `error.BadHeader` (previously such records were skipped). New `WriteOptions{ .long_names = .gnu | .pax }`
  and `Writer.initOptions`; `Writer.init` and the default `.gnu` output are byte-identical to before.
  `.pax` writes a `././@PaxHeader` 'x' record set (`gid linkpath mtime path size uid`, exact
  `"<len> <key>=<value>\n"` form) for what ustar cannot hold, tries the ustar `prefix`/`name` split
  for a long path first, and carries negative/out-of-range/fractional mtimes and ids over 0o7777777
  that `.gnu` refuses with `FieldOutOfRange`. `mtime_nsec` above 999 999 999 is `FieldOutOfRange` in
  both modes. Anchored to GNU tar 1.35 `--format=pax` and Python `tarfile` archives
  (`testdata/read_pax_*.tar`).
  Write direction cross-checked by the coordinator on an archive this module wrote in `.pax` mode
  (150-byte path, uid 5000000 / gid 6000000, mtime 1727700007.5, mtime -1.25, a 130-byte symlink
  target): GNU tar 1.35 `-tvv --numeric-owner` and Python 3.14 `tarfile` both read every field back
  (GNU tar prints the negative fractional time shifted, Python gives -1.25 exactly). Also: a `path`
  or link target containing NUL is now `FieldOutOfRange` in both modes (no tar form carries one; it
  came back truncated before).

- **2026-09-30** — **BEHAVIOURAL, not breaking:** the reader honours pax extended headers
  ('x'). `path`, `linkpath` and `size` now override the ustar fields, as Python's tarfile
  (PAX_FORMAT is its default since 3.8), Go's archive/tar and bsdtar intend for a name over
  100 bytes or a file over 8 GiB. Before, the header was discarded: such an entry came back
  under its truncated ustar name, and a pax `size` (0 in the ustar field) desynchronised the
  stream. A malformed pax header (a record whose length, newline, `=` or digits do not add up,
  a NUL in a path, a payload over the new `max_pax_len` of 1 MiB) is now `error.BadHeader`
  where it used to be skipped. Global pax headers ('g') are still skipped. Found by the
  2026-09-30 competitive survey; anchored against GNU tar `--format=pax`.
- **2026-09-10** — A1 fix (P1, no in-repo consumer): **base-256 `size` field
  ignored 3 of its 11 magnitude bytes.** `sizeField` only read `field[4..12]`
  (the low 64 bits); a crafted header whose magnitude set any of `field[1..4]`
  (bits 64-87) silently reported the truncated low-64-bit value instead of the
  size actually encoded — a header claiming `2^64 + 5` read back as `size = 5`
  behind a valid checksum. Now `error.BadHeader` whenever those 3 bytes are
  non-zero, matching the existing overflow guard's stance that a header this
  close to `maxInt(u64)` is malformed, not a legitimately huge file.
  `parseHeader`/`sizeField` are now fallible.

- **2026-09-07** — Fuzz reach: `fuzzReader` never saw an archive. It opened
  `smith.bytes(&buf)` and then drew the length with `smith.valueRangeAtMost`; `bytes`
  consumes `@min(buf.len, in.len)` octets and a ranged draw reads EIGHT more as a
  little-endian `u64`, returning the range MINIMUM when fewer remain, so the length was 0
  for every input a corpus can carry — and the target had no corpus, so the one input it
  ever ran was empty. Measured 2026-09-07: 1 round, 0 entries walked, 0 content octets
  read. ⚠ The buffer was also too small for the threat model the harness's own comment
  names: at `4 * block_size` = 2048 octets a GNU long-name archive does not fit (the 'L'
  record, its payload block, the real header, one content block and the two-block
  terminator are 3072), so the long-name payload could not have passed through even with
  a corpus. The draw is now one `smith.slice`, the buffer is `8 * block_size`, and the
  corpus is built at run time from this module's own `Writer`: a one-file archive, a
  dir/file/symlink tree, a 137-octet path forcing the GNU 'L' record, an archive with no
  terminator, a corrupted `chksum`, a size field claiming 8 GiB behind a valid checksum,
  a block of 0xFF, and the empty archive. A corpus guard builds from the SAME place the
  harness does and pins 7 non-empty, 7 entries, 4 refusals and 1556 content octets — of
  which 1536 come from the lying-size seed reading until the stream runs out.

- **2026-09-01** — Security audit: **the reader no longer honors a `size` field on an
  entry type that carries no content**, which was a content-smuggling desync. POSIX is
  explicit ("No data logical records are stored for types 1, 2, or 5"), and GNU tar
  1.35 ignores the field for `'1'`, `'2'`, `'3'`, `'4'`, `'5'` and `'6'` alike.
  Honoring it let a crafted archive hide entries: a link entry claiming one block of
  content, followed by a valid header, made this `Reader` report 2 entries where
  `tar tf` on the same bytes reports 3 — so a scanner or policy gate built on it
  never saw a file a real extractor still creates. The typeflag set was established
  against GNU tar rather than assumed; `'7'` (contiguous) genuinely does carry
  content and is deliberately excluded, with a positive-control test to keep the fix
  from degenerating into "ignore every size field". `Entry.size` now reports the
  content actually present.
- **2026-09-01** — Security audit: **`Writer` refuses a numeric header field that does
  not fit instead of silently truncating it** (new `WriteError.FieldOutOfRange`). The
  8-byte octal fields hold 21 bits, so uid/gid `2097152` was being written as
  `"0000000"` — root — and `mode` truncated the same way. (This entry used to name
  `mtime` alongside them; `mtime` is the 12-byte field at `block[136..148]`, 33 bits,
  and `writeHeader` has always checked it against `max_octal_12`. Reading it as an
  8-byte field would mean a truncation at 1970-01-25, which never existed. Corrected
  2026-09-17 after a consumer checked whether its restore path could hit it.) GNU tar 1.35
  refuses the identical value ("value 2097152 out of uid_t range 0..2097151") rather
  than writing it. Reachable wherever high ids exist: userns/`subuid` mappings,
  idmap ranges, `overflowuid`. `packDir` stays best-effort as documented — it skips
  such an entry rather than failing the archive — but now counts it in the new
  `PackStats.skipped`, so a short archive is distinguishable from a complete one;
  `packTarGz`, which is handed an explicit entry list, propagates the error instead.

- **2026-08-18** — New `packDirToPath(io, gpa, roots, out_path)`: the create-file /
  wrap-writer / call-`packDir` / flush dance every caller was repeating verbatim,
  collapsed into one call with the same `PackStats` return. `packDir` itself is
  unchanged (still writes to a caller-owned `*std.Io.Writer`).
- **2026-08-18** — New `Entry.dupe(allocator) -> OwnedEntry`: `Entry.path`/
  `link_target` are borrowed from the `Reader` and valid only until the next
  `next()`/`deinit()` — documented, but easy to trip over when building a manifest
  across multiple entries. `dupe` copies both into the caller's allocator and returns
  a distinctly-typed `OwnedEntry` (its own `deinit(allocator)`, not `Entry`'s, since
  `Entry` never owns anything) so ownership is visible at the call site rather than
  inferred from the doc comment.
- **2026-08-14** — Finished a retraction that stopped halfway on 2026-07-09.
  `667b29d` judged "modeled after GNU tar / libarchive" an overstatement —
  the headers come from the POSIX ustar + documented GNU extension layout and
  a GNU tar binary served as a black-box oracle — and corrected `SPEC.md`.
  It never reached `README.md` or `src/root.zig`'s `.model_after`, which is
  the canonical field the README line is derived from, so the retracted claim
  survived for five weeks in the two places a reader meets first. Both fixed.
  Documentation only; no code change.

- **2026-07-19** — Security audit: a crafted GNU/star base-256 archive size field could
  overflow `padding()`'s internal arithmetic and crash the reader before any content was
  read; fixed the same day. A second finding (path-traversal in caller-supplied
  extraction) turned out to already be documented as the caller's responsibility; a
  third was accepted as informative-only.
- **2026-07-05** — New module: ustar/GNU tar reader+writer (preserves uid/gid/mtime) +
  gzip.
