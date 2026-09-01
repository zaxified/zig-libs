# tar — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
  `"0000000"` — root — and `mode`/`mtime` truncated the same way. GNU tar 1.35
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
