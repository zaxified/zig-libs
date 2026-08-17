# tar — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
