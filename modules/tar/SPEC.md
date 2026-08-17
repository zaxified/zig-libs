# tar — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — own code; the installed GNU tar binary was used only as a black-box test oracle).

## Design & invariants
Headers are the security boundary: every 512-byte header is checksum-verified (unsigned sum per
spec; the signed-sum variant of ancient tars also accepted) and bounds-checked; a truncated stream,
short header, garbage block, or oversized GNU 'L'/'K' payload (>64 KiB `max_name_len`) yields
`error.TruncatedArchive`/`error.BadHeader` — never a panic or over-read. Numeric fields parse
leniently (garbage → 0; busybox pads oddly), checksum validating the block as a whole. Streaming,
bounded memory: `Reader` streams content via `read()` and auto-skips unread bytes on the next
`next()`; only path/link-target strings are allocated (allocator explicit); `packTarGz`/`packDir`
allocate exactly one flate window. Format subset (busybox + GNU): files/dirs/symlinks/hard links,
GNU long-name('L')/long-link('K') records, ustar `prefix` field (honored only under POSIX `ustar\0`
magic — GNU reuses those bytes for atime/ctime), octal and GNU/star base-256 size fields; pax
('x'/'g') payloads skipped (never fatal); unknown typeflags surface as `.other` (writer rejects with
`error.UnsupportedKind`). Reentrant, portable codec / Linux packer: `Reader`/`Writer`/`packTarGz` are
platform-pure (I/O only through the caller's `std.Io.Reader`/`Writer`); only `packDir` (filesystem
walker reading real attrs via raw `statx`/`readlink`) is Linux. Implements the public POSIX ustar
format plus the documented GNU long-name/long-link ('L'/'K') header extensions; the installed GNU
tar binary was used only as a black-box compatibility test oracle (see Verification) — its source
was never consulted, and no GPL code is involved — no NOTICE entry needed (own code, no third-party
source).

## API surface additions (2026-08-18)
`packDirToPath(io, gpa, roots, out_path)` wraps `packDir` with the create-file/wrap-writer/flush
steps a caller otherwise repeats for every call site; `packDir` is unchanged and still writes to a
caller-owned `*std.Io.Writer`. `Entry.dupe(allocator) -> OwnedEntry` copies the borrowed
`path`/`link_target` (valid only until the next `Reader.next()`/`deinit()`, per the `Entry` doc
comment) into the caller's allocator; `OwnedEntry` is a distinct type with its own `deinit`, so a
caller building a manifest across multiple entries has an unmistakable ownership signal at the call
site rather than relying on remembering the doc comment.

## Threat model / out of scope
Untrusted archives: the reader never panics or over-reads on malformed input, and caps name buffers
— but it does **not** sanitize paths: `../` escapes, absolute paths and symlink targets are returned
verbatim, so a caller extracting to the filesystem must reject/clamp them itself (this module never
writes files on the read side). Out of scope: pax extended-header *interpretation* (skipped), sparse
files, per-file compression other than the whole-stream gzip, encryption/signing, non-regular special
files (fifo/dev/socket — `packDir` skips them). `packDir` is best-effort (unstatable/unreadable
entries skipped so one bad file never fails the archive).

## Verification
Golden header bytes captured from GNU tar 1.35 pinned (read side) and field-compared against the
writer's emit (write side). Write→read round-trips assert uid/gid/mtime/mode/size/path/link_target
survive, incl. >100-byte GNU 'L'/'K' long names, dirs, symlinks, hard links; a gzip round-trip goes
`packTarGz` → `std.compress.flate` decompress → `Reader`. Malformed-input tests: truncated
header/content, mid-archive truncation, bad checksum, garbage block, hostile 'L' size, empty archive.
A live external cross-check writes an archive that system GNU `tar` must list (`tvf`) and extract
(`xf`), and reads a GNU-tar-produced archive back (skips cleanly with no `tar` on PATH); `packDir`
round-trips real statx attrs on Linux.

The live cross-check only anchors the writer on a machine with `tar` installed. `write_golden_test.zig`
closes that gap offline: five archives (`testdata/write_golden_*.tar`) captured once from real GNU tar
1.35 (`--format=ustar` for four — byte-identical magic to this module's own writer, so those are
asserted fully byte-exact, incl. the 512-byte content padding and the two-zero-block trailer; `--format=gnu`
for the >100-byte long-name case, asserted field-by-field since GNU's own magic/uname/gname differ by
design) cover the writer's header field padding/octal formatting, the checksum field, every typeflag
(file/dir/symlink/hardlink), the GNU 'L' long-name extension, and — read back through this module's own
`Reader` — the real 10240-byte record-blocking-factor padding GNU tar itself emits (which this module's
`Writer.finish()` deliberately does not replicate; a design choice, not a gap — see that file's doc
comment). No subprocess, no skip path.

`packDirToPath` is verified by a real round-trip through disk: pack a tree into a path, then reopen and
decompress+read that exact file back with `Reader`, asserting the same content and stats `packDir`
itself would produce. `Entry.dupe`/`OwnedEntry` is verified by a test that duped an entry's fields,
then called `Reader.next()` again (the operation that invalidates a plain `Entry`'s borrowed
`path`/`link_target`) and only then asserted the duped copy's content — a test shaped so it would
fail if `dupe` forgot to actually copy the bytes, unlike a test that asserts before advancing (which
the un-duped path would also pass).

Run: `zig build test-tar`.

## Backlog / deferred
None beyond the documented out-of-scope list (pax interpretation,
sparse files, per-file compression, encryption/signing, special files).

## Status
`extract · any (packDir: linux) · both (reader+writer) · reentrant` + deps: none (std only —
`std.compress.flate` for gzip) — canonical source is `pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class A · oracle MIXED

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle MIXED** — anchored for some paths, self for others — the evidence below names which.

**What the tests actually contain.** read path: real GNU tar 1.35 golden header; write path only via skippable live tar test

**How it got there.** The anchoring work landed. DONE 23312c0: 5 real GNU tar archives frozen, write path anchored offline
