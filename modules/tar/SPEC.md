# tar — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

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
walker reading real attrs via raw `statx`/`readlink`) is Linux. Modeled after GNU tar/libarchive
behavior; headers implemented from the public POSIX ustar + GNU-extension layout, not third-party
source — see NOTICE (own code, no attribution entry needed).

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
round-trips real statx attrs on Linux. 20 tests. Run: `zig build test-tar`.

## Backlog / deferred
None beyond the documented out-of-scope list (pax interpretation,
sparse files, per-file compression, encryption/signing, special files).

## Status
`extract · any (packDir: linux) · both (reader+writer) · reentrant` + deps: none (std only —
`std.compress.flate` for gzip) — canonical source is `pub const meta` in src/root.zig.
