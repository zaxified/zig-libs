# SPEC — `tar`

**Purpose** — A ustar/GNU tar reader + writer that preserves the numeric attrs (**uid/gid/mtime**)
`std.tar` drops, plus a streaming gzip-tar packer. One tar implementation for backup/restore
pipelines: parse archives produced by GNU tar/busybox, emit archives GNU tar extracts, and
round-trip byte-faithfully through both — the piece `std.tar` (read-only, name/size/mode only, no
writer) does not cover.

**Model after / Seed** — GNU tar / libarchive (behavior only; headers implemented from the public
POSIX ustar + GNU-extension layout — the spec itself, no third-party source). Extracted from the
authors' axp project: `axp-core/src/tar.zig` (writer/packer) + `axp-vault/src/backup.zig` (reader),
where it packs `sysupgrade -b`-style device backups into a content-addressed vault (Apache-2.0,
relicensed MIT). Own code — no `NOTICE` entry.

**Design & invariants**
- **Headers are the security boundary.** Every 512-byte header is checksum-verified (unsigned sum
  per spec; the signed-sum variant of ancient tars is also accepted) and bounds-checked; a truncated
  stream, short header, garbage block, or oversized GNU 'L'/'K' payload (>64 KiB `max_name_len`)
  yields `error.TruncatedArchive`/`error.BadHeader` — never a panic or over-read. Numeric fields are
  parsed leniently (garbage → 0; busybox pads oddly), the checksum validating the block as a whole.
- **Streaming, bounded memory.** `Reader` streams content via `read()` and auto-skips unread bytes
  on the next `next()`; only path/link-target strings are allocated (allocator explicit).
  `packTarGz`/`packDir` allocate exactly one flate window.
- **Format subset (busybox + GNU):** files ('0'/NUL/'7'), dirs ('5'), symlinks ('2'), hard links
  ('1'), GNU long-name ('L') / long-link ('K') records, the ustar `prefix` field (honored **only**
  under the POSIX `ustar\0` magic — GNU reuses those bytes for atime/ctime), octal and GNU/star
  base-256 size fields. pax ('x'/'g') payloads are skipped (never fatal); unknown typeflags surface
  as `.other` (writer rejects them with `error.UnsupportedKind`).
- **Reentrant, portable codec / Linux packer.** `Reader`/`Writer`/`packTarGz` are platform-pure
  (I/O only through the caller's `std.Io.Reader`/`Writer`) and compile/test anywhere; only `packDir`
  (the filesystem walker reading real attrs via raw `statx`/`readlink`) is Linux — a conscious ceiling.

**Threat model / out of scope** — Untrusted archives: the reader never panics or over-reads on
malformed input, and caps name buffers; but it does **not** sanitize paths — `../` escapes,
absolute paths and symlink targets are returned verbatim, so a caller extracting to the filesystem
must reject/clamp them itself (this module never writes files on the read side). Out of scope: pax
extended-header *interpretation* (skipped), sparse files, per-file compression other than the whole-
stream gzip, encryption/signing, and non-regular special files (fifo/dev/socket — `packDir` skips
them). `packDir` is best-effort (unstatable/unreadable entries are skipped so one bad file never
fails the archive).

**Verification** — Golden header bytes captured from GNU tar 1.35 are pinned in a test (read side)
and field-compared against the writer's emit (write side). Write→read round-trips assert
uid/gid/mtime/mode/size/path/link_target all survive, incl. >100-byte GNU 'L'/'K' long names, dirs,
symlinks and hard links; a gzip round-trip goes `packTarGz` → `std.compress.flate` decompress →
`Reader`. Malformed-input tests: truncated header/content, mid-archive truncation, bad checksum,
garbage block, hostile 'L' size, empty archive. A live external cross-check writes an archive that
system GNU `tar` must list (`tvf`, numeric ids + sizes) and extract (`xf`), and reads a
GNU-tar-produced archive back (skips cleanly with no `tar` on PATH); `packDir` round-trips real
statx attrs on Linux.

**Status** — `extract · any (packDir: linux) · both (reader+writer) · reentrant` · deps: none
(std only — `std.compress.flate` for gzip).
