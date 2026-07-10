# tar

**ustar/GNU tar** reader + writer that preserves the numeric attrs
(**uid/gid/mtime**) which `std.tar` drops, plus a streaming **gzip-tar
packer**. One tar implementation for backup/restore pipelines: parse archives
produced by GNU tar/busybox, emit archives GNU tar extracts, and round-trip
byte-faithfully through both.

- The writer packs device backups (`sysupgrade -b`
  style) and the
  reader ingests them into a content-addressed vault.
- **Model after:** GNU tar / libarchive (behavior only — headers implemented
  from the POSIX ustar + GNU extension layout).
- **Platform:** the codec (`Reader`/`Writer`/`packTarGz`) is platform-pure —
  no I/O beyond the caller's `std.Io.Reader`/`Writer`, compiles and tests
  anywhere; only `packDir` (the filesystem walker) is Linux (raw
  `statx`/`readlink` via `std.os.linux` — a conscious ceiling). **Role:**
  both (reader + writer). **Concurrency:** reentrant (no globals; one
  `Reader`/`Writer` per stream).
- **Deps:** none (std only — `std.compress.flate` for gzip).

Provenance: original work of the zig-libs authors (MIT). The wire format is
the public POSIX ustar / GNU tar spec — no third-party source involved; no
NOTICE entry needed.

## API

```zig
const tar = @import("tar");

// Write: entries -> plain tar on any *std.Io.Writer.
var tw = tar.Writer.init(dst);
try tw.writeEntry(.{ .path = "etc", .kind = .dir, .mode = 0o755, .mtime = t }, "");
try tw.writeEntry(.{ .path = "etc/hostname", .mode = 0o644, .uid = 1000,
    .gid = 1000, .mtime = t }, "router\n");
try tw.writeEntry(.{ .path = "etc/link", .kind = .symlink,
    .link_target = "hostname", .mode = 0o777 }, "");
try tw.finish(); // two zero trailer blocks
// Large files: tw.writeHeader(entry) -> stream entry.size bytes to dst
// -> tw.writePadding(entry.size).

// Read: streaming, bounded memory (only names are buffered, 64 KiB cap).
var tr = tar.Reader.init(gpa, src);
defer tr.deinit();
while (try tr.next()) |e| {
    // e.path, e.kind (.file/.dir/.symlink/.hardlink/.other), e.mode,
    // e.uid, e.gid, e.mtime, e.size, e.link_target
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try tr.read(&buf); // stream content; 0 = entry done
        if (n == 0) break;
    }
    // unread content is auto-skipped by the following next()
}

// gzip packer (portable): entries -> gzip-compressed tar, streaming.
try tar.packTarGz(gpa, dst, &.{
    .{ .entry = .{ .path = "data/report.csv", .mode = 0o640 }, .content = csv },
});

// Filesystem packer (Linux): walk roots, real uid/gid/mtime via statx.
const stats = try tar.packDir(io, gpa, &.{"/etc/config"}, dst);
// stats: .files/.dirs/.symlinks/.bytes; skips unreadable entries best-effort
```

## Format support (as implemented)

- **Read** (covers busybox + GNU tar): regular files ('0'/NUL/'7'), dirs
  ('5'), symlinks ('2'), hard links ('1'), GNU long-name ('L') / long-link
  ('K') records, the ustar `prefix` field (only under the POSIX
  `ustar\0` magic — GNU reuses those bytes), octal and GNU/star base-256
  size fields. pax ('x'/'g') payloads are skipped, never fatal; other
  typeflags surface as `.other` with the raw flag in `Entry.typeflag`.
- **Write:** ustar blocks + GNU 'L'/'K' records for >100-byte paths/link
  targets, correct checksum, 512-byte blocking, two zero trailer blocks;
  base-256 size field for files ≥ 8 GiB; negative mtimes clamp to 0.

## Design notes

- **Headers are the security boundary.** Every header is checksum-verified
  (unsigned sum per the spec; the signed-sum variant of ancient tars is also
  accepted) and bounds-checked; a truncated stream, short header, garbage
  block or oversized 'L'/'K' payload yields `error.TruncatedArchive` /
  `error.BadHeader` — never a panic or over-read. Numeric fields themselves
  are parsed leniently (garbage → 0, busybox pads oddly); the checksum
  validates the block as a whole.
- **Streaming/bounded memory.** Content is never buffered — `read()` streams
  it; only path/link-target strings are allocated (64 KiB cap, allocator
  explicit). `packTarGz`/`packDir` allocate one flate window.
- **Hardening choices** (wire format untouched): every header is
  checksum-verified; the ustar `prefix` is honored only under the POSIX magic
  (never under GNU magic, where those bytes mean atime/ctime); hard links
  ('1') are modeled rather than skipped; base-256 size emit for ≥ 8 GiB files;
  `packDir` zero-fills a file that turns unreadable after its header was
  written (so a header is never emitted with no content, which would desync
  the archive) and writes to a caller-supplied `*std.Io.Writer` rather than a
  path.
- **Verification:** golden header bytes captured from GNU tar 1.35 are pinned
  in a test (read side) and field-compared against our emit (write side);
  write→read round-trips assert uid/gid/mtime/mode/size/path/link_target all
  survive (incl. 'L'/'K' long names); gzip round-trip via
  `std.compress.flate`; malformed-input tests (truncated header/content, bad
  checksum, hostile 'L' size, empty archive); a live cross-check writes an
  archive that system GNU `tar` must list (`tvf`, numeric ids + sizes) and
  extract (`xf`), and reads a GNU-tar-produced archive back (skips cleanly
  when no `tar` on PATH); `packDir` round-trips real statx attrs on Linux.
