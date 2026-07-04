# SPEC — `tar`

ustar/GNU **tar** reader + writer that preserves uid/gid/mtime (which `std.tar` drops), plus a
gzip-tar packer. Wave P2 (AXP extraction). `extract · any · both · reentrant` (codec portable; the
filesystem-walking packer is Linux). **Seed: extract from `~/workspace/axp/axp-core/tar.zig`
(writer/packer) + `~/workspace/axp/axp-vault/src/backup.zig` (reader)** — same authors' Apache-2.0
code, relicensed MIT. Deps: **none (std only — `std.compress.flate` for gzip)**. New `build.zig`
entry `.{ .name = "tar" }`.

## Why

`std.tar` is read-oriented and **hides uid/gid/mtime** — the seed hand-rolls a reader to preserve
them, and a writer/packer for backups. One tar impl (reader + writer + gzip) is broadly useful and
absent from std in this shape.

## Scope

1. **Reader (portable):** parse ustar + GNU tar; expose each entry's `{path, kind (file/dir/
   symlink/…), mode, uid, gid, mtime, size, link_target}` and stream its content. Handle **GNU long
   names** (`'L'` path / `'K'` linkname extension records). Bounds-checked header parse — a
   truncated/garbage header returns an error, never panics. Streaming (bounded memory, don't buffer
   whole entries).
2. **Writer (portable):** build ustar/GNU tar from caller-supplied entries (`{path, mode, uid, gid,
   mtime, size, kind, link_target}` + a content reader/bytes). Correct header checksum, `'L'`/`'K'`
   long-name records when a path exceeds the ustar field, proper 512-byte blocking + two zero
   trailer blocks. Round-trips with the reader byte-faithfully.
3. **gzip packer:** `packTarGz` — tar + gzip via `std.compress.flate` (gzip container). Streaming.
4. **Filesystem packer (Linux helper):** a helper that walks a directory and packs it, reading real
   uid/gid/mtime via `statx` (this part is Linux — mark it; the codec above stays portable and is
   what the tests exercise). Port the seed's `statx` numeric-attr path.

## Public API sketch (final = the seed's shape)

```zig
pub const Reader = struct {
    pub fn init(src: *std.Io.Reader) Reader;
    pub fn next(self) !?Entry;      // Entry: path, kind, mode, uid, gid, mtime, size, link_target
    pub fn read(self, buf) !usize;  // stream current entry content
};
pub const Writer = struct {
    pub fn init(dst: *std.Io.Writer) Writer;
    pub fn writeEntry(self, meta: Entry, content: []const u8) !void;   // or a content reader
    pub fn finish(self) !void;      // two zero blocks
};
pub fn packTarGz(...) !void;                 // tar + gzip
pub fn packDir(gpa, dir, dst) !void;         // Linux: walk + statx + pack
```

## Acceptance / verification

- **Offline unit tests (port the seed's + add):** write entries → read back, asserting
  **uid/gid/mtime/mode/size/path/link_target all preserved**; GNU long-name (`'L'`/`'K'`) round-trip
  (path > 100 chars); dir + symlink entries; checksum correctness (golden header bytes); gzip
  round-trip (`packTarGz` → gunzip via `std.compress.flate` → read back); truncated/bad-checksum
  header → error (no panic); empty archive (just the trailer).
- **External cross-check (bash, when `tar` is available — gate/skip if not):** write an archive with
  the `Writer`, extract it with GNU `tar xf` and confirm the files + a `tar tvf` listing show the
  right names/sizes; and read a GNU-`tar`-produced archive with the `Reader`. (If `tar` isn't on
  PATH, rely on the round-trip tests.)
- `zig build test-tar` + `zig build test` (all) green, Debug + ReleaseFast; `zig fmt --check` clean.
  Registered with no deps.

## Notes for the implementer

- Use the **zig skill** for Zig 0.16 (`std.Io.Reader/Writer`, `std.compress.flate` gzip, octal
  field formatting, `statx` via `std.os.linux` for the Linux packer). No libc.
- EXTRACTION: keep the seed's proven header handling (uid/gid/mtime, GNU long names) and tests;
  adapt layout + 0.16 drift. Keep the reader/writer **codec portable** (any) and Linux-gate only the
  `statx` filesystem packer, so the codec tests run everywhere.
- Provenance: README `Provenance:` line = "extracted from axp `axp-core/tar.zig` + `axp-vault/src/
  backup.zig` (same authors, Apache-2.0, relicensed MIT)". `model_after` = "GNU tar / libarchive
  (behavior only)". SPDX MIT header. No NOTICE entry (own code; the format is the POSIX ustar/GNU
  spec).
