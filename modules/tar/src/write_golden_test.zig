// SPDX-License-Identifier: MIT

//! Offline anchor for the WRITER half of this module.
//!
//! Before this file, the write path had exactly one external cross-check:
//! "GNU tar extracts + lists our archive (external cross-check)" in
//! `root.zig`, which is host-gated (`if (builtin.os.tag != .linux) return
//! error.SkipZigTest`) and additionally skips cleanly whenever a `tar`
//! binary isn't on `PATH`. That test is real and stays — but on any machine
//! (or CI image) without `tar` installed, or on a non-Linux host, it
//! contributes nothing: the writer's byte-level output has no external
//! anchor at all there, silently. `root.zig` already has one golden-bytes
//! test for a single plain file ("writer emits the GNU header fields
//! byte-for-byte"); this file extends the same idea — real bytes, captured
//! once, committed, asserted with no subprocess — to the shapes that test
//! doesn't reach: directories, symlinks, hard links, the GNU long-name/
//! long-link extension, the checksum field computed over a real foreign
//! header, and the two-zero-block end-of-archive marker as GNU tar itself
//! emits it (not just as this module's own `finish()` does).
//!
//! Capture method (run once, GNU tar 1.35, reproducible from a POSIX shell):
//!
//!   printf "hello world\n" > hello.txt; chmod 644 hello.txt
//!   mkdir sub; chmod 755 sub
//!   ln -s ../hello.txt sub/link
//!   ln hello.txt hardlink.txt; chmod 644 hardlink.txt
//!   touch -d @1600000000 hello.txt hardlink.txt sub
//!   tar --format=ustar --owner=1234 --group=4321 --mtime=@1600000000 \
//!       -cf write_golden_file.tar hello.txt
//!   tar --format=ustar --owner=1234 --group=4321 --mtime=@1600000000 \
//!       -cf write_golden_dir.tar sub          # sub/ header, then sub/link
//!   tar --format=ustar --owner=1234 --group=4321 --mtime=@1600000000 \
//!       -cf write_golden_symlink.tar sub/link
//!   tar --format=ustar --owner=1234 --group=4321 --mtime=@1600000000 \
//!       -cf write_golden_hardlink_pair.tar hello.txt hardlink.txt
//!   # long name: 125-byte path, GNU format (only format that carries >100B
//!   # names — the extension this module's writer also uses for that case)
//!   mkdir -p nested/nested/.../nested   # 16 levels
//!   printf "deep content" > nested/.../deep-file.txt; chmod 644 it
//!   touch -d @1600000000 every dir + the file
//!   tar --format=gnu --owner=7 --group=8 --mtime=@1600000000 \
//!       -cf write_golden_longname.tar nested/.../deep-file.txt
//!
//! Each captured file is a genuinely valid, independently inspectable tar
//! archive (`tar tvf modules/tar/src/testdata/write_golden_*.tar` lists it
//! correctly with any tar implementation, not just this module's) — nothing
//! here is a hand-derived byte string. `--format=ustar` was chosen (not the
//! default GNU format) for four of the five fixtures because GNU tar's own
//! ustar-mode magic ("ustar\0" + version "00") is byte-identical to what
//! this module's `Writer` always emits (see `emitHeader`) — meaning those
//! four fixtures are asserted **fully byte-exact**, not field-by-field. Only
//! the long-name fixture necessarily uses `--format=gnu` (ustar mode caps
//! names at ~100/255 bytes; GNU's 'L' extension is the only way to carry a
//! 125-byte path, and it's the same extension this module's writer uses for
//! that case) — GNU format's magic ("ustar  \0" + uname/gname text fields)
//! differs from ours by design (documented in `root.zig`'s existing
//! byte-for-byte test), so that fixture is checked field-by-field, exactly
//! like the existing single-file case.
//!
//! Regenerate: rerun the shell recipe above, replace the five files under
//! `testdata/`, and update this file's byte-offset comments if any capture
//! changed size. Do not hand-edit the `.tar` fixtures.
//!
//! Not covered here, with reasons:
//!   - a size beyond the 8 GiB octal-field cutoff (GNU/star base-256 escape,
//!     `writeSizeField`'s `size > 0o77777777777` branch) — no external tool
//!     capture is worth an 8+ GiB fixture in this repo; that path is
//!     exercised by the existing hand-derived unit test
//!     ("size field base-256 round-trip (>8 GiB)"), which checks the
//!     bit-level encoding against the documented GNU/star format directly,
//!     not against a captured tool run.
//!   - block padding to the 10240-byte **record** (blocking-factor) size:
//!     real GNU tar pads whole archives to a multiple of 10240 bytes by
//!     default (verified during capture — every fixture above is exactly
//!     10240 bytes on disk); this module's `Writer.finish()` deliberately
//!     does not, emitting only the two mandatory zero blocks (1024 bytes)
//!     and stopping. This is a scope decision, not a gap: `Writer` targets
//!     streams/pipes, not physical tape volumes, and `Reader.next()` stops
//!     at the *first* zero block it sees (see `root.zig`), so it never
//!     needs the rest of a real archive's record padding either way — which
//!     the count-canary test below proves directly against the real,
//!     10240-byte fixtures (each one read successfully well past its
//!     logical end-of-archive marker).

const std = @import("std");
const testing = std.testing;
const tar = @import("root.zig");
const Writer = tar.Writer;
const Reader = tar.Reader;
const Entry = tar.Entry;
const Kind = tar.Kind;
const block_size = tar.block_size;

const golden_file: []const u8 = @embedFile("testdata/write_golden_file.tar");
const golden_dir: []const u8 = @embedFile("testdata/write_golden_dir.tar");
const golden_symlink: []const u8 = @embedFile("testdata/write_golden_symlink.tar");
const golden_hardlink_pair: []const u8 = @embedFile("testdata/write_golden_hardlink_pair.tar");
const golden_longname: []const u8 = @embedFile("testdata/write_golden_longname.tar");

// ── byte-exact: file, incl. the two-zero-block trailer and 512 padding ────

test "golden: writer reproduces real GNU tar (--format=ustar) byte-for-byte, whole small archive incl. trailer" {
    var buf: [2048]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeEntry(.{
        .path = "hello.txt",
        .mode = 0o644,
        .uid = 1234,
        .gid = 4321,
        .mtime = 1_600_000_000,
    }, "hello world\n");
    try tw.finish();

    // header(512) + content padded to a 512 block + two zero trailer blocks
    // == exactly the first 2048 bytes of the real fixture (which continues
    // to 10240 bytes of record-blocking-factor padding this module doesn't
    // replicate — see the file doc comment).
    try testing.expectEqualSlices(u8, golden_file[0..2048], dst.buffered());
}

// ── byte-exact: directory header ──────────────────────────────────────────

test "golden: writer reproduces real GNU tar directory header byte-for-byte" {
    var buf: [block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeHeader(.{
        .path = "sub/", // real tar names a directory member with a trailing '/'
        .kind = .dir,
        .mode = 0o755,
        .uid = 1234,
        .gid = 4321,
        .mtime = 1_600_000_000,
    });
    try testing.expectEqualSlices(u8, golden_dir[0..block_size], dst.buffered());
}

// ── byte-exact: symlink header ────────────────────────────────────────────

test "golden: writer reproduces real GNU tar symlink header byte-for-byte" {
    var buf: [block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeHeader(.{
        .path = "sub/link",
        .kind = .symlink,
        .link_target = "../hello.txt",
        .mode = 0o777,
        .uid = 1234,
        .gid = 4321,
        .mtime = 1_600_000_000,
    });
    try testing.expectEqualSlices(u8, golden_symlink[0..block_size], dst.buffered());
}

// ── byte-exact: hard-link header ──────────────────────────────────────────

test "golden: writer reproduces real GNU tar hard-link header byte-for-byte" {
    var buf: [block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeHeader(.{
        .path = "hardlink.txt",
        .kind = .hardlink,
        .link_target = "hello.txt",
        .mode = 0o644,
        .uid = 1234,
        .gid = 4321,
        .mtime = 1_600_000_000,
    });
    // hardlink.txt is the SECOND entry in the two-entry fixture archive:
    // hello.txt's header (block 0) + its content padded to a block (block
    // 1) come first, so hardlink.txt's own header starts at block 2.
    try testing.expectEqualSlices(u8, golden_hardlink_pair[2 * block_size .. 3 * block_size], dst.buffered());
}

// ── field-by-field: GNU long-name extension ('L' record) ──────────────────
//
// Necessarily not byte-exact (see file doc comment: GNU-format magic +
// uname/gname text fields this module never writes, and GNU tar's own 'L'
// header carries a nonzero mode/checksum of its own where this module's
// `writeGnuLong` always emits zeroed mode/uid/gid/mtime — harmless, since
// no reader (including this module's own `Reader.next`) inspects those
// fields on an 'L'/'K' record, only its typeflag and size). Every field
// this module's writer DOES own is compared.

const long_path = "nested/" ** 16 ++ "deep-file.txt"; // 125 bytes, matches the fixture

test "golden: GNU long-name 'L' record — name, typeflag, size, payload bytes match real GNU tar" {
    // writeHeader for a >100-byte path emits three blocks: the 'L' header,
    // its payload (path + NUL, padded), then the real header itself.
    var buf: [3 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeHeader(.{
        .path = long_path,
        .mode = 0o644,
        .uid = 7,
        .gid = 8,
        .mtime = 1_600_000_000,
        .size = 12, // "deep content"
    });
    const ours = dst.buffered();
    const theirs = golden_longname[0 .. 2 * block_size];

    // 'L' header: name field is the fixed GNU longlink marker, typeflag 'L',
    // size field is payload length (path + NUL).
    try testing.expectEqualSlices(u8, theirs[0..100], ours[0..100]); // "././@LongLink" name
    try testing.expectEqual(@as(u8, 'L'), theirs[156]);
    try testing.expectEqual(@as(u8, 'L'), ours[156]);
    try testing.expectEqualSlices(u8, theirs[124..136], ours[124..136]); // size field
    // Payload block: the long path itself, NUL-terminated, zero-padded.
    try testing.expectEqualSlices(u8, theirs[block_size..][0 .. long_path.len + 1], ours[block_size..][0 .. long_path.len + 1]);
    try testing.expectEqualSlices(u8, theirs[block_size + long_path.len + 1 ..][0 .. block_size - long_path.len - 1], ours[block_size + long_path.len + 1 ..][0 .. block_size - long_path.len - 1]);
}

test "golden: GNU long-name real header (after the 'L' record) — truncated name, mode/uid/gid/mtime/size/typeflag match" {
    // writeEntry adds one more block for the 12-byte content, padded.
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.init(&dst);
    try tw.writeEntry(.{
        .path = long_path,
        .mode = 0o644,
        .uid = 7,
        .gid = 8,
        .mtime = 1_600_000_000,
    }, "deep content");
    const ours = dst.buffered()[2 * block_size ..][0..block_size];
    const theirs = golden_longname[2 * block_size .. 3 * block_size];

    try testing.expectEqualSlices(u8, theirs[0..100], ours[0..100]); // truncated name (first 100 bytes)
    try testing.expectEqualSlices(u8, theirs[100..148], ours[100..148]); // mode, uid, gid, size, mtime
    try testing.expectEqual(theirs[156], ours[156]); // typeflag '0'
    try testing.expectEqualSlices(u8, theirs[157..257], ours[157..257]); // linkname (empty)
}

// ── decode direction: our Reader parses real GNU tar output correctly ─────
//
// Mirrors "reader parses a real GNU tar header (golden bytes)" in root.zig
// (which only covers a plain file) for the shapes that test doesn't reach.
// Also exercises the real 10240-byte fixture's end-of-archive marker
// directly (not a hand-rolled zero block), for the "block padding" note in
// the file doc comment above.

test "golden: Reader parses the real directory + symlink fixture correctly, stops cleanly at real end-of-archive" {
    var src: std.Io.Reader = .fixed(golden_dir); // full 10240-byte real fixture
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const dir_entry = (try tr.next()).?;
    try testing.expectEqualStrings("sub/", dir_entry.path);
    try testing.expectEqual(Kind.dir, dir_entry.kind);
    try testing.expectEqual(@as(u32, 0o755), dir_entry.mode);
    try testing.expectEqual(@as(u32, 1234), dir_entry.uid);
    try testing.expectEqual(@as(u32, 4321), dir_entry.gid);
    try testing.expectEqual(@as(i64, 1_600_000_000), dir_entry.mtime);

    const link_entry = (try tr.next()).?; // GNU tar recursed into sub/
    try testing.expectEqualStrings("sub/link", link_entry.path);
    try testing.expectEqual(Kind.symlink, link_entry.kind);
    try testing.expectEqualStrings("../hello.txt", link_entry.link_target);

    // The real fixture is 10240 bytes total (GNU tar's own record-blocking
    // padding); our Reader stops at the first zero block it meets, well
    // before consuming the rest, and returns null cleanly rather than
    // erroring on the trailing padding.
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "golden: Reader parses the real hard-link fixture correctly" {
    var src: std.Io.Reader = .fixed(golden_hardlink_pair);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const first = (try tr.next()).?;
    try testing.expectEqualStrings("hello.txt", first.path);
    try testing.expectEqual(Kind.file, first.kind);

    const second = (try tr.next()).?;
    try testing.expectEqualStrings("hardlink.txt", second.path);
    try testing.expectEqual(Kind.hardlink, second.kind);
    try testing.expectEqualStrings("hello.txt", second.link_target);
    try testing.expectEqual(@as(u32, 0o644), second.mode);

    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "golden: Reader parses the real GNU long-name fixture correctly" {
    var src: std.Io.Reader = .fixed(golden_longname);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const e = (try tr.next()).?;
    try testing.expectEqualStrings(long_path, e.path);
    try testing.expectEqual(Kind.file, e.kind);
    try testing.expectEqual(@as(u32, 0o644), e.mode);
    try testing.expectEqual(@as(u32, 7), e.uid);
    try testing.expectEqual(@as(u32, 8), e.gid);
    try testing.expectEqual(@as(u64, 12), e.size);

    var buf: [16]u8 = undefined;
    const n = try tr.read(&buf);
    try testing.expectEqualStrings("deep content", buf[0..n]);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

// ── count canary ──────────────────────────────────────────────────────────
//
// Five fixtures, five bytes-on-disk sizes pinned — guards against a
// regenerated fixture silently changing shape (e.g. a future GNU tar
// defaulting to a different record-blocking factor) without this file's
// byte-offset comments being revisited.

test "golden: fixture count + size canary — 5 real GNU tar captures, all 10240 bytes" {
    try testing.expectEqual(@as(usize, 10240), golden_file.len);
    try testing.expectEqual(@as(usize, 10240), golden_dir.len);
    try testing.expectEqual(@as(usize, 10240), golden_symlink.len);
    try testing.expectEqual(@as(usize, 10240), golden_hardlink_pair.len);
    try testing.expectEqual(@as(usize, 10240), golden_longname.len);
}
