// SPDX-License-Identifier: MIT

//! pax extended headers: external anchors for the READ direction, hand-computed
//! bytes and round trips for the WRITE direction.
//!
//! READ anchors (`testdata/read_pax_*.tar`, produced 2026-09-30 by real tools,
//! never by this module; each is < 10 KiB — GNU tar with `-b 1`, Python with
//! `tarfile.RECORDSIZE = 512`, so there is no 10240-byte record padding):
//!
//!   # GNU tar 1.35, a file with a nanosecond mtime and ids over the ustar range
//!   printf 'pax gnu content\n' > f.txt; chmod 644 f.txt
//!   touch -d '2024-09-30 12:40:07.123456789' f.txt
//!   tar --format=pax -b 1 --numeric-owner --owner=3000000 --group=4000001 \
//!       -cf read_pax_gnu_nsec_uid.tar f.txt
//!   $ tar -tvv --full-time --numeric-owner -f read_pax_gnu_nsec_uid.tar
//!   -rw-r--r-- 3000000/4000001  16 2024-09-30 14:40:07.123456789 f.txt   (TZ +0200)
//!   The 'x' payload: `uid=3000000`, `gid=4000001`, `mtime=1727700007.123456789`,
//!   `atime=1727700007.123456789`, `ctime=1790745735.082019227` (the last two are
//!   parsed past); the ustar uid/gid fields hold 0.
//!
//!   # GNU tar 1.35, a 130-byte path and a negative fractional mtime
//!   touch -d '1960-01-01 00:00:00.5 UTC' <130-byte path>
//!   tar --format=pax -b 1 --pax-option=delete=atime,delete=ctime --numeric-owner \
//!       --owner=7 --group=8 -cf read_pax_gnu_neg_longpath.tar <130-byte path>
//!   The 'x' payload: `path=<130 bytes>`, `mtime=-315619199.5` (the ustar name
//!   is truncated to 100 bytes, its mtime field 0). GNU tar's own `-tvv` prints
//!   the time of this entry off by one second, so the anchor is the record.
//!
//!   # Python 3.14 tarfile, PAX_FORMAT
//!   see the script below; `tarfile.open('read_pax_python.tar').getmembers()`:
//!     'p'*150   uid=5000000 gid=6000000 mtime=1727700007.5 size=11 type=b'0'
//!     'neg.txt' uid=1000    gid=1000    mtime=-1.25        size=4  type=b'0'
//!     'link'    uid=0       gid=0       mtime=1600000000   size=0  type=b'2'
//!               linkname='t'*130
//!   `tar -tvv --full-time --numeric-owner` on it agrees on the first line:
//!   -rw-r--r-- 5000000/6000000  11 2024-09-30 14:40:07.5 ppp…
//!
//!     tarfile.RECORDSIZE = 512
//!     def add(tf, name, data=b'', uid=0, gid=0, mtime=0, mode=0o644, typ=tarfile.REGTYPE, link=''):
//!         ti = tarfile.TarInfo(name); ti.size = len(data); ti.uid = uid; ti.gid = gid
//!         ti.mtime = mtime; ti.mode = mode; ti.type = typ; ti.linkname = link
//!         tf.addfile(ti, io.BytesIO(data) if data else None)
//!     with tarfile.open('read_pax_python.tar', 'w', format=tarfile.PAX_FORMAT) as tf:
//!         add(tf, 'p' * 150, b'python pax\n', uid=5000000, gid=6000000, mtime=1727700007.5)
//!         add(tf, 'neg.txt', b'neg\n', uid=1000, gid=1000, mtime=-1.25)
//!         add(tf, 'link', typ=tarfile.SYMTYPE, link='t' * 130, mode=0o777, mtime=1600000000)
//!
//! Python reports a float mtime; this module reports floor seconds plus
//! nanoseconds, so -1.25 is (-2, 750_000_000).
//!
//! WRITE direction. The exact pax bytes below are computed by hand from the
//! POSIX record form. The cross-check against real tools needs an archive this
//! module wrote; see README.md ("pax writing: cross-check") for the commands.

const std = @import("std");
const testing = std.testing;
const tar = @import("root.zig");
const Writer = tar.Writer;
const Reader = tar.Reader;
const Entry = tar.Entry;
const Kind = tar.Kind;
const block_size = tar.block_size;

const fx_gnu_nsec_uid: []const u8 = @embedFile("testdata/read_pax_gnu_nsec_uid.tar");
const fx_gnu_neg_longpath: []const u8 = @embedFile("testdata/read_pax_gnu_neg_longpath.tar");
const fx_python: []const u8 = @embedFile("testdata/read_pax_python.tar");

fn expectContent(tr: *Reader, want: []const u8) !void {
    var buf: [64]u8 = undefined;
    const n = try tr.read(&buf);
    try testing.expectEqualStrings(want, buf[0..n]);
    try testing.expectEqual(@as(usize, 0), try tr.read(&buf));
}

// ── READ anchors ────────────────────────────────────────────────────────────

test "anchor (GNU tar --format=pax): nanosecond mtime and uid/gid over the ustar range" {
    try testing.expect(fx_gnu_nsec_uid.len < 10 * 1024);
    var src: std.Io.Reader = .fixed(fx_gnu_nsec_uid);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings("f.txt", e.path);
    try testing.expectEqual(Kind.file, e.kind);
    try testing.expectEqual(@as(u32, 0o644), e.mode);
    try testing.expectEqual(@as(u32, 3_000_000), e.uid);
    try testing.expectEqual(@as(u32, 4_000_001), e.gid);
    try testing.expectEqual(@as(i64, 1_727_700_007), e.mtime);
    try testing.expectEqual(@as(u32, 123_456_789), e.mtime_nsec);
    try testing.expectEqual(@as(u64, 16), e.size);
    try expectContent(&tr, "pax gnu content\n");
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "anchor (GNU tar --format=pax): 130-byte path and a negative fractional mtime" {
    try testing.expect(fx_gnu_neg_longpath.len < 10 * 1024);
    var src: std.Io.Reader = .fixed(fx_gnu_neg_longpath);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings("d" ** 60 ++ "/" ++ "e" ** 60 ++ "-file.txt", e.path);
    try testing.expectEqual(@as(u32, 0o600), e.mode);
    try testing.expectEqual(@as(u32, 7), e.uid);
    try testing.expectEqual(@as(u32, 8), e.gid);
    // mtime=-315619199.5 -> floor -315619200 s + 0.5 s
    try testing.expectEqual(@as(i64, -315_619_200), e.mtime);
    try testing.expectEqual(@as(u32, 500_000_000), e.mtime_nsec);
    try testing.expectEqual(@as(u64, 4), e.size);
    try expectContent(&tr, "neg\n");
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

test "anchor (Python tarfile PAX_FORMAT): 150-byte path, uid 5000000, mtime 1727700007.5, -1.25, long link" {
    try testing.expect(fx_python.len < 10 * 1024);
    var src: std.Io.Reader = .fixed(fx_python);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();

    const a = (try tr.next()).?;
    try testing.expectEqualStrings("p" ** 150, a.path);
    try testing.expectEqual(@as(u32, 5_000_000), a.uid);
    try testing.expectEqual(@as(u32, 6_000_000), a.gid);
    try testing.expectEqual(@as(i64, 1_727_700_007), a.mtime);
    try testing.expectEqual(@as(u32, 500_000_000), a.mtime_nsec);
    try testing.expectEqual(@as(u64, 11), a.size);
    try expectContent(&tr, "python pax\n");

    const b = (try tr.next()).?;
    try testing.expectEqualStrings("neg.txt", b.path);
    try testing.expectEqual(@as(u32, 1000), b.uid);
    try testing.expectEqual(@as(u32, 1000), b.gid);
    try testing.expectEqual(@as(i64, -2), b.mtime); // -1.25 = -2 + 0.75
    try testing.expectEqual(@as(u32, 750_000_000), b.mtime_nsec);
    try expectContent(&tr, "neg\n");

    const c = (try tr.next()).?;
    try testing.expectEqualStrings("link", c.path);
    try testing.expectEqual(Kind.symlink, c.kind);
    try testing.expectEqualStrings("t" ** 130, c.link_target);
    try testing.expectEqual(@as(u32, 0o777), c.mode);
    try testing.expectEqual(@as(i64, 1_600_000_000), c.mtime);
    try testing.expectEqual(@as(u32, 0), c.mtime_nsec);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

// ── WRITE: exact bytes, computed by hand ────────────────────────────────────

test "pax writer: exact bytes for a path with no prefix split, uid over the ustar range, fractional mtime" {
    var buf: [8 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    const path = "x" ** 120; // one component: cannot split into prefix/name
    try tw.writeEntry(.{
        .path = path,
        .mode = 0o644,
        .uid = 5_000_000, // > 0o7777777
        .gid = 1,
        .mtime = 1_727_700_007,
        .mtime_nsec = 500_000_000,
    }, "hi");
    const out = dst.buffered();
    try testing.expectEqual(@as(usize, 4 * block_size), out.len); // 'x' header, records, ustar header, content

    // Records in key order. Length = digits + 1 + len("key=value\n"):
    //   mtime: len("mtime=1727700007.5\n") = 19, + 2 digits + space = 22
    //   path : len("path=" ++ 120 x ++ "\n") = 126, + 3 digits + space = 130
    //   uid  : len("uid=5000000\n") = 12, + 2 digits + space = 15
    const payload = "22 mtime=1727700007.5\n" ++ "130 path=" ++ path ++ "\n" ++ "15 uid=5000000\n";
    try testing.expectEqual(@as(usize, 167), payload.len);
    const xh = out[0..block_size];
    try testing.expectEqualStrings("././@PaxHeader", std.mem.sliceTo(xh[0..100], 0));
    try testing.expectEqual(@as(u8, 'x'), xh[156]);
    try testing.expectEqualStrings("00000000247\x00", xh[124..136]); // 167 = 0o247
    try testing.expectEqualStrings("ustar\x0000", xh[257..265]);
    try testing.expectEqualSlices(u8, payload, out[block_size..][0..payload.len]);
    for (out[block_size + payload.len .. 2 * block_size]) |b| try testing.expectEqual(@as(u8, 0), b);

    // The ustar block: name truncated to 100 bytes, ids that do not fit are 0,
    // the mtime field holds the whole seconds (1727700007 = 0o14676516047).
    const h = out[2 * block_size ..][0..block_size];
    try testing.expectEqualStrings("x" ** 100, std.mem.sliceTo(h[0..100], 0));
    try testing.expectEqualStrings("0000644\x00", h[100..108]);
    try testing.expectEqualStrings("0000000\x00", h[108..116]); // uid
    try testing.expectEqualStrings("0000001\x00", h[116..124]); // gid
    try testing.expectEqualStrings("00000000002\x00", h[124..136]);
    try testing.expectEqualStrings("14676516047\x00", h[136..148]);
    try testing.expectEqual(@as(u8, '0'), h[156]);

    // And the whole thing reads back through the checksum-verifying Reader
    // (a stream ending on a block boundary is a clean end of archive).
    var src: std.Io.Reader = .fixed(out);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqualStrings(path, e.path);
    try testing.expectEqual(@as(u32, 5_000_000), e.uid);
    try testing.expectEqual(@as(u32, 1), e.gid);
    try testing.expectEqual(@as(i64, 1_727_700_007), e.mtime);
    try testing.expectEqual(@as(u32, 500_000_000), e.mtime_nsec);
    try expectContent(&tr, "hi");
}

test "pax writer: the record length counts itself across a digit boundary (99/1001/1002)" {
    // key `path`: body = value + 6. Value 89 would give 99 (two digits), but a
    // path over 100 bytes starts at 101; the boundary that path can reach is
    // 999 -> 1001: with 989 value bytes the record is 999 long, with 990 the
    // three-digit prefix no longer fits and it is 1001, with 991 it is 1002.
    inline for (.{ .{ 989, "999 path=" }, .{ 990, "1001 path=" }, .{ 991, "1002 path=" } }) |c| {
        var buf: [8 * block_size]u8 = undefined;
        var dst: std.Io.Writer = .fixed(&buf);
        const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
        const path = "y" ** c[0];
        try tw.writeHeader(.{ .path = path, .mode = 0o644 });
        const out = dst.buffered();
        try testing.expect(std.mem.startsWith(u8, out[block_size..], c[1]));
        const len = try std.fmt.parseInt(usize, c[1][0 .. c[1].len - " path=".len], 10);
        const digits = c[1].len - " path=".len;
        try testing.expectEqual(digits + 1 + (4 + 1 + c[0] + 1), len); // digits + space + "path=" + value + "\n"
        try testing.expectEqual(@as(u8, '\n'), out[block_size + len - 1]);
        // The size field of the 'x' header is exactly that one record.
        const size = try std.fmt.parseInt(usize, std.mem.sliceTo(out[124..136], 0), 8);
        try testing.expectEqual(len, size);
    }
}

test "pax writer: a path that splits into prefix/name needs no pax header" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    const dir = "dir/" ** 20 ++ "last"; // 84 bytes
    const path = dir ++ "/" ++ "n" ** 80; // 165 bytes, splits at the '/' before the 80-byte name
    try tw.writeHeader(.{ .path = path, .mode = 0o644 });
    const out = dst.buffered();
    try testing.expectEqual(@as(usize, block_size), out.len); // one block, no 'x'
    try testing.expectEqual(@as(u8, '0'), out[156]);
    try testing.expectEqualStrings("n" ** 80, std.mem.sliceTo(out[0..100], 0));
    try testing.expectEqualStrings(dir, std.mem.sliceTo(out[345..500], 0));

    var src: std.Io.Reader = .fixed(out);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    try testing.expectEqualStrings(path, (try tr.next()).?.path);
}

// ── WRITE: round trips ──────────────────────────────────────────────────────

/// Write `e` (+ `content`) in pax mode, read it back, and hand the entry to
/// `check`; also returns how many 'x' headers were emitted.
fn roundTrip(e: Entry, content: []const u8, comptime check: fn (Entry) anyerror!void) !usize {
    var buf: [16 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    try tw.writeEntry(e, content);
    try tw.finish();
    const out = dst.buffered();
    const has_x: usize = if (out[156] == 'x') 1 else 0;
    var src: std.Io.Reader = .fixed(out);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const got = (try tr.next()).?;
    try check(got);
    if (e.kind == .file) try expectContent(&tr, content);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
    return has_x;
}

test "pax round trip: 150-byte path with no split" {
    const path = "q" ** 150;
    const S = struct {
        fn check(g: Entry) anyerror!void {
            try testing.expectEqualStrings("q" ** 150, g.path);
            try testing.expectEqual(@as(u32, 0o600), g.mode);
            try testing.expectEqual(@as(u64, 3), g.size);
        }
    };
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = path, .mode = 0o600, .mtime = 5 }, "abc", S.check));
}

test "pax round trip: uid and gid over 0o7777777, up to maxInt(u32)" {
    const S = struct {
        fn check(g: Entry) anyerror!void {
            try testing.expectEqual(@as(u32, 4_000_000_000), g.uid);
            try testing.expectEqual(@as(u32, std.math.maxInt(u32)), g.gid);
            try testing.expectEqualStrings("f", g.path);
        }
    };
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .uid = 4_000_000_000, .gid = std.math.maxInt(u32) }, "", S.check));
}

test "pax round trip: fractional mtime" {
    const S = struct {
        fn check(g: Entry) anyerror!void {
            try testing.expectEqual(@as(i64, 1_727_700_007), g.mtime);
            try testing.expectEqual(@as(u32, 123_456_789), g.mtime_nsec);
        }
    };
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .mtime = 1_727_700_007, .mtime_nsec = 123_456_789 }, "", S.check));
}

test "pax round trip: negative mtime, whole and fractional" {
    const Neg = struct {
        fn whole(g: Entry) anyerror!void {
            try testing.expectEqual(@as(i64, -86_400), g.mtime);
            try testing.expectEqual(@as(u32, 0), g.mtime_nsec);
        }
        fn frac(g: Entry) anyerror!void {
            try testing.expectEqual(@as(i64, -2), g.mtime); // -1.25
            try testing.expectEqual(@as(u32, 750_000_000), g.mtime_nsec);
        }
        fn tiny(g: Entry) anyerror!void {
            try testing.expectEqual(@as(i64, -1), g.mtime); // -0.999999999
            try testing.expectEqual(@as(u32, 1), g.mtime_nsec);
        }
        fn min(g: Entry) anyerror!void {
            try testing.expectEqual(@as(i64, std.math.minInt(i64)), g.mtime);
            try testing.expectEqual(@as(u32, 999_999_999), g.mtime_nsec);
        }
    };
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .mtime = -86_400 }, "", Neg.whole));
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .mtime = -2, .mtime_nsec = 750_000_000 }, "", Neg.frac));
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .mtime = -1, .mtime_nsec = 1 }, "", Neg.tiny));
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .mtime = std.math.minInt(i64), .mtime_nsec = 999_999_999 }, "", Neg.min));
}

test "pax round trip: mtime past the 33-bit octal range, exact bytes of the record" {
    const S = struct {
        fn check(g: Entry) anyerror!void {
            try testing.expectEqual(@as(i64, 8_589_934_592), g.mtime); // 2^33
            try testing.expectEqual(@as(u32, 0), g.mtime_nsec);
        }
    };
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "f", .mtime = 8_589_934_592 }, "", S.check));

    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    try tw.writeHeader(.{ .path = "f", .mtime = -1, .mtime_nsec = 500_000_000 });
    const rec = "14 mtime=-0.5\n"; // -1 s + 0.5 s
    try testing.expectEqualSlices(u8, rec, dst.buffered()[block_size..][0..rec.len]);
}

test "pax round trip: long symlink and hard-link targets" {
    const target = "../" ** 50 ++ "t"; // 151 bytes
    const S = struct {
        fn check(g: Entry) anyerror!void {
            try testing.expectEqual(Kind.symlink, g.kind);
            try testing.expectEqualStrings("../" ** 50 ++ "t", g.link_target);
            try testing.expectEqualStrings("l", g.path);
        }
        fn hard(g: Entry) anyerror!void {
            try testing.expectEqual(Kind.hardlink, g.kind);
            try testing.expectEqualStrings("../" ** 50 ++ "t", g.link_target);
        }
    };
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "l", .kind = .symlink, .link_target = target }, "", S.check));
    try testing.expectEqual(@as(usize, 1), try roundTrip(.{ .path = "h", .kind = .hardlink, .link_target = target }, "", S.hard));
}

test "pax round trip: size of 20 GiB + 7 keeps the stream in sync (header only)" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    const big: u64 = 20 * 1024 * 1024 * 1024 + 7;
    try tw.writeHeader(.{ .path = "big.bin", .size = big });
    const out = dst.buffered();
    try testing.expectEqual(@as(u8, 'x'), out[156]);
    // 20 GiB + 7 = 21474836487; the record is 20 bytes long.
    try testing.expect(std.mem.startsWith(u8, out[block_size..], "20 size=21474836487\n"));
    var src: std.Io.Reader = .fixed(out);
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const e = (try tr.next()).?;
    try testing.expectEqual(big, e.size);
}

test "pax round trip: everything at once, then a plain entry that must not inherit any of it" {
    var buf: [16 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    try tw.writeEntry(.{
        .path = "z" ** 130,
        .kind = .symlink,
        .link_target = "w" ** 130,
        .uid = 3_000_000,
        .gid = 4_000_001,
        .mtime = -5,
        .mtime_nsec = 1,
    }, "");
    try tw.writeEntry(.{ .path = "plain", .uid = 1, .gid = 2, .mtime = 9 }, "x");
    try tw.finish();
    var src: std.Io.Reader = .fixed(dst.buffered());
    var tr = Reader.init(testing.allocator, &src);
    defer tr.deinit();
    const a = (try tr.next()).?;
    try testing.expectEqualStrings("z" ** 130, a.path);
    try testing.expectEqualStrings("w" ** 130, a.link_target);
    try testing.expectEqual(@as(u32, 3_000_000), a.uid);
    try testing.expectEqual(@as(u32, 4_000_001), a.gid);
    try testing.expectEqual(@as(i64, -5), a.mtime);
    try testing.expectEqual(@as(u32, 1), a.mtime_nsec);
    const b = (try tr.next()).?;
    try testing.expectEqualStrings("plain", b.path);
    try testing.expectEqualStrings("", b.link_target);
    try testing.expectEqual(@as(u32, 1), b.uid);
    try testing.expectEqual(@as(u32, 2), b.gid);
    try testing.expectEqual(@as(i64, 9), b.mtime);
    try testing.expectEqual(@as(u32, 0), b.mtime_nsec);
    try testing.expectEqual(@as(?Entry, null), try tr.next());
}

// ── the default stays exactly what it was ───────────────────────────────────

test "default (GNU) mode: byte-identical with and without options, no pax header, fraction dropped" {
    const e: Entry = .{ .path = "n" ** 120, .mode = 0o644, .uid = 7, .gid = 8, .mtime = 1_600_000_000, .mtime_nsec = 999 };
    var b1: [8 * block_size]u8 = undefined;
    var d1: std.Io.Writer = .fixed(&b1);
    try Writer.init(&d1).writeEntry(e, "abc");
    var b2: [8 * block_size]u8 = undefined;
    var d2: std.Io.Writer = .fixed(&b2);
    try Writer.initOptions(&d2, .{}).writeEntry(e, "abc");
    try testing.expectEqualSlices(u8, d1.buffered(), d2.buffered());
    try testing.expectEqual(@as(u8, 'L'), d1.buffered()[156]);

    // The fraction is not in the output at all: the same entry without it is identical.
    var b3: [8 * block_size]u8 = undefined;
    var d3: std.Io.Writer = .fixed(&b3);
    var e0 = e;
    e0.mtime_nsec = 0;
    try Writer.init(&d3).writeEntry(e0, "abc");
    try testing.expectEqualSlices(u8, d1.buffered(), d3.buffered());
}

test "writer: mtime_nsec over 999_999_999 is FieldOutOfRange in both modes, and nothing is emitted" {
    inline for (.{ tar.LongNames.gnu, tar.LongNames.pax }) |mode| {
        var buf: [4 * block_size]u8 = undefined;
        var dst: std.Io.Writer = .fixed(&buf);
        const tw = Writer.initOptions(&dst, .{ .long_names = mode });
        try testing.expectError(error.FieldOutOfRange, tw.writeHeader(.{ .path = "f", .mtime_nsec = 1_000_000_000 }));
        try testing.expectEqual(@as(usize, 0), dst.buffered().len);
    }
}

test "pax mode still refuses a mode that does not fit (there is no pax keyword for it)" {
    var buf: [4 * block_size]u8 = undefined;
    var dst: std.Io.Writer = .fixed(&buf);
    const tw = Writer.initOptions(&dst, .{ .long_names = .pax });
    try testing.expectError(error.FieldOutOfRange, tw.writeHeader(.{ .path = "f", .mode = 0o10000000 }));
    try testing.expectEqual(@as(usize, 0), dst.buffered().len);
    // and GNU mode still refuses a negative mtime / big uid, as before
    var d2: std.Io.Writer = .fixed(&buf);
    const gw = Writer.init(&d2);
    try testing.expectError(error.FieldOutOfRange, gw.writeHeader(.{ .path = "f", .mtime = -1 }));
    try testing.expectError(error.FieldOutOfRange, gw.writeHeader(.{ .path = "f", .uid = 0o10000000 }));
}
