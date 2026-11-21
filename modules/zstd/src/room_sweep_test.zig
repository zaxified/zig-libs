// SPDX-License-Identifier: MIT
//! Every destination capacity, against libzstd 1.5.7: the block API
//! (`compressBlockOnly`, libzstd's `ZSTD_compressBlock`), the buffer-less
//! API (`begin` / `compressContinue` / `compressEnd`) and
//! `compressSequences`. `room_test.zig` pins the least room of one-shot
//! frames; the bound checks here sit where a one-shot frame never runs
//! short (the minimum block size, the sequences header, the room for the
//! last empty block, a block start with less than a block header and one
//! byte left, the frame header of the sequence API), and a one-byte shift
//! of any of them changes some capacity's answer.
//!
//! Each `room_sweep_goldens` row is a run of `tools/zroom.c` over capacities
//! 0..`maxcap`: one line per capacity, `<cap> ok <hex of the output>` or
//! `<cap> err dstSize_tooSmall` (`tools/gen-room-sweep-goldens.sh`). The
//! test writes the same lines from this module and compares their SHA-256.
//! One divergence is by design: below the largest frame header (18 bytes)
//! libzstd's `ZSTD_compressSequences` does not check the frame header's
//! error and goes on at a wild position, so the recipe does not call it
//! there (`<cap> below-header`), and this module must refuse the room
//! (`error.DstSizeTooSmall`).
//!
//! To see where a row differs: `zroom <args>` against the lines this test
//! prints for that row with `ZSTD_ROOM_SWEEP_DUMP=1`.

const std = @import("std");
const zstd = @import("root.zig");
const goldens = @import("testdata/room_sweep_goldens.zig");

const gpa = std.testing.allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

const text = "the quick brown fox jumps over the lazy dog; ";

/// `zroom.c`'s `make`.
fn make(buf: []u8, kind: u8) void {
    var x: u32 = 2463534242 +% @as(u32, @truncate(buf.len));
    for (buf, 0..) |*b, i| b.* = switch (kind) {
        'z' => 0,
        't' => text[(7 * i + (i >> 3)) % 44],
        'r' => blk: {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            break :blk @truncate(x);
        },
        else => unreachable,
    };
}

const Transcript = struct {
    h: Sha256 = .init(.{}),
    dump: bool,

    fn put(t: *Transcript, s: []const u8) void {
        t.h.update(s);
        if (t.dump) std.debug.print("{s}", .{s});
    }
    fn hex(t: *Transcript, bytes: []const u8) void {
        const digits = "0123456789abcdef";
        var buf: [256]u8 = undefined;
        var n: usize = 0;
        for (bytes) |b| {
            buf[n] = digits[b >> 4];
            buf[n + 1] = digits[b & 15];
            n += 2;
            if (n == buf.len) {
                t.put(&buf);
                n = 0;
            }
        }
        t.put(buf[0..n]);
    }
    fn cap(t: *Transcript, c: usize) void {
        var buf: [24]u8 = undefined;
        t.put(std.fmt.bufPrint(&buf, "{d} ", .{c}) catch unreachable);
    }
    fn err(t: *Transcript, c: usize, e: anyerror) void {
        t.cap(c);
        if (e == error.DstSizeTooSmall) t.put("err dstSize_tooSmall\n") else {
            t.put("err zig ");
            t.put(@errorName(e));
            t.put("\n");
        }
    }
};

fn run(row: goldens.Golden, t: *Transcript) !void {
    var c: zstd.Compressor = .init(gpa);
    defer c.deinit();
    const dst = try gpa.alloc(u8, row.maxcap + 1);
    defer gpa.free(dst);
    switch (row.mode) {
        .block => {
            const src = try gpa.alloc(u8, row.len);
            defer gpa.free(src);
            make(src, row.kind);
            for (0..row.maxcap + 1) |cap| {
                try c.ctx.beginUsingDict(&.{}, row.level);
                const n = c.ctx.compressBlockOnly(dst[0..cap], src) catch |e| {
                    t.err(cap, e);
                    continue;
                };
                t.cap(cap);
                t.put("ok ");
                t.hex(dst[0..n]);
                t.put("\n");
            }
        },
        .bufferless => {
            const src = try gpa.alloc(u8, row.len);
            defer gpa.free(src);
            make(src, row.kind);
            const half = if (row.split) row.len / 2 else 0;
            const head = try gpa.alloc(u8, zstd.compressBound(row.len) + 64);
            defer gpa.free(head);
            for (0..row.maxcap + 1) |cap| {
                try c.begin(.{ .level = .{ .level = row.level } });
                var h: usize = 0;
                if (row.split) h = c.compressContinue(head, src[0..half]) catch |e| {
                    t.err(cap, e);
                    continue;
                };
                const n = c.compressEnd(dst[0..cap], src[half..]) catch |e| {
                    t.err(cap, e);
                    continue;
                };
                t.cap(cap);
                t.put("ok ");
                t.hex(head[0..h]);
                t.put(" ");
                t.hex(dst[0..n]);
                t.put("\n");
            }
        },
        .seq => {
            const len = if (row.shape == 'l') row.k else 4 * row.k + 4;
            const src = try gpa.alloc(u8, len);
            defer gpa.free(src);
            const seqs = try gpa.alloc(zstd.Sequence, row.k + 2);
            defer gpa.free(seqs);
            var ns: usize = 0;
            if (row.shape == 'l') {
                make(src, 't');
                seqs[0] = .{ .offset = 0, .lit_length = @intCast(len), .match_length = 0 };
                ns = 1;
            } else {
                for (src, 0..) |*b, i| b.* = "abcd"[i % 4];
                for (seqs[0..row.k], 0..) |*s, i| s.* = .{ .offset = 4, .lit_length = if (i == 0) 4 else 0, .match_length = 4 };
                seqs[row.k] = .{ .offset = 0, .lit_length = if (row.k == 0) 4 else 0, .match_length = 0 };
                ns = row.k + 1;
            }
            const opts: zstd.Options = .{ .level = row.level, .checksum = row.checksum, .advanced = .{ .block_delimiters = .explicit } };
            for (0..row.maxcap + 1) |cap| {
                const r = c.compressSequences(dst[0..cap], seqs[0..ns], src, opts);
                if (cap < @import("decompress.zig").frame_header_size_max) {
                    // libzstd is not called here (see the top of this file)
                    try std.testing.expectError(error.DstSizeTooSmall, r);
                    t.cap(cap);
                    t.put("below-header\n");
                    continue;
                }
                const n = r catch |e| {
                    t.err(cap, e);
                    continue;
                };
                t.cap(cap);
                t.put("ok ");
                t.hex(dst[0..n]);
                t.put("\n");
            }
        },
    }
}

test "every capacity gives libzstd's answer: block, buffer-less and sequence APIs" {
    if (!@import("params.zig").all_strategies) return error.SkipZigTest;
    // `getPosix` does not exist on Windows; the dump knob is a POSIX-host aid.
    const dump = @import("builtin").target.os.tag != .windows and @import("builtin").target.os.tag != .wasi and
        std.testing.environ.getPosix("ZSTD_ROOM_SWEEP_DUMP") != null;
    var bad: usize = 0;
    for (goldens.rows) |row| {
        var t: Transcript = .{ .dump = dump };
        try run(row, &t);
        var d: [32]u8 = undefined;
        t.h.final(&d);
        const got = std.fmt.bytesToHex(d, .lower);
        if (!std.mem.eql(u8, &got, row.sha256)) {
            std.debug.print("room sweep differs: {s}\n", .{row.args});
            bad += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), bad);
}
