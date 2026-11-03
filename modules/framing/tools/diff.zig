// SPDX-License-Identifier: MIT
//! Differential driver against tokio-util 0.7.19 `LengthDelimitedCodec` (MIT),
//! the module's reference (tools/oracle is the Rust side). A PROGRAM, not a test.
//!
//!   zig run -OReleaseSafe --dep framing -Mroot=modules/framing/tools/diff.zig \
//!       -Mframing=modules/framing/src/root.zig -- gen <seed> <cases> <cases.txt> <ours.txt>
//!   modules/framing/tools/oracle/target/release/framing-oracle < cases.txt > theirs.txt
//!   zig run ... -- cmp <cases.txt> <ours.txt> <theirs.txt>
//!
//! `gen` writes random cases (the line format of tools/oracle/src/main.rs) and
//! our answer to each. Encode cases: every fixed width 1..8, both byte orders,
//! `adjustment`, `includes_prefix`, `max_frame`, payload lengths around the
//! width's limit. Decode cases: the same plus `offset` and `skip`, over streams
//! that are well formed, truncated, bit-flipped or random; ours answers through
//! `Decoder` fed in random 1..9-byte pieces, and the driver itself checks that
//! `readFrame` and `readFrameAlloc` give the same frames (else it exits 1).
//! tokio gets the whole stream at once. `cmp` fails on the first difference.
//!
//! Where ours and tokio differ BY DESIGN the case is answered `W` (wildcard,
//! counted and printed): a `skip` below the head with a frame shorter than the
//! head bytes it keeps (ours `BadLength`; tokio hands out a frame and resumes
//! inside the head). `max_frame`: tokio bounds the raw field, ours the length
//! after adjustment; the driver gives tokio `max - adj_t` so both refuse the
//! same frames (cases where that is negative are not generated).
const std = @import("std");
const framing = @import("framing");

const widths = [_]framing.Width{ .u8, .u16, .u24, .u32, .u40, .u48, .u56, .u64 };

fn hexOf(gpa: std.mem.Allocator, out: *std.ArrayList(u8), b: []const u8) !void {
    if (b.len == 0) return out.append(gpa, '-');
    for (b) |x| try out.print(gpa, "{x:0>2}", .{x});
}

const Cfg = struct {
    w: usize, // 1..8
    big: bool,
    incl: bool,
    adj: i32,
    offset: u8 = 0,
    skip: ?u8 = null,
    fn prefix(c: Cfg) framing.Prefix {
        return .{
            .width = widths[c.w - 1],
            .endian = if (c.big) .big else .little,
            .includes_prefix = c.incl,
            .adjustment = c.adj,
            .offset = c.offset,
            .skip = c.skip,
        };
    }
    /// tokio's length_adjustment for the same wire.
    fn adjT(c: Cfg) i64 {
        return @as(i64, c.adj) - if (c.incl) @as(i64, @intCast(c.w)) else 0;
    }
};

fn randCfg(r: std.Random) Cfg {
    return .{
        .w = r.intRangeAtMost(usize, 1, 8),
        .big = r.boolean(),
        .incl = r.boolean(),
        .adj = switch (r.uintLessThan(u8, 20)) {
            0...5 => 0,
            6...11 => r.intRangeAtMost(i32, -9, 9),
            12...17 => r.intRangeAtMost(i32, -2000, 2000),
            18 => std.math.minInt(i32) + r.intRangeAtMost(i32, 0, 3),
            else => std.math.maxInt(i32) - r.intRangeAtMost(i32, 0, 3),
        },
    };
}

fn encodeCase(gpa: std.mem.Allocator, r: std.Random, cases: *std.ArrayList(u8), ours: *std.ArrayList(u8)) !void {
    const c = randCfg(r);
    const len: usize = switch (r.uintLessThan(u8, 4)) {
        0 => r.uintAtMost(usize, 12),
        1 => (if (c.w == 1) @as(usize, 255) else 40) -| r.uintAtMost(usize, 3) +| r.uintAtMost(usize, 5),
        else => r.uintAtMost(usize, 300),
    };
    var payload: [320]u8 = undefined;
    r.bytes(payload[0..len]);
    const m: u32 = switch (r.uintLessThan(u8, 4)) {
        0 => @intCast(len -| 1),
        1 => @intCast(len),
        2 => @intCast(len + 1),
        else => 400,
    };
    try cases.print(gpa, "E {d} {s} {d} {d} ", .{ c.w, if (c.big) "b" else "l", c.adjT(), m });
    try hexOf(gpa, cases, payload[0..len]);
    try cases.append(gpa, '\n');
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    if (framing.writeFrame(&w.writer, payload[0..len], .{ .max_frame = m, .prefix = c.prefix() })) {
        try hexOf(gpa, ours, w.written());
    } else |_| try ours.append(gpa, 'E');
    try ours.append(gpa, '\n');
}

/// Is the Decoder's refusal at its current position the `n < head - skip` rule
/// (and not an adjustment that takes n below zero, or an oversize frame)?
fn byDesignRefusal(d: *const framing.Decoder, c: Cfg) bool {
    const avail = d.pending.items[d.start..];
    if (avail.len < c.offset + c.w) return false;
    var v: u64 = 0;
    for (0..c.w) |i| {
        const byte = avail[c.offset + (if (c.big) i else c.w - 1 - i)];
        v = (v << 8) | byte;
    }
    const n: i128 = @as(i128, v) + c.adjT();
    const head: i128 = c.offset + c.w;
    return n >= 0 and n < head - c.skip.?;
}

fn decodeCase(gpa: std.mem.Allocator, r: std.Random, cases: *std.ArrayList(u8), ours: *std.ArrayList(u8)) !bool {
    var c = randCfg(r);
    if (r.uintLessThan(u8, 3) == 0) c.offset = r.intRangeAtMost(u8, 1, if (r.boolean()) 6 else 60);
    const head: usize = c.offset + c.w;
    if (r.uintLessThan(u8, 10) < 3) c.skip = r.uintAtMost(u8, @intCast(head));
    var m: u32 = switch (r.uintLessThan(u8, 6)) {
        0 => r.uintAtMost(u32, 70_000),
        1 => r.uintAtMost(u32, 5000),
        else => r.uintAtMost(u32, 400),
    };
    // Room for accepted frames at a large positive adjustment (the payload must be
    // at least the adjustment long for the field to be non-negative).
    if (c.adj > 0 and c.adj < 3000 and r.boolean()) m = @max(m, @as(u32, @intCast(c.adj)) + 20);
    var t = @as(i64, m) - c.adjT();
    // tokio clamps max_frame_length to (2^(8w) - 1 + adjustment) and compares the
    // RAW field with it, so with a negative adjustment it refuses fields ours accepts
    // (their length after adjustment is within max_frame): by design, not compared.
    // Keep the generated max below that clamp so both bound the same frames.
    if (c.adjT() < 0 and c.w < 8) {
        const maxnum: i64 = (@as(i64, 1) << @intCast(8 * c.w)) - 1;
        if (t > maxnum + c.adjT()) {
            t = maxnum + c.adjT();
            if (t + c.adjT() < 0) return false;
            m = @intCast(t + c.adjT());
        }
    }
    if (t < 0) return false;

    // The stream: well-formed frames written by us (random header bytes), then damaged.
    var wr: std.Io.Writer.Allocating = .init(gpa);
    defer wr.deinit();
    var wlimits = framing.Limits{ .max_frame = m, .prefix = c.prefix() };
    wlimits.prefix.skip = null;
    const nframes = r.uintAtMost(usize, 4);
    for (0..nframes) |_| {
        var hdr: [64]u8 = undefined;
        r.bytes(&hdr);
        var pl: [3100]u8 = undefined;
        const base: usize = if (c.adj > 0 and c.adj < 3000 and r.uintLessThan(u8, 4) != 0) @intCast(c.adj) else 0;
        const len = @min(base + r.uintAtMost(usize, @min(m, 40)), pl.len);
        r.bytes(pl[0..len]);
        framing.writeFrameWithHeader(&wr.writer, hdr[0..c.offset], pl[0..len], wlimits) catch {};
    }
    const owned = try gpa.dupe(u8, wr.written());
    defer gpa.free(owned);
    var stream: []u8 = owned;
    switch (r.uintLessThan(u8, 6)) {
        0, 1 => if (stream.len > 0) {
            stream = stream[0..r.uintAtMost(usize, stream.len)];
        },
        2 => if (stream.len > 0) {
            const flips = r.intRangeAtMost(usize, 1, 3);
            for (0..flips) |_| stream[r.uintLessThan(usize, stream.len)] ^= @as(u8, 1) << r.int(u3);
        },
        3 => {
            stream = stream[0..0];
        },
        else => {},
    }
    var rnd: [64]u8 = undefined;
    if (r.uintLessThan(u8, 8) == 0) {
        const n = r.uintAtMost(usize, rnd.len);
        r.bytes(rnd[0..n]);
        stream = rnd[0..n];
    }

    try cases.print(gpa, "D {d} {s} {d} {d} {d} {d} ", .{ c.w, if (c.big) "b" else "l", c.offset, c.adjT(), c.skip orelse head, t });
    try hexOf(gpa, cases, stream);
    try cases.append(gpa, '\n');

    const limits = framing.Limits{ .max_frame = m, .prefix = c.prefix() };
    // Ours: the Decoder, fed in random pieces.
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    var d: framing.Decoder = .init(limits);
    defer d.deinit(gpa);
    var frames: std.ArrayList([]u8) = .empty;
    defer {
        for (frames.items) |f| gpa.free(f);
        frames.deinit(gpa);
    }
    var pos: usize = 0;
    var terminal: u8 = 'N';
    feed: while (true) {
        const n = @min(stream.len - pos, r.intRangeAtMost(usize, 1, 9));
        try d.feed(gpa, stream[pos..][0..n]);
        pos += n;
        while (true) {
            const f = d.next() catch {
                terminal = 'E';
                break :feed;
            } orelse break;
            try frames.append(gpa, try gpa.dupe(u8, f));
        }
        if (pos == stream.len) break;
    }
    // The blocking readers must agree frame for frame.
    var rd: std.Io.Reader = .fixed(stream);
    var rd2: std.Io.Reader = .fixed(stream);
    const buf = try gpa.alloc(u8, 1 << 17);
    defer gpa.free(buf);
    var rterm: u8 = 'N';
    var i: usize = 0;
    while (true) : (i += 1) {
        const got = framing.readFrame(&rd, buf, limits) catch |e| {
            rterm = if (e == error.EndOfStream) 'N' else 'E';
            break;
        };
        const got2 = try framing.readFrameAlloc(&rd2, gpa, limits);
        defer gpa.free(got2);
        if (i >= frames.items.len or !std.mem.eql(u8, got, frames.items[i]) or !std.mem.eql(u8, got, got2)) {
            std.debug.print("MISMATCH Decoder vs readFrame at frame {d}\n", .{i});
            return error.Mismatch;
        }
    }
    if (rterm != terminal or i != frames.items.len) {
        std.debug.print("MISMATCH Decoder vs readFrame: terminal {c}/{c}, frames {d}/{d}\n", .{ terminal, rterm, frames.items.len, i });
        return error.Mismatch;
    }
    for (frames.items) |f| {
        try line.appendSlice(gpa, "F:");
        try hexOf(gpa, &line, f);
        try line.append(gpa, ' ');
    }
    // `W` = the rest is by design, not compared: only when the refusal is the
    // `n < head - skip` rule (tokio hands out a frame and resumes inside the head).
    // The frames before it, and every other refusal (n < 0, over max_frame), ARE compared.
    if (terminal == 'E' and c.skip != null and c.skip.? < head and byDesignRefusal(&d, c)) {
        try line.append(gpa, 'W');
    } else try line.append(gpa, terminal);
    try ours.appendSlice(gpa, line.items);
    try ours.append(gpa, '\n');
    return true;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const cwd = std.Io.Dir.cwd();
    if (args.len == 6 and std.mem.eql(u8, args[1], "gen")) {
        var prng = std.Random.DefaultPrng.init(try std.fmt.parseInt(u64, args[2], 0));
        const r = prng.random();
        const n = try std.fmt.parseInt(usize, args[3], 10);
        var cases: std.ArrayList(u8) = .empty;
        defer cases.deinit(gpa);
        var ours: std.ArrayList(u8) = .empty;
        defer ours.deinit(gpa);
        var made: usize = 0;
        while (made < n) {
            if (made % 2 == 0) {
                try encodeCase(gpa, r, &cases, &ours);
                made += 1;
            } else if (try decodeCase(gpa, r, &cases, &ours)) made += 1;
        }
        try cwd.writeFile(io, .{ .sub_path = args[4], .data = cases.items });
        try cwd.writeFile(io, .{ .sub_path = args[5], .data = ours.items });
        return 0;
    }
    if (args.len == 5 and std.mem.eql(u8, args[1], "cmp")) {
        const cases = try cwd.readFileAlloc(io, args[2], gpa, .limited(1 << 28));
        defer gpa.free(cases);
        const ours = try cwd.readFileAlloc(io, args[3], gpa, .limited(1 << 28));
        defer gpa.free(ours);
        const theirs = try cwd.readFileAlloc(io, args[4], gpa, .limited(1 << 28));
        defer gpa.free(theirs);
        var ci = std.mem.splitScalar(u8, cases, '\n');
        var oi = std.mem.splitScalar(u8, ours, '\n');
        var ti = std.mem.splitScalar(u8, theirs, '\n');
        var total: usize = 0;
        var wild: usize = 0;
        var refused: usize = 0;
        var enc_ok: usize = 0;
        var enc_err: usize = 0;
        var dec_frames: usize = 0;
        var dec_e: usize = 0;
        var dec_n: usize = 0;
        while (ci.next()) |cl| {
            const ol = oi.next() orelse "";
            const tl = ti.next() orelse "";
            if (cl.len == 0 and ol.len == 0 and tl.len == 0) break;
            total += 1;
            if (std.mem.eql(u8, tl, "R")) {
                refused += 1; // the oracle declined (declared length past its 16 MiB bound): not agreement
                continue;
            }
            if (ol[ol.len - 1] == 'W') {
                // Frames before the by-design refusal must be the same; what follows is not compared.
                if (!std.mem.startsWith(u8, tl, ol[0 .. ol.len - 1])) {
                    std.debug.print("DIFFERENT at case {d} (before a by-design refusal)\n  case:   {s}\n  ours:   {s}\n  tokio:  {s}\n", .{ total, cl, ol, tl });
                    return 1;
                }
                wild += 1;
                continue;
            }
            if (!std.mem.eql(u8, ol, tl)) {
                std.debug.print("DIFFERENT at case {d}\n  case:   {s}\n  ours:   {s}\n  tokio:  {s}\n", .{ total, cl, ol, tl });
                return 1;
            }
            if (cl[0] == 'E') {
                if (ol[0] == 'E') enc_err += 1 else enc_ok += 1;
            } else {
                dec_frames += std.mem.count(u8, ol, "F:");
                if (ol[ol.len - 1] == 'E') dec_e += 1 else dec_n += 1;
            }
        }
        std.debug.print("{d} cases identical ({d} wildcard: by design; {d} refused by the oracle, NOT compared). encode ok/refused {d}/{d}; decode frames {d}, ending in error/need-more {d}/{d}\n", .{ total - wild - refused, wild, refused, enc_ok, enc_err, dec_frames, dec_e, dec_n });
        return 0;
    }
    std.debug.print("usage: diff gen <seed> <cases> <cases.txt> <ours.txt> | diff cmp <cases.txt> <ours.txt> <theirs.txt>\n", .{});
    return 2;
}
