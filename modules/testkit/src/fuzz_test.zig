// SPDX-License-Identifier: MIT
//! testkit's own fuzz harnesses: the driver over the module that holds it.
//!
//!     TESTKIT_FUZZ=<runs>[,<first seed>]   (`_ONLY`, `_MS`, `_SHRINK`, … as
//!                                           documented in fuzz_driver.zig)
//!
//! Each harness checks a piece against an independent model written here,
//! not against itself: `hex` against a from-scratch nibble decoder, the
//! golden `diff`/`render`/verdicts against a naive first-difference scan and
//! a string-built rendering, the fault transports against the bytes they were
//! given, and the choice tape against the PRNG it records (a recorded run, a
//! plain run and a replay must draw the same values). Every harness is
//! byte-first (its first draw is one `slice`), so `testing.fuzz` corpus
//! seeds reach it.

const std = @import("std");
const testing = std.testing;
const driver = @import("fuzz_driver.zig");
const hex = @import("hex.zig");
const golden = @import("golden.zig");
const fault = @import("fault.zig");

const Rng = driver.Rng;
const hit = driver.hit;

// ── hex ──────────────────────────────────────────────────────────────────────

fn nibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

const alphabet = "0123456789abcdefABCDEF";
const junk = "gZ \x00-x";

/// Raw bytes to a mostly-hex string: most bytes pick a hex digit, a few a
/// character that is not one.
fn hexish(raw: []u8) void {
    for (raw) |*b| b.* = if (b.* < 232) alphabet[b.* % alphabet.len] else junk[b.* % junk.len];
}

pub fn fuzzHex(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var sbuf: [160]u8 = undefined;
    const s = sbuf[0..src.slice(&sbuf)];
    hexish(s);
    const cap = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, 80)));

    // The model: odd length, then a non-hex character, else the bytes.
    var want: [80]u8 = undefined;
    var bad = false;
    for (0..s.len / 2) |i| {
        const hi = nibble(s[2 * i]);
        const lo = nibble(s[2 * i + 1]);
        if (hi == null or lo == null) {
            bad = true;
            break;
        }
        want[i] = @as(u8, hi.?) << 4 | lo.?;
    }
    const odd = s.len % 2 == 1;

    var out: [80]u8 = undefined;
    const got_into = hex.into(out[0..cap], s);
    if (cap < s.len / 2) {
        hit("into: no space");
        try testing.expectError(error.NoSpaceLeft, got_into);
    } else if (odd) {
        hit("into: odd");
        try testing.expectError(error.InvalidLength, got_into);
    } else if (bad) {
        hit("into: not hex");
        try testing.expectError(error.InvalidCharacter, got_into);
    } else {
        hit("into: decoded");
        try testing.expectEqualSlices(u8, want[0 .. s.len / 2], try got_into);
    }

    if (odd) {
        try testing.expectError(error.InvalidLength, hex.alloc(gpa, s));
    } else if (bad) {
        try testing.expectError(error.InvalidCharacter, hex.alloc(gpa, s));
    } else {
        const got = try hex.alloc(gpa, s);
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, want[0 .. s.len / 2], got);
    }
}

// ── golden ───────────────────────────────────────────────────────────────────

const Mutation = enum { equal, flip, truncate, extend, scatter };

pub fn fuzzGolden(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var ebuf: [300]u8 = undefined;
    const expected = ebuf[0..src.slice(&ebuf)];
    var abuf: [340]u8 = undefined;
    @memcpy(abuf[0..expected.len], expected);
    var alen = expected.len;
    const m = src.value(Mutation);
    switch (m) {
        .equal => {},
        .flip => if (alen > 0) {
            abuf[src.index(alen)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        .truncate => alen = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, alen))),
        .extend => {
            const k = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, 40)));
            src.bytes(abuf[alen..][0..k]);
            alen += k;
        },
        .scatter => for (0..src.valueRangeAtMost(u8, 0, 6)) |_| {
            if (alen == 0) break;
            abuf[src.index(alen)] = src.value(u8);
        },
    }
    const actual = abuf[0..alen];
    switch (m) {
        inline else => |tag| hit(@tagName(tag)),
    }

    // The model: a plain scan.
    const first: ?usize = blk: {
        for (0..@min(expected.len, actual.len)) |i| if (expected[i] != actual[i]) break :blk i;
        break :blk null;
    };
    const equal = expected.len == actual.len and first == null;

    const d = golden.diff(expected, actual);
    if (equal) {
        try testing.expect(d == null);
        try golden.verdict(expected, actual);
    } else {
        try testing.expectError(error.TestExpectedEqual, golden.verdict(expected, actual));
        if (expected.len != actual.len) {
            hit("length mismatch");
            try testing.expectEqual(expected.len, d.?.length.expected);
            try testing.expectEqual(actual.len, d.?.length.actual);
        } else {
            hit("byte mismatch");
            try testing.expectEqual(first.?, d.?.byte);
        }
    }

    // The hex form of the same golden decides the same way.
    const ehex = try gpa.alloc(u8, 2 * expected.len);
    defer gpa.free(ehex);
    for (expected, 0..) |b, i| _ = std.mem.print(ehex[2 * i ..][0..2], "{x:0>2}", .{b}) catch unreachable;
    if (equal) try golden.hexVerdict(ehex, actual) else try testing.expectError(error.TestExpectedEqual, golden.hexVerdict(ehex, actual));

    // render, against a string built the obvious way, at the difference and
    // at an arbitrary offset (possibly past the end), into a buffer that may
    // be too small: the output is then a prefix of the full rendering.
    const ats = [_]usize{ first orelse 0, @as(usize, @intCast(src.valueRangeAtMost(u64, 0, actual.len + 2))) };
    for (ats) |at| {
        var ref: std.ArrayList(u8) = .empty;
        defer ref.deinit(gpa);
        const lo = at -| golden.window;
        const hi = @min(actual.len, at +| golden.window +| 1);
        var i = lo;
        while (i < hi) : (i += 1) {
            if (i == at) try ref.print(gpa, "[{x:0>2}]", .{actual[i]}) else try ref.print(gpa, " {x:0>2} ", .{actual[i]});
        }
        if (hi < actual.len) try ref.appendSlice(gpa, " ...");
        var rbuf: [16 * golden.window + 8]u8 = undefined;
        const size = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, rbuf.len)));
        const got = golden.render(rbuf[0..size], actual, at);
        try testing.expect(got.len <= size);
        if (size == rbuf.len) {
            try testing.expectEqualStrings(ref.items, got);
        } else {
            hit("render truncated");
            try testing.expect(std.mem.startsWith(u8, ref.items, got));
        }
    }
}

// ── fault transports ─────────────────────────────────────────────────────────

pub fn fuzzFault(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var data: [2048]u8 = undefined;
    const input = data[0..src.slice(&data)];
    const plan = fault.FaultPlan.draw(src, input.len);
    if (plan.fail_at != null) hit("fails");

    // Reader: everything up to the failure byte, then the failure.
    var rbuf: [64]u8 = undefined;
    const rlen = @as(usize, @intCast(src.valueRangeAtMost(u64, 1, rbuf.len)));
    var r = fault.ChunkedReader.init(input, plan, rbuf[0..rlen]);
    var got: std.Io.Writer.Allocating = .init(gpa);
    defer got.deinit();
    const res = r.interface.streamRemaining(&got.writer);
    if (plan.fail_at) |f| {
        try testing.expectError(error.ReadFailed, res);
        try testing.expectEqualSlices(u8, input[0..f], got.written());
    } else {
        _ = try res;
        try testing.expectEqualSlices(u8, input, got.written());
    }

    // Writer: the same bytes written in drawn pieces reach the sink in order.
    var out: [2048]u8 = undefined;
    var wbuf: [64]u8 = undefined;
    const wlen = @as(usize, @intCast(src.valueRangeAtMost(u64, 0, wbuf.len)));
    var w = fault.ChunkedWriter.init(&out, plan, wbuf[0..wlen]);
    var pos: usize = 0;
    const wres = blk: {
        while (pos < input.len) {
            const k = @as(usize, @intCast(src.valueRangeAtMost(u64, 1, input.len - pos)));
            if (src.value(bool)) {
                w.interface.writeAll(input[pos..][0..k]) catch |e| break :blk e;
            } else for (input[pos..][0..k]) |b| {
                w.interface.writeByte(b) catch |e| break :blk e;
            }
            pos += k;
        }
        w.interface.flush() catch |e| break :blk e;
    };
    if (plan.fail_at != null and plan.fail_at.? < input.len) {
        hit("writer failed");
        try testing.expectError(error.WriteFailed, wres);
        try testing.expectEqualSlices(u8, input[0..plan.fail_at.?], w.written());
    } else {
        try wres;
        try testing.expectEqualSlices(u8, input, w.written());
    }
}

// ── the choice tape ──────────────────────────────────────────────────────────

const Op = enum { range8, range_signed, range64, range128, boolean, enumv, int16, int128, index, slice, bytes };
const E = enum { a, b, c, d, e };

fn drawOp(r: *Rng, op: Op, arg: u64, buf: []u8) u128 {
    return switch (op) {
        .range8 => r.valueRangeAtMost(u8, @truncate(arg & 0x7f), 200),
        .range_signed => @bitCast(@as(i128, r.valueRangeAtMost(i32, -1000, @as(i32, @intCast(arg % 5000))))),
        .range64 => r.valueRangeAtMost(u64, arg, std.math.maxInt(u64)),
        .range128 => r.valueRangeAtMost(u128, 0, @as(u128, arg) << 64 | arg),
        .boolean => @intFromBool(r.value(bool)),
        .enumv => @backingInt(r.value(E)),
        .int16 => r.value(u16),
        .int128 => r.value(u128),
        .index => r.index(@intCast(arg % 1000 + 1)),
        .slice => blk: {
            const n = r.slice(buf[0 .. arg % buf.len + 1]);
            break :blk std.hash.Wyhash.hash(n, buf[0..n]);
        },
        .bytes => blk: {
            const b = buf[0 .. arg % 50];
            r.bytes(b);
            break :blk std.hash.Wyhash.hash(0, b);
        },
    };
}

pub fn fuzzTape(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    // The program: one byte per op, its argument from the next draws.
    var prog: [64]u8 = undefined;
    const n = src.slice(&prog);
    const seed = src.value(u64);
    const args = try gpa.alloc(u64, n);
    defer gpa.free(args);
    for (args) |*a| a.* = src.value(u64);

    const log = try gpa.alloc(u64, 64 * 260);
    defer gpa.free(log);
    var rec: driver.Tape = .{ .mode = .record, .buf = log };
    var p1 = std.Random.DefaultPrng.init(seed);
    var p2 = std.Random.DefaultPrng.init(seed);
    var a: Rng = .{ .r = p1.random(), .tape = &rec };
    var plain: Rng = .{ .r = p2.random() };
    var seen: [64]u128 = undefined;
    var b1: [200]u8 = undefined;
    var b2: [200]u8 = undefined;
    for (prog[0..n], args, 0..) |o, arg, i| {
        const op: Op = @fromBackingInt(@intCast(o % @typeInfo(Op).@"enum".field_names.len));
        seen[i] = drawOp(&a, op, arg, &b1);
        try testing.expectEqual(drawOp(&plain, op, arg, &b2), seen[i]);
    }
    try testing.expect(!rec.overflow);
    if (n > 0) hit("program");

    var rep: driver.Tape = .{ .mode = .replay, .buf = log[0..rec.len], .len = rec.len };
    var p3 = std.Random.DefaultPrng.init(~seed);
    var r: Rng = .{ .r = p3.random(), .tape = &rep };
    for (prog[0..n], args, 0..) |o, arg, i| {
        const op: Op = @fromBackingInt(@intCast(o % @typeInfo(Op).@"enum".field_names.len));
        try testing.expectEqual(seen[i], drawOp(&r, op, arg, &b1));
    }
    try testing.expectEqual(rec.len, rep.at);
}

// ── the tests: a smoke run here, the verdict under TESTKIT_FUZZ ────────────────

fn smoke(comptime harness: anytype, runs: usize) !void {
    defer driver.resetReach();
    for (0..runs) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        try harness(Rng, &rng, testing.allocator);
    }
}

fn viaSmith(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

test "fuzz smoke: hex, golden, fault transports, choice tape (300 seeds each)" {
    try smoke(fuzzHex, 300);
    try smoke(fuzzGolden, 300);
    try smoke(fuzzFault, 300);
    try smoke(fuzzTape, 300);
}

test "fuzz: hex" {
    try testing.fuzz({}, viaSmith(fuzzHex), .{});
}
test "fuzz: golden" {
    try testing.fuzz({}, viaSmith(fuzzGolden), .{});
}
test "fuzz: fault transports" {
    try testing.fuzz({}, viaSmith(fuzzFault), .{});
}
test "fuzz: choice tape" {
    try testing.fuzz({}, viaSmith(fuzzTape), .{});
}

test "fuzz driver: hex" {
    try driver.run(fuzzHex, .{ .prefix = "TESTKIT_FUZZ", .name = "testkit-hex" });
}
test "fuzz driver: golden" {
    try driver.run(fuzzGolden, .{ .prefix = "TESTKIT_FUZZ", .name = "testkit-golden" });
}
test "fuzz driver: fault transports" {
    try driver.run(fuzzFault, .{ .prefix = "TESTKIT_FUZZ", .name = "testkit-fault" });
}
test "fuzz driver: choice tape" {
    try driver.run(fuzzTape, .{ .prefix = "TESTKIT_FUZZ", .name = "testkit-tape", .scale = 4 });
}
