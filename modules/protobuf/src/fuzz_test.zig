// SPDX-License-Identifier: MIT
//! Deterministic-PRNG corrupt-input harness for the 2026-10-04 decode paths
//! — `oneof` gathering, `map` dedupe, the well-known `Struct`/`Value` tree —
//! alongside the existing shapes (`Wide`, `Repeated`, `Keeps`, `Chain`).
//!
//! Each input is a random message (a `C` with maps and a oneof, or a random
//! `Struct` document), encoded, then damaged with aim at the structure: a
//! tag byte, a length byte, a copied run of a field (which makes duplicate
//! map keys and repeated oneof members), truncation, byte flips, or random
//! bytes. Oracles:
//!
//!   - no crash, no hang, no leak (the driver's DebugAllocator);
//!   - an intact encoding decodes and re-encodes byte for byte;
//!   - every accepted input is a fixed point after one round: encoding the
//!     decoded value, decoding that and encoding again gives the same bytes;
//!   - a decoded map never holds two entries with the same key.
//!
//! Driver: `PROTOBUF_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver).
//! 300 seeds also run in every ordinary test run.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");
const wkt = pb.wkt;
const core = @import("core_test.zig");
const ct = @import("codec_test.zig");
const fuzz_driver = @import("testkit").fuzz.driver;
const hit = fuzz_driver.hit;

const max_input = 4096;

fn genC(comptime S: type, src: *S, a: std.mem.Allocator) !core.C {
    var c: core.C = .{};
    // Keys unique by construction; duplicates come from the damage step.
    const labels = try a.alloc(core.Labels, src.valueRangeAtMost(u8, 0, 4));
    for (labels, 0..) |*e, i| e.* = .{ .key = ([_][]const u8{ "", "a", "bb", "\u{fc}" })[i], .value = src.value(i32) };
    c.labels = labels;
    const names = try a.alloc(core.Names, src.valueRangeAtMost(u8, 0, 3));
    for (names, 0..) |*e, i| e.* = .{ .key = @as(i32, @intCast(i)) * 1000 - 1, .value = if (src.value(bool)) "v" else "" };
    c.names = names;
    const subs = try a.alloc(core.Subs, src.valueRangeAtMost(u8, 0, 3));
    for (subs, 0..) |*e, i| e.* = .{ .key = @as(i64, @intCast(i)) - 1, .value = .{ .x = src.value(i32), .y = src.valueRangeAtMost(i32, -2, 2) } };
    c.subs = subs;
    if (src.value(bool)) c.flags = &.{ .{ .key = false, .value = "" }, .{ .key = true, .value = "\x00" } };
    c.choice = switch (src.valueRangeAtMost(u8, 0, 4)) {
        0 => null,
        1 => .{ .a = src.value(i32) },
        2 => .{ .b = "s" },
        3 => .{ .c = .{ .x = src.valueRangeAtMost(i32, -1, 1) } },
        else => .{ .d = "" },
    };
    c.tail = src.valueRangeAtMost(i32, -1, 1);
    return c;
}

fn genValue(comptime S: type, src: *S, a: std.mem.Allocator, depth: u8) !wkt.Value {
    const top: u8 = if (depth < 3) 6 else 4;
    return .{ .kind = switch (src.valueRangeAtMost(u8, 0, top)) {
        0 => null,
        1 => .{ .null_value = .null_value },
        2 => .{ .number_value = @bitCast(src.value(u64)) },
        3 => .{ .string_value = if (src.value(bool)) "x" else "" },
        4 => .{ .bool_value = src.value(bool) },
        5 => blk: {
            const f = try a.alloc(wkt.Struct.FieldsEntry, src.valueRangeAtMost(u8, 0, 3));
            for (f, 0..) |*e, i| e.* = .{ .key = ([_][]const u8{ "k", "kk", "" })[i], .value = try genValue(S, src, a, depth + 1) };
            break :blk .{ .struct_value = .{ .fields = f } };
        },
        else => blk: {
            const v = try a.alloc(wkt.Value, src.valueRangeAtMost(u8, 0, 3));
            for (v) |*x| x.* = try genValue(S, src, a, depth + 1);
            break :blk .{ .list_value = .{ .values = v } };
        },
    } };
}

/// Offsets of every top-level field's tag, as far as the bytes parse.
fn fieldStarts(bytes: []const u8, out: []usize) usize {
    var cur = pb.wire.Cursor.init(bytes);
    var n: usize = 0;
    while (!cur.atEnd() and n < out.len) {
        const at = cur.pos;
        const t = cur.tag() catch break;
        _ = cur.skipValue(t.wire) catch break;
        out[n] = at;
        n += 1;
    }
    return n;
}

fn damage(comptime S: type, src: *S, base: []const u8, buf: []u8) []const u8 {
    var len = @min(base.len, buf.len);
    @memcpy(buf[0..len], base[0..len]);
    var starts: [256]usize = undefined;
    const ns = fieldStarts(buf[0..len], &starts);
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0, 1 => hit("intact"),
        2 => if (ns > 0) { // a tag byte: another field number or wire type
            const at = starts[src.index(ns)];
            buf[at] = if (src.value(bool)) buf[at] ^ @as(u8, 1) << src.valueRangeAtMost(u3, 0, 7) else src.value(u8);
            hit("dmg-tag");
        },
        3 => if (ns > 0) { // the byte after a tag: a length or a varint
            const at = starts[src.index(ns)] + 1;
            if (at < len) buf[at] = switch (src.valueRangeAtMost(u8, 0, 2)) {
                0 => buf[at] +% 1,
                1 => buf[at] -% 1,
                else => src.value(u8),
            };
            hit("dmg-len");
        },
        4 => if (ns > 0 and len < buf.len) { // append a copy of one whole field
            const i = src.index(ns);
            const end = if (i + 1 < ns) starts[i + 1] else len;
            const n = @min(end - starts[i], buf.len - len);
            @memcpy(buf[len..][0..n], base[starts[i]..][0..n]);
            len += n;
            hit("dmg-dup-field");
        },
        5 => len = src.index(len + 1),
        6 => for (0..src.valueRangeAtMost(u8, 1, 4)) |_| {
            if (len > 0) buf[src.index(len)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        else => {
            len = src.valueRangeAtMost(u8, 0, 96);
            src.bytes(buf[0..len]);
        },
    }
    return buf[0..len];
}

fn mapKeysUnique(entries: anytype) bool {
    for (entries, 0..) |e, i| for (entries[i + 1 ..]) |f| {
        const same = if (@TypeOf(e.key) == []const u8) std.mem.eql(u8, e.key, f.key) else e.key == f.key;
        if (same) return false;
    };
    return true;
}

fn structKeysUnique(s: wkt.Struct) bool {
    if (!mapKeysUnique(s.fields)) return false;
    for (s.fields) |f| if (!valueKeysUnique(f.value)) return false;
    return true;
}

fn valueKeysUnique(v: wkt.Value) bool {
    const k = v.kind orelse return true;
    return switch (k) {
        .struct_value => |s| structKeysUnique(s),
        .list_value => |l| for (l.values) |x| {
            if (!valueKeysUnique(x)) break false;
        } else true,
        else => true,
    };
}

/// Decode, check the invariants, re-encode twice: a fixed point.
fn checkOne(comptime T: type, gpa: std.mem.Allocator, input: []const u8, max_depth: u8, intact: bool) !void {
    var d = pb.decode(T, gpa, input, .{ .max_depth = max_depth }) catch |e| {
        if (e == error.DepthExceeded) hit("depth");
        if (intact and max_depth == 64) return error.IntactInputRefused;
        return;
    };
    defer d.deinit();
    hit("decoded");
    if (T == core.C) {
        if (!mapKeysUnique(d.value.labels) or !mapKeysUnique(d.value.names) or
            !mapKeysUnique(d.value.subs) or !mapKeysUnique(d.value.flags)) return error.DuplicateKeyKept;
        if (d.value.choice != null) hit("oneof");
    }
    if (T == wkt.Struct and !structKeysUnique(d.value)) return error.DuplicateKeyKept;
    const once = try pb.encodeAlloc(gpa, d.value, .{ .max_depth = 255 });
    defer gpa.free(once);
    if (intact and !std.mem.eql(u8, once, input)) return error.IntactRoundTripDiffers;
    if (!intact and once.len != input.len) hit("normalized");
    var d2 = try pb.decode(T, gpa, once, .{ .max_depth = 255 });
    defer d2.deinit();
    const twice = try pb.encodeAlloc(gpa, d2.value, .{ .max_depth = 255 });
    defer gpa.free(twice);
    if (!std.mem.eql(u8, once, twice)) return error.NotAFixedPoint;
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();
    var buf: [max_input]u8 = undefined;
    const max_depth: u8 = ([_]u8{ 2, 3, 64 })[src.index(3)];
    switch (src.valueRangeAtMost(u8, 0, 2)) {
        0 => {
            const c = try genC(S, src, aa);
            const base = try pb.encodeAlloc(aa, c, .{});
            const input = damage(S, src, base, &buf);
            try checkOne(core.C, gpa, input, max_depth, std.mem.eql(u8, input, base));
        },
        1 => {
            const v = try genValue(S, src, aa, 0);
            const s: wkt.Struct = .{ .fields = &.{.{ .key = "root", .value = v }} };
            const base = try pb.encodeAlloc(aa, s, .{});
            const input = damage(S, src, base, &buf);
            try checkOne(wkt.Struct, gpa, input, max_depth, std.mem.eql(u8, input, base));
        },
        else => {
            // The older shapes, from damaged copies of the oracle's own C cases.
            const case = @import("testdata/core_vectors.zig").c_cases[src.index(25)];
            var raw: [256]u8 = undefined;
            const base = std.fmt.hexToBytes(&raw, case.input) catch unreachable;
            const input = damage(S, src, base, &buf);
            try checkOne(ct.Wide, gpa, input, max_depth, false);
            try checkOne(ct.Keeps, gpa, input, max_depth, false);
            try checkOne(core.C, gpa, input, max_depth, false);
        },
    }
}

test "fuzz driver: PROTOBUF_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "PROTOBUF_FUZZ", .name = "protobuf" });
}

test "fuzz harness: 300 seeds in every test run" {
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
    }
}
