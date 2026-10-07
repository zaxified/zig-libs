// SPDX-License-Identifier: MIT
//! Deterministic-PRNG harness over the composer (with and without merge
//! keys), the emitter and the typed mapping.
//!
//! Each input is a random `Value` — strings full of characters that need
//! quoting or escaping, every number class including subnormals and
//! infinities, collection keys, duplicate keys, a subtree shared to make a
//! DAG — then emitted. Oracles:
//!
//!   - the emitted text composes back to an equal `Value` (NaN equal to NaN);
//!   - the same text, damaged with aim at YAML's syntax (indicators, quotes,
//!     escapes, indentation, anchors, merge keys) and composed under random
//!     options, either fails with a typed error or composes to a value that
//!     is a fixed point of emit → compose;
//!   - the typed mapping, run on the damaged text, never crashes or leaks;
//!   - no crash, no hang, no leak (the driver's DebugAllocator).
//!
//! Driver: `YAML_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver).
//! 300 seeds also run in every ordinary test run.

const std = @import("std");
const testing = std.testing;
const yaml = @import("root.zig");
const Value = yaml.Value;
const Pair = yaml.Pair;
const fuzz_driver = @import("testkit").fuzz.driver;
const hit = fuzz_driver.hit;

const pieces = [_][]const u8{ "a", " ", "yes", "1", ".5", ":", "#", "-", "\"", "\\", "\n", "\t", "'", "&x", "*y", "<<", "\u{e9}", "\u{85}", "\u{2028}", "\u{feff}", "\x00", "\x7f", "[", "}", "," };

fn genString(comptime S: type, src: *S, a: std.mem.Allocator) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| try out.appendSlice(a, pieces[src.index(pieces.len)]);
    return out.items;
}

fn genValue(comptime S: type, src: *S, a: std.mem.Allocator, depth: u8, shared: *?Value) anyerror!Value {
    const top: u8 = if (depth < 4) 9 else 5;
    return switch (src.valueRangeAtMost(u8, 0, top)) {
        0 => .null,
        1 => .{ .bool = src.value(bool) },
        2 => .{ .int = switch (src.valueRangeAtMost(u8, 0, 2)) {
            0 => src.valueRangeAtMost(i64, -3, 3),
            1 => src.value(i64),
            else => std.math.minInt(i64),
        } },
        3 => .{ .float = blk: {
            const f: f64 = @bitCast(src.value(u64));
            break :blk if (std.math.isNan(f)) 0.25 else f;
        } },
        4, 5 => .{ .string = try genString(S, src, a) },
        6 => blk: {
            const items = try a.alloc(Value, src.valueRangeAtMost(u8, 0, 3));
            for (items) |*it| it.* = try genValue(S, src, a, depth + 1, shared);
            break :blk .{ .sequence = items };
        },
        7, 8 => blk: {
            const pairs = try a.alloc(Pair, src.valueRangeAtMost(u8, 0, 3));
            for (pairs) |*p| p.* = .{ .key = try genValue(S, src, a, depth + 2, shared), .value = try genValue(S, src, a, depth + 1, shared) };
            break :blk .{ .mapping = pairs };
        },
        else => blk: {
            // Reuse a subtree: the tree becomes a DAG, as aliases make it.
            if (shared.*) |s| {
                hit("shared");
                break :blk s;
            }
            const v = try genValue(S, src, a, depth + 1, shared);
            shared.* = v;
            break :blk v;
        },
    };
}

/// `valueEql`, but NaN equals NaN (the emitter writes `.nan` and reads it back).
fn eql(x: Value, y: Value) bool {
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .null => true,
        .bool => |b| b == y.bool,
        .int => |i| i == y.int,
        .float => |f| (std.math.isNan(f) and std.math.isNan(y.float)) or f == y.float,
        .string => |s| std.mem.eql(u8, s, y.string),
        .sequence => |s| s.len == y.sequence.len and for (s, y.sequence) |p, q| {
            if (!eql(p, q)) break false;
        } else true,
        .mapping => |m| m.len == y.mapping.len and for (m, y.mapping) |p, q| {
            if (!eql(p.key, q.key) or !eql(p.value, q.value)) break false;
        } else true,
    };
}

fn hotSpots(bytes: []const u8, out: []usize) usize {
    var n: usize = 0;
    for (bytes, 0..) |c, i| switch (c) {
        ':', '-', '"', '\\', '\n', ' ', '&', '*', '[', '{', '?', '#' => {
            if (n == out.len) break;
            out[n] = i;
            n += 1;
        },
        else => {},
    };
    return n;
}

fn damage(comptime S: type, src: *S, base: []const u8, buf: []u8) []const u8 {
    var len = @min(base.len, buf.len);
    @memcpy(buf[0..len], base[0..len]);
    var spots: [1024]usize = undefined;
    const ns = hotSpots(buf[0..len], &spots);
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0, 1 => hit("intact"),
        2 => if (ns > 0) {
            buf[spots[src.index(ns)]] = ":- \"\\\n&*[]{}?#'!|>%@\t"[src.index(21)];
            hit("dmg-syntax");
        },
        3 => if (ns > 0 and len + 12 <= buf.len) { // insert a construct
            const at = spots[src.index(ns)];
            const ins = ([_][]const u8{ "<<: ", "&x ", "*x", "\n  ", "!!merge ", "? ", "- ", "{<<: *x}", "--- ", "\\x41" })[src.index(10)];
            std.mem.copyBackwards(u8, buf[at + ins.len .. len + ins.len], buf[at..len]);
            @memcpy(buf[at..][0..ins.len], ins);
            len += ins.len;
            hit("dmg-insert");
        },
        4 => if (ns > 1) {
            const from = spots[src.index(ns)];
            const to = spots[src.index(ns)];
            const n = @min(@as(usize, src.valueRangeAtMost(u8, 1, 40)), len - from, buf.len - to);
            std.mem.copyForwards(u8, buf[to..][0..n], base[from..][0..n]);
            len = @max(len, to + n);
        },
        5 => len = src.index(len + 1),
        6 => for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
            if (len > 0) buf[src.index(len)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        else => {
            len = src.valueRangeAtMost(u8, 0, 96);
            src.bytes(buf[0..len]);
        },
    }
    return buf[0..len];
}

const Cfg = struct {
    a: ?i64 = null,
    b: ?[]const u8 = null,
    c: []const f64 = &.{},
    d: ?Choice = null,
    const Choice = union(enum) { x, y: bool, z: []const []const u8 };
};

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();
    var shared: ?Value = null;
    const v = try genValue(S, src, aa, 0, &shared);
    const text = try yaml.stringify(gpa, v);
    defer gpa.free(text);

    // 1. The emitter round trip.
    const lax: yaml.ComposeOptions = .{ .reject_duplicate_keys = false };
    const back = yaml.composeAllLeaky(aa, text, lax) catch |e| {
        std.debug.print("emitted text does not compose ({t}):\n{s}\n", .{ e, text });
        return error.EmittedTextRefused;
    };
    if (back.len != 1 or !eql(v, back[0])) {
        std.debug.print("emitted text composes differently:\n{s}\n", .{text});
        return error.EmitterRoundTrip;
    }
    hit("emit-roundtrip");

    // 2. Damaged text through the composer, then a fixed point.
    var buf: [4096]u8 = undefined;
    const input = damage(S, src, text, &buf);
    const opts: yaml.ComposeOptions = .{
        .merge_keys = src.value(bool),
        .reject_duplicate_keys = src.value(bool),
        .max_depth = ([_]usize{ 3, 1024 })[src.index(2)],
    };
    if (yaml.composeAllLeaky(aa, input, opts)) |docs| {
        hit("damaged-composed");
        if (opts.merge_keys and std.mem.indexOf(u8, input, "<<") != null) hit("merge");
        for (docs) |d| {
            const t2 = try yaml.stringify(gpa, d);
            defer gpa.free(t2);
            const again = yaml.composeAllLeaky(aa, t2, lax) catch return error.FixedPointRefused;
            if (again.len != 1 or !eql(d, again[0])) return error.NotAFixedPoint;
        }
    } else |e| switch (e) {
        error.InvalidMerge => hit("merge-refused"),
        error.TooDeep => hit("depth"),
        else => {},
    }

    // 3. The typed mapping on the same bytes.
    if (yaml.typed.parse(Cfg, gpa, input, .{ .compose = opts })) |p| {
        hit("typed-ok");
        p.deinit();
    } else |_| {}
}

test "fuzz driver: YAML_FUZZ" {
    try fuzz_driver.run(harness, .{ .prefix = "YAML_FUZZ", .name = "yaml" });
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
