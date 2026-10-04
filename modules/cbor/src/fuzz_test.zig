// SPDX-License-Identifier: MIT
//! Deterministic-PRNG corrupt-input harness over every parser in the module:
//! `decode` (lenient, `reject_duplicate_keys`, `deterministic`),
//! `decodePrefix`, `Sequence`, `Reader.skipValue` and `typed.decode`.
//!
//! Each input is a random `Value` tree, encoded (plain or canonical), then
//! damaged with aim at the structure: a head's additional-info bits, a
//! length/argument byte, a copied token range (which makes duplicate keys and
//! wrong counts), truncation, byte flips, or plain random bytes. Oracles:
//!
//!   - no crash, no hang, no leak (the driver's DebugAllocator);
//!   - `Reader.skipValue` reaches the same verdict as `decodePrefix` — same
//!     length on success, same error otherwise;
//!   - an accepted input re-encodes, and `Writer.value` gives `encode`'s bytes;
//!   - `deterministic` accepts an input iff it equals the canonical encoding
//!     of its own value (an equal-key map aside, which is `DuplicateKey`);
//!   - `reject_duplicate_keys` fails iff some map holds two keys that are
//!     equal by `dmEql`, an independent data-model equality written here;
//!   - an intact plain encoding comes back byte for byte.
//!
//! Driver: `CBOR_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there). 300 seeds also run in every
//! ordinary test run.

const std = @import("std");
const testing = std.testing;
const cbor = @import("root.zig");
const Value = cbor.Value;
const MapEntry = cbor.MapEntry;
const fuzz_driver = @import("testkit").fuzz.driver;
const hit = fuzz_driver.hit;

const max_input = 2048;

fn genValue(comptime S: type, src: *S, a: std.mem.Allocator, depth: u32) !Value {
    const top: u8 = if (depth < 5) 12 else 8;
    return switch (src.valueRangeAtMost(u8, 0, top)) {
        0 => .{ .uint = genArg(S, src) },
        1 => .{ .negint = genArg(S, src) },
        2 => blk: {
            const b = try a.alloc(u8, src.valueRangeAtMost(u8, 0, 12));
            src.bytes(b);
            break :blk .{ .bytes = b };
        },
        3 => blk: {
            const alphabet = [_][]const u8{ "a", "b", "\"", "\\", "\n", "\u{fc}", "\u{6c34}", "\u{10151}" };
            var t: std.ArrayList(u8) = .empty;
            for (0..src.valueRangeAtMost(u8, 0, 5)) |_| try t.appendSlice(a, alphabet[src.index(alphabet.len)]);
            break :blk .{ .text = t.items };
        },
        4 => .{ .simple = if (src.value(bool)) src.valueRangeAtMost(u8, 0, 19) else src.valueRangeAtMost(u8, 32, 255) },
        5 => switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => .{ .bool = false },
            1 => .{ .bool = true },
            2 => .null_value,
            else => .undefined_value,
        },
        6 => switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => .{ .f16 = @bitCast(src.value(u16)) },
            1 => .{ .f32 = @bitCast(src.value(u32)) },
            2 => .{ .f64 = @bitCast(src.value(u64)) },
            // A binary64 that a shorter width holds exactly: what float
            // shrinking and the deterministic check are about.
            else => .{ .f64 = @as(f16, @bitCast(src.value(u16))) },
        },
        // Small keys and short texts, so maps get equal keys.
        7 => .{ .uint = src.valueRangeAtMost(u8, 0, 3) },
        8 => .{ .text = ([_][]const u8{ "a", "b", "aa" })[src.index(3)] },
        9 => blk: {
            const items = try a.alloc(Value, src.valueRangeAtMost(u8, 0, 4));
            for (items) |*it| it.* = try genValue(S, src, a, depth + 1);
            break :blk .{ .array = items };
        },
        10, 11 => blk: {
            const entries = try a.alloc(MapEntry, src.valueRangeAtMost(u8, 0, 4));
            for (entries) |*e| e.* = .{ .key = try genValue(S, src, a, depth + 1), .value = try genValue(S, src, a, depth + 1) };
            break :blk .{ .map = entries };
        },
        else => blk: {
            const inner = try a.create(Value);
            inner.* = try genValue(S, src, a, depth + 1);
            break :blk .{ .tag = .{ .number = genArg(S, src), .value = inner } };
        },
    };
}

/// An argument from each of the five head widths.
fn genArg(comptime S: type, src: *S) u64 {
    return switch (src.valueRangeAtMost(u8, 0, 4)) {
        0 => src.valueRangeAtMost(u64, 0, 23),
        1 => src.valueRangeAtMost(u64, 24, 0xff),
        2 => src.valueRangeAtMost(u64, 0x100, 0xffff),
        3 => src.valueRangeAtMost(u64, 0x1_0000, 0xffff_ffff),
        else => src.value(u64),
    };
}

/// Offsets where a token starts in `bytes` (as far as the reader gets).
fn tokenStarts(bytes: []const u8, out: []usize) usize {
    var r: cbor.Reader = .init(bytes);
    var n: usize = 0;
    while (n < out.len) {
        const at = r.pos;
        const t = r.next() catch break;
        if (t == null) break;
        out[n] = at;
        n += 1;
    }
    return n;
}

fn damage(comptime S: type, src: *S, base: []const u8, buf: []u8) []const u8 {
    var len = @min(base.len, buf.len);
    @memcpy(buf[0..len], base[0..len]);
    var starts: [512]usize = undefined;
    const ns = tokenStarts(buf[0..len], &starts);
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0, 1 => hit("intact"),
        2 => if (ns > 0) { // a head's additional-info bits
            const at = starts[src.index(ns)];
            buf[at] = (buf[at] & 0xe0) | src.valueRangeAtMost(u8, 0, 31);
            hit("dmg-info");
        },
        3 => if (ns > 0) { // the byte after a head: an argument / length
            const at = starts[src.index(ns)] + 1;
            if (at < len) buf[at] = switch (src.valueRangeAtMost(u8, 0, 3)) {
                0 => buf[at] +% 1,
                1 => buf[at] -% 1,
                2 => 0xff,
                else => src.value(u8),
            };
            hit("dmg-arg");
        },
        4 => if (ns > 1) { // copy a token range over another place
            const from = starts[src.index(ns)];
            const to = starts[src.index(ns)];
            const n = @min(@as(usize, src.valueRangeAtMost(u8, 1, 24)), len - from, buf.len - to);
            std.mem.copyForwards(u8, buf[to..][0..n], base[from..][0..n]);
            len = @max(len, to + n);
            hit("dmg-copy");
        },
        5 => len = src.index(len + 1), // truncated
        6 => for (0..src.valueRangeAtMost(u8, 1, 4)) |_| {
            if (len > 0) buf[src.index(len)] ^= src.valueRangeAtMost(u8, 1, 255);
        },
        else => {
            len = src.valueRangeAtMost(u8, 0, 64);
            src.bytes(buf[0..len]);
        },
    }
    return buf[0..len];
}

/// CBOR data-model equality (RFC 8949 §2, §5.6), written independently of
/// the encoder: integers by value and sign, floats by value across widths
/// (bits of the binary64 value; every NaN equal), strings by content,
/// arrays in order, maps as sets of pairs, tags by number and content.
fn dmEql(x: Value, y: Value) bool {
    const fx = asF64(x);
    const fy = asF64(y);
    if (fx != null or fy != null) {
        if (fx == null or fy == null) return false;
        if (std.math.isNan(fx.?) and std.math.isNan(fy.?)) return true;
        return @as(u64, @bitCast(fx.?)) == @as(u64, @bitCast(fy.?));
    }
    if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
    return switch (x) {
        .uint => |u| u == y.uint,
        .negint => |n| n == y.negint,
        .bytes => |b| std.mem.eql(u8, b, y.bytes),
        .text => |t| std.mem.eql(u8, t, y.text),
        .array => |items| items.len == y.array.len and for (items, y.array) |p, q| {
            if (!dmEql(p, q)) break false;
        } else true,
        .map => |m| m.len == y.map.len and for (m) |e| {
            const found = for (y.map) |f| {
                if (dmEql(e.key, f.key) and dmEql(e.value, f.value)) break true;
            } else false;
            if (!found) break false;
        } else true,
        .tag => |t| t.number == y.tag.number and dmEql(t.value.*, y.tag.value.*),
        .simple => |s| s == y.simple,
        .bool => |b| b == y.bool,
        .null_value, .undefined_value => true,
        .f16, .f32, .f64 => unreachable,
    };
}

fn asF64(v: Value) ?f64 {
    return switch (v) {
        .f16 => |f| f,
        .f32 => |f| f,
        .f64 => |f| f,
        else => null,
    };
}

fn hasDuplicateKeys(v: Value) bool {
    switch (v) {
        .array => |items| for (items) |it| {
            if (hasDuplicateKeys(it)) return true;
        },
        .map => |m| for (m, 0..) |e, i| {
            if (hasDuplicateKeys(e.key) or hasDuplicateKeys(e.value)) return true;
            for (m[i + 1 ..]) |f| if (dmEql(e.key, f.key)) return true;
        },
        .tag => |t| return hasDuplicateKeys(t.value.*),
        else => {},
    }
    return false;
}

const Shape = union(enum) { circle: f64, point, poly: []const [2]i16 };
const Typed = struct {
    a: ?u16 = null,
    b: ?[]const u8 = null,
    c: ?[]const i32 = null,
    d: ?f32 = null,
    e: ?Shape = null,
    pub const cbor_options = .{ .keys = .{ .a = 0, .b = 1, .c = 2, .d = 3 }, .bytes = .{.b} };
};

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();
    const tree = try genValue(S, src, aa, 0);
    const canonical_base = src.value(bool);
    const base = try cbor.encode(aa, tree, .{ .canonical = canonical_base });
    var buf: [max_input]u8 = undefined;
    const input = damage(S, src, base, &buf);
    const intact = std.mem.eql(u8, input, base);
    const max_depth: u32 = ([_]u32{ 2, 4, 64 })[src.index(3)];
    try checkInput(gpa, input, max_depth, intact and !canonical_base);
}

fn checkInput(gpa: std.mem.Allocator, input: []const u8, max_depth: u32, plain_intact: bool) !void {
    const opts: cbor.DecodeOptions = .{ .max_depth = max_depth };

    // The reader and the tree decoder agree on every input.
    var r: cbor.Reader = .init(input);
    const skipped = r.skipValue(max_depth);
    if (cbor.decodePrefix(gpa, input, opts)) |p| {
        defer cbor.freeValue(gpa, p.value);
        try skipped;
        if (r.pos != p.len) return error.ReaderLengthDiffers;
    } else |e| {
        if (e == error.OutOfMemory) return e;
        if (skipped) |_| return error.ReaderAcceptedWhatDecodeRefused else |se| if (se != e) return error.ReaderErrorDiffers;
        if (r.pos != 0) return error.ReaderMovedOnError;
    }

    // A sequence reads until the end or an error, and frees what it gave.
    var seq: cbor.Sequence = .init(gpa, input, opts);
    var items: usize = 0;
    while (seq.next() catch null) |v| {
        cbor.freeValue(gpa, v);
        items += 1;
    }
    if (items > 1) hit("seq-multi");

    // Typed mapping: any verdict, no leak.
    if (cbor.typed.decode(Typed, gpa, input, .{ .decode = opts })) |p| {
        hit("typed-ok");
        p.deinit();
    } else |_| {}

    const v = cbor.decode(gpa, input, opts) catch |e| {
        if (e == error.DepthLimitExceeded) hit("depth");
        if (plain_intact and max_depth == 64) return error.IntactInputRefused;
        // Strict decoding refuses whatever lenient decoding refuses.
        if (cbor.decode(gpa, input, .{ .max_depth = max_depth, .deterministic = true })) |w| {
            cbor.freeValue(gpa, w);
            return error.StrictAcceptedWhatLenientRefused;
        } else |_| {}
        return;
    };
    defer cbor.freeValue(gpa, v);
    hit("lenient-ok");

    const plain = try cbor.encode(gpa, v, .{});
    defer gpa.free(plain);
    if (plain_intact and !std.mem.eql(u8, plain, input)) return error.IntactRoundTripDiffers;

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try cbor.Writer.init(&aw.writer).value(v);
    if (!std.mem.eql(u8, aw.written(), plain)) return error.WriterDiffersFromEncode;

    const d = try cbor.diagnostic(gpa, v);
    gpa.free(d);

    // Duplicate keys, against the independent data-model equality.
    const dup = hasDuplicateKeys(v);
    if (dup) hit("dup");
    if (cbor.decode(gpa, input, .{ .max_depth = max_depth, .reject_duplicate_keys = true })) |w| {
        cbor.freeValue(gpa, w);
        if (dup) return error.DuplicateMissed;
    } else |e| {
        if (e != error.DuplicateKey or !dup) return error.DuplicateFalseAlarm;
    }

    // Deterministic: accepted iff the input is its own canonical encoding.
    const canon = try cbor.encode(gpa, v, .{ .canonical = true });
    defer gpa.free(canon);
    const is_canon = std.mem.eql(u8, canon, input);
    if (cbor.decode(gpa, input, .{ .max_depth = max_depth, .deterministic = true })) |w| {
        cbor.freeValue(gpa, w);
        hit("det-ok");
        if (!is_canon) return error.DeterministicAcceptedNonCanonical;
        if (dup) return error.DeterministicAcceptedDuplicate;
    } else |e| switch (e) {
        error.DuplicateKey => if (!dup) return error.DeterministicFalseDuplicate,
        error.NotDeterministic => {
            hit("det-refused");
            if (is_canon) return error.DeterministicRefusedCanonical;
        },
        else => return e,
    }
}

test "fuzz driver: CBOR_FUZZ" {
    fuzz_driver.run(harness, .{ .prefix = "CBOR_FUZZ", .name = "cbor" }) catch |e| switch (e) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return e,
    };
}

test "fuzz harness: 300 seeds in every test run, and it gets everywhere" {
    var reached: [8]usize = @splat(0);
    const labels = [_][]const u8{ "lenient-ok", "det-ok", "det-refused", "dup", "typed-ok", "depth", "intact", "refused" };
    for (0..300) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        // The same draws as `harness`, with the verdicts counted here.
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const aa = arena.allocator();
        const tree = try genValue(fuzz_driver.Rng, &rng, aa, 0);
        const canonical_base = rng.value(bool);
        const base = try cbor.encode(aa, tree, .{ .canonical = canonical_base });
        var buf: [max_input]u8 = undefined;
        const input = damage(fuzz_driver.Rng, &rng, base, &buf);
        const max_depth: u32 = ([_]u32{ 2, 4, 64 })[rng.index(3)];
        const intact = std.mem.eql(u8, input, base);
        checkInput(testing.allocator, input, max_depth, intact and !canonical_base) catch |e| {
            std.debug.print("seed {d}: {t}\n", .{ seed, e });
            return e;
        };
        if (intact) reached[6] += 1;
        const opts: cbor.DecodeOptions = .{ .max_depth = max_depth };
        if (cbor.decode(testing.allocator, input, opts)) |v| {
            defer cbor.freeValue(testing.allocator, v);
            reached[0] += 1;
            if (hasDuplicateKeys(v)) reached[3] += 1;
            if (cbor.decode(testing.allocator, input, .{ .max_depth = max_depth, .deterministic = true })) |w| {
                cbor.freeValue(testing.allocator, w);
                reached[1] += 1;
            } else |e| {
                if (e == error.NotDeterministic) reached[2] += 1;
            }
        } else |e| {
            reached[7] += 1;
            if (e == error.DepthLimitExceeded) reached[5] += 1;
        }
        if (cbor.typed.decode(Typed, testing.allocator, input, .{ .decode = opts })) |p| {
            reached[4] += 1;
            p.deinit();
        } else |_| {}
    }
    // Reach before verdict: every branch the oracles judge was taken.
    for (reached, labels) |n, l| {
        if (n == 0) {
            std.debug.print("unreached: {s}\n", .{l});
            return error.Unreached;
        }
    }
}
