// SPDX-License-Identifier: MIT
//! Shared machinery of the keyed verbs: a canonical, injective key encoding, a
//! factorizer (row -> dense group id, pandas' `factorize` shape) and a stable
//! radix sort. Not a public namespace: the keyed verbs sit on it. Taken from
//! `tabular` (the same authors, MIT), where the row verbs use the same code.
//!
//! Key equality is the one `Value.order` gives, by canonical form: int 1, float
//! 1.0 and decimal 1 are one key (-0.0 is 0), text "1" and "i1" are other keys,
//! and text is length-prefixed, so no cell content can make two different
//! composite keys collide (the 0x1f separator used before could).
//!
//! Hashing, against constructed keys: every table has its own seed, from the address of
//! a stack variable and of the input (ASLR entropy, no `std.Io` needed), and a seeded
//! 128-bit multiply, so a key set cannot be built in advance to collide. Where the
//! addresses are predictable (no ASLR, freestanding) a work cap still holds: each table
//! counts its collision steps and refuses with `TooLarge` past `work_floor +
//! work_per_row x rows`, far above what any seed gives honest data (about one step per
//! row at the 1/2 load kept here). A seed never reaches a result: ids are first-seen.

const std = @import("std");
const dtype = @import("dtype.zig");
const ds = @import("value.zig");
const Value = ds.Value;

pub const Error = error{ OutOfMemory, TooLarge };

/// A NaN cell: the second half of "missing" (`.null` is the first).
pub fn isMissing(v: Value) bool {
    return v == .null or (v == .float and std.math.isNan(v.float));
}

pub const Nan = enum {
    /// NaN and null are one key: "missing" (pandas' view of a float column).
    as_null,
    /// NaN is a key of its own, sorted by `Value.order` (`sort` needs it).
    own,
};

/// The i64 a numeric cell equals exactly, if any.
pub inline fn exactInt(v: Value) ?i64 {
    switch (v) {
        .int => |i| return i,
        .uint => |u| return std.math.cast(i64, u), // a hand-built one at or below maxInt(i64)
        .float => |f| {
            // Bounds as in Value.floatToInt; `f == @trunc(f)` rejects NaN too.
            if (!(f >= -9223372036854775808.0 and f < 9223372036854775808.0)) return null;
            if (f != @trunc(f)) return null;
            return @intFromFloat(f);
        },
        .decimal => |r| {
            if (@rem(r, ds.decimal_scale) != 0) return null;
            return std.math.cast(i64, @divExact(r, ds.decimal_scale));
        },
        else => return null,
    }
}

/// The u64 above `maxInt(i64)` a numeric cell equals exactly, if any.
fn exactAboveI64(v: Value) ?u64 {
    const x = dtype.exactI128(v) orelse return null;
    if (x <= std.math.maxInt(i64)) return null;
    return std.math.cast(u64, x);
}

/// The f64 exactly equal to the decimal `raw / 10^12`, if there is one. In integers,
/// since `asFloat` rounds: a float has a power of two below it, so 5^12 must divide
/// `raw`, leaving `q / 2^12`, and `q` must fit a 53-bit significand. Dividing by 4096
/// then loses nothing: the result is at least 2^-12, far from the subnormals.
fn decimalAsFloat(raw: i128) ?f64 {
    const five12: i128 = 244_140_625;
    comptime std.debug.assert(five12 * 4096 == ds.decimal_scale);
    if (@rem(raw, five12) != 0) return null;
    const q = @divExact(raw, five12);
    const u: u128 = @abs(q);
    if (u == 0) return 0;
    if (128 - @clz(u) - @ctz(u) > 53) return null;
    return @as(f64, @floatFromInt(q)) / 4096;
}

/// Append `v`'s canonical bytes. Self-delimiting, so a composite key is simply
/// the concatenation of its cells' encodings.
pub fn encode(a: std.mem.Allocator, buf: *std.ArrayList(u8), v: Value, nan: Nan) error{OutOfMemory}!void {
    return encodeAt(a, buf, v, nan, 0);
}

/// `encode` at nesting level `depth`: a list is `L`, its length and its elements, a
/// record `R`, its field count and its fields in order (names are the column's, the
/// same for every row), so a key equals another exactly when `Value.order` says so.
/// Past `max_nesting_depth` a nested value encodes as null, as every walker reads it.
fn encodeAt(a: std.mem.Allocator, buf: *std.ArrayList(u8), v0: Value, nan: Nan, depth: u8) error{OutOfMemory}!void {
    const v = Value.capped(v0, depth);
    switch (v) {
        .list => |l| {
            const n: u64 = l.len();
            try buf.append(a, 'L');
            try buf.appendSlice(a, std.mem.asBytes(&n));
            for (0..l.len()) |i| try encodeAt(a, buf, l.get(i), nan, depth + 1);
            return;
        },
        .record => |r| {
            const n: u64 = r.len();
            try buf.append(a, 'R');
            try buf.appendSlice(a, std.mem.asBytes(&n));
            for (0..r.len()) |i| try encodeAt(a, buf, r.get(i), nan, depth + 1);
            return;
        },
        else => {},
    }
    if (exactInt(v)) |i| {
        try buf.append(a, 'i');
        try buf.appendSlice(a, std.mem.asBytes(&i));
        return;
    }
    // A whole number in [2^63, 2^64) — a UInt64 cell, or a float or decimal equal to one —
    // keys as that u64, so the three meet as `Value.order` says they are equal.
    if (exactAboveI64(v)) |u| {
        try buf.append(a, 'u');
        try buf.appendSlice(a, std.mem.asBytes(&u));
        return;
    }
    switch (v) {
        .null => try buf.append(a, '0'),
        .bool => |b| try buf.appendSlice(a, if (b) "b1" else "b0"),
        .text => |t| {
            const n: u64 = t.len;
            try buf.append(a, 's');
            try buf.appendSlice(a, std.mem.asBytes(&n));
            try buf.appendSlice(a, t);
        },
        .float => |f| {
            if (std.math.isNan(f)) {
                try buf.append(a, if (nan == .as_null) '0' else 'n');
            } else {
                try buf.append(a, 'f');
                try buf.appendSlice(a, std.mem.asBytes(&f));
            }
        },
        .decimal => |r| {
            // One that a float states exactly keys as that float (0.5 == 0.5).
            if (decimalAsFloat(r)) |f| {
                try buf.append(a, 'f');
                try buf.appendSlice(a, std.mem.asBytes(&f));
            } else {
                try buf.append(a, 'd');
                try buf.appendSlice(a, std.mem.asBytes(&r));
            }
        },
        .int, .uint => unreachable, // exactInt or exactAboveI64 took it
        .list, .record => unreachable, // the switch above took them
    }
}

inline fn mum(x: u64, y: u64) u64 {
    const m = @as(u128, x) *% y;
    return @truncate(m ^ (m >> 64));
}

const IntSlot = struct { key: i64 = 0, id: u32 = 0 }; // id + 1; 0 = empty
const ByteSlot = struct { h: u32 = 0, id: u32 = 0 }; // id + 1; 0 = empty

inline fn hashInt(x: i64, seed: u64) u64 {
    const u: u64 = @bitCast(x);
    return mum(u ^ seed, 0x9E3779B97F4A7C15);
}

/// Differs per call and per process where addresses do (see the file header).
pub fn freshSeed(input: usize) u64 {
    var here: u8 = 0;
    std.mem.doNotOptimizeAway(&here);
    return mum(@intFromPtr(&here) ^ 0xa0761d6478bd642f, input ^ 0xe7037ed1a0b428db);
}

pub const work_floor: u64 = 1 << 20;
pub const work_per_row: u64 = 128;

/// Collision steps of one table, against its limit.
const Work = struct {
    steps: u64 = 0,
    limit: u64,

    inline fn step(w: *Work) Error!void {
        w.steps += 1;
        if (w.steps > w.limit) return error.TooLarge;
    }
};

fn newWork(a: std.mem.Allocator, rows: usize) Error!*Work {
    const w = try a.create(Work);
    w.* = .{ .limit = work_floor +| (work_per_row *| rows) };
    return w;
}

/// A short text in a word's time (the wyhash mix); longer ones go to `Wyhash`.
inline fn hashText(t: []const u8, seed: u64) u64 {
    const n = t.len;
    const k0: u64 = 0xa0761d6478bd642f;
    const k1: u64 = 0xe7037ed1a0b428db;
    if (n > 16) return std.hash.Wyhash.hash(seed, t);
    var lo: u64 = 0;
    var hi: u64 = 0;
    if (n >= 8) {
        lo = std.mem.readInt(u64, t[0..8], .little);
        hi = std.mem.readInt(u64, t[n - 8 ..][0..8], .little);
    } else if (n >= 4) {
        lo = std.mem.readInt(u32, t[0..4], .little);
        hi = std.mem.readInt(u32, t[n - 4 ..][0..4], .little);
    } else if (n > 0) {
        lo = t[0];
        hi = (@as(u64, t[n / 2]) << 8) | t[n - 1];
    }
    return mum(lo ^ k0 ^ n ^ seed, hi ^ k1);
}

/// Open-addressed key -> dense id table, ids in first-seen order. One of three
/// shapes: every key one exact i64 (`int_slots`), every key one text cell (`texts`
/// set, compared in place), anything else as canonical bytes.
pub const Table = struct {
    int_slots: []IntSlot = &.{},
    byte_slots: []ByteSlot = &.{},
    offs: std.ArrayList(usize) = .empty,
    bytes: std.ArrayList(u8) = .empty,
    /// Text shape: the extracted key cells and each id's first row in them.
    texts: []const []const u8 = &.{},
    text_mode: bool = false,
    text_firsts: []const u32 = &.{},
    count: u32 = 0,
    seed: u64 = 0,
    /// Set by every constructor; the empty table of a no-key factorize never probes.
    work: *Work = undefined,

    const initial_slots = 64;

    pub fn initInt(a: std.mem.Allocator, rows: usize, seed: u64) Error!Table {
        const s = try a.alloc(IntSlot, capacityFor(rows));
        @memset(s, .{});
        return .{ .int_slots = s, .seed = seed, .work = try newWork(a, rows) };
    }

    pub fn initBytes(a: std.mem.Allocator, rows: usize, seed: u64) Error!Table {
        const s = try a.alloc(ByteSlot, capacityFor(rows));
        @memset(s, .{});
        return .{ .byte_slots = s, .seed = seed, .work = try newWork(a, rows) };
    }

    /// Room for `rows` more lookups in the work budget.
    pub fn allow(t: *const Table, rows: usize) void {
        if (t.int_slots.len != 0 or t.byte_slots.len != 0) {
            t.work.limit +|= work_per_row *| rows;
        }
    }

    /// A first guess; the tables grow from it. Not `rows`: a low-cardinality
    /// key would touch a far bigger table than it needs.
    fn capacityFor(expect: usize) usize {
        return std.math.ceilPowerOfTwo(usize, @max(initial_slots, @min(expect, 1 << 12))) catch initial_slots;
    }

    pub inline fn getOrPutInt(t: *Table, a: std.mem.Allocator, k: i64) Error!u32 {
        if ((@as(usize, t.count) + 1) * 2 > t.int_slots.len) try t.growInt(a);
        const mask = t.int_slots.len - 1;
        var i: usize = @intCast(hashInt(k, t.seed) & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = &t.int_slots[i];
            if (s.id == 0) {
                t.count += 1;
                s.* = .{ .key = k, .id = t.count };
                return t.count - 1;
            }
            if (s.key == k) return s.id - 1;
            try t.work.step();
        }
    }

    pub inline fn getInt(t: *const Table, k: i64) Error!?u32 {
        const mask = t.int_slots.len - 1;
        var i: usize = @intCast(hashInt(k, t.seed) & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = t.int_slots[i];
            if (s.id == 0) return null;
            if (s.key == k) return s.id - 1;
            try t.work.step();
        }
    }

    fn growInt(t: *Table, a: std.mem.Allocator) Error!void {
        const n = try a.alloc(IntSlot, t.int_slots.len * 2);
        @memset(n, .{});
        const mask = n.len - 1;
        for (t.int_slots) |s| {
            if (s.id == 0) continue;
            var i: usize = @intCast(hashInt(s.key, t.seed) & mask);
            while (n[i].id != 0) : (i = (i + 1) & mask) try t.work.step();
            n[i] = s;
        }
        a.free(t.int_slots);
        t.int_slots = n;
    }

    pub fn getOrPutBytes(t: *Table, a: std.mem.Allocator, key: []const u8) Error!u32 {
        if ((@as(usize, t.count) + 1) * 2 > t.byte_slots.len) try t.growBytes(a);
        const h64 = std.hash.Wyhash.hash(t.seed, key);
        const h: u32 = @truncate(h64 >> 32);
        const mask = t.byte_slots.len - 1;
        var i: usize = @intCast(h64 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = &t.byte_slots[i];
            if (s.id == 0) {
                const id = t.count;
                try t.offs.append(a, t.bytes.items.len);
                try t.bytes.appendSlice(a, key);
                t.count += 1;
                s.* = .{ .h = h, .id = t.count };
                return id;
            }
            if (s.h == h and std.mem.eql(u8, t.keyOf(s.id - 1), key)) return s.id - 1;
            try t.work.step();
        }
    }

    pub fn getBytes(t: *const Table, key: []const u8) Error!?u32 {
        const h64 = std.hash.Wyhash.hash(t.seed, key);
        const h: u32 = @truncate(h64 >> 32);
        const mask = t.byte_slots.len - 1;
        var i: usize = @intCast(h64 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = t.byte_slots[i];
            if (s.id == 0) return null;
            if (s.h == h and std.mem.eql(u8, t.keyOf(s.id - 1), key)) return s.id - 1;
            try t.work.step();
        }
    }

    fn keyOf(t: *const Table, id: u32) []const u8 {
        const end = if (id + 1 < t.count) t.offs.items[id + 1] else t.bytes.items.len;
        return t.bytes.items[t.offs.items[id]..end];
    }

    fn growBytes(t: *Table, a: std.mem.Allocator) Error!void {
        const n = try a.alloc(ByteSlot, t.byte_slots.len * 2);
        @memset(n, .{});
        const mask = n.len - 1;
        for (t.byte_slots) |s| {
            if (s.id == 0) continue;
            const h64 = std.hash.Wyhash.hash(t.seed, t.keyOf(s.id - 1));
            var i: usize = @intCast(h64 & mask);
            while (n[i].id != 0) : (i = (i + 1) & mask) try t.work.step();
            n[i] = s;
        }
        a.free(t.byte_slots);
        t.byte_slots = n;
    }

    pub inline fn getText(t: *const Table, key: []const u8) Error!?u32 {
        const h64 = hashText(key, t.seed);
        const h: u32 = @truncate(h64 >> 32);
        const mask = t.byte_slots.len - 1;
        var i: usize = @intCast(h64 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = t.byte_slots[i];
            if (s.id == 0) return null;
            if (s.h == h and std.mem.eql(u8, t.texts[t.text_firsts[s.id - 1]], key)) return s.id - 1;
            try t.work.step();
        }
    }

    /// The id of `row`'s key, if present. Works in every shape: an int or text
    /// table holds only such keys, so any other cell is simply absent.
    pub fn lookup(t: *const Table, a: std.mem.Allocator, scratch: *std.ArrayList(u8), row: []const Value, idxs: []const usize, nan: Nan) Error!?u32 {
        if (t.int_slots.len != 0) {
            const k = exactInt(row[idxs[0]]) orelse return null;
            return try t.getInt(k);
        }
        if (t.text_mode) {
            const c = row[idxs[0]];
            return if (c == .text) try t.getText(c.text) else null;
        }
        if (idxs.len == 0) return if (t.count > 0) 0 else null;
        scratch.clearRetainingCapacity();
        for (idxs) |ci| try encode(a, scratch, row[ci], nan);
        return try t.getBytes(scratch.items);
    }
};

/// Make every name unique in place, in order: the first keeps its name, a later one
/// becomes `name_2`, `name_3`, ... (`columnIndex` could only ever find the first).
pub fn uniqueNames(a: std.mem.Allocator, cols: []ds.Column) Error!void {
    var seen: std.StringHashMapUnmanaged(u32) = .empty;
    defer seen.deinit(a);
    for (cols) |*c| {
        const gop = try seen.getOrPut(a, c.name);
        if (!gop.found_existing) {
            gop.value_ptr.* = 2;
            continue;
        }
        const base = c.name;
        while (true) {
            const n = gop.value_ptr.*;
            seen.getPtr(base).?.* = n + 1;
            const name = try std.fmt.allocPrint(a, "{s}_{d}", .{ base, n });
            if (!seen.contains(name)) {
                try seen.put(a, name, 2);
                c.name = name;
                break;
            }
        }
    }
}

pub const Factors = struct {
    /// Group id per row.
    ids: []u32,
    /// Row of each group's first occurrence, in id order.
    firsts: []u32,
    table: Table,

    pub fn groups(f: Factors) usize {
        return f.firsts.len;
    }
};

fn checkRows(n: usize) Error!void {
    if (n >= std.math.maxInt(u32)) return error.TooLarge;
}

/// Dense ids over an extracted int column. The slot of a key some rows ahead is
/// prefetched: on a high-cardinality key the table is out of cache and the probe
/// is most of the cost.
/// For the differential tests only: `factorizeInts` with and without the presize.
pub const test_hooks = struct {
    pub fn factorizeIntsPresize(a: std.mem.Allocator, ints: []const i64, presize: bool) Error!Factors {
        return factorizeIntsImpl(a, ints, freshSeed(@intFromPtr(ints.ptr)), presize);
    }
    pub fn presizeSlotsOf(ints: []const i64) usize {
        return presizeSlots(ints, 0x1234);
    }
};

pub fn factorizeInts(a: std.mem.Allocator, ints: []const i64) Error!Factors {
    return factorizeIntsSeeded(a, ints, freshSeed(@intFromPtr(ints.ptr)));
}

/// Most slots (16 bytes each) the int table is presized to from its cardinality estimate.
/// A wrong estimate (sorted keys that look all distinct) costs at most this much zeroed
/// memory; growth reaches larger tables by itself when the keys really need them.
pub const max_presize_slots: usize = 1 << 20;

const sample_chunks = 4;
const sample_chunk_len = 256;

/// Slots to start the int table with, from 4 evenly spaced runs of 256 rows: the birthday
/// estimate `s^2 / (2 c)` of the distinct count from the `c` repeats among the `s` sampled
/// keys (no repeat reads as "about as many as rows"). Depends on the key values alone. 0:
/// too few rows, or a small estimate, where the table's own first guess serves.
fn presizeSlots(ints: []const i64, seed: u64) usize {
    const s = sample_chunks * sample_chunk_len;
    if (ints.len < 4 * s) return 0;
    var slots: [2 * s]IntSlot = @splat(.{});
    var distinct: usize = 0;
    const stride = ints.len / sample_chunks;
    for (0..sample_chunks) |c| {
        for (ints[c * stride ..][0..sample_chunk_len]) |k| {
            var i: usize = @intCast(hashInt(k, seed) & (slots.len - 1));
            while (slots[i].id != 0 and slots[i].key != k) i = (i + 1) & (slots.len - 1);
            if (slots[i].id == 0) {
                slots[i] = .{ .key = k, .id = 1 };
                distinct += 1;
            }
        }
    }
    const repeats = s - distinct;
    const est = if (repeats == 0) ints.len else @min(ints.len, s * s / (2 * repeats));
    if (est <= 4096) return 0;
    const want = std.math.ceilPowerOfTwo(usize, est * 2) catch return 0;
    return @min(want, max_presize_slots);
}

fn factorizeIntsSeeded(a: std.mem.Allocator, ints: []const i64, seed: u64) Error!Factors {
    return factorizeIntsImpl(a, ints, seed, true);
}

fn factorizeIntsImpl(a: std.mem.Allocator, ints: []const i64, seed: u64, presize: bool) Error!Factors {
    try checkRows(ints.len);
    const ids = try a.alloc(u32, ints.len);
    var firsts: std.ArrayList(u32) = .empty;
    var t = try Table.initInt(a, ints.len, seed);
    const want = if (presize) presizeSlots(ints, seed) else 0;
    if (want > t.int_slots.len) {
        a.free(t.int_slots);
        t.int_slots = try a.alloc(IntSlot, want);
        @memset(t.int_slots, .{});
    }
    for (ints, ids, 0..) |x, *id, ri| {
        if (ri + prefetch_ahead < ints.len) {
            const h: usize = @intCast(hashInt(ints[ri + prefetch_ahead], seed) & (t.int_slots.len - 1));
            @prefetch(&t.int_slots[h], .{});
        }
        const before = t.count;
        id.* = try t.getOrPutInt(a, x);
        if (t.count != before) try firsts.append(a, @intCast(ri));
    }
    return .{ .ids = ids, .firsts = try firsts.toOwnedSlice(a), .table = t };
}

const prefetch_ahead = 12;

/// Dense ids over an extracted text column; `texts` must outlive the table.
pub fn factorizeTexts(a: std.mem.Allocator, texts: []const []const u8) Error!Factors {
    try checkRows(texts.len);
    const ids = try a.alloc(u32, texts.len);
    var firsts: std.ArrayList(u32) = .empty;
    var slots = try a.alloc(ByteSlot, Table.capacityFor(texts.len));
    @memset(slots, .{});
    var count: u32 = 0;
    const seed = freshSeed(@intFromPtr(texts.ptr));
    const work = try newWork(a, texts.len);
    for (texts, ids, 0..) |x, *id, ri| {
        if ((@as(usize, count) + 1) * 2 > slots.len) {
            const n = try a.alloc(ByteSlot, slots.len * 2);
            @memset(n, .{});
            const nmask = n.len - 1;
            for (slots) |s| {
                if (s.id == 0) continue;
                var i: usize = @intCast(hashText(texts[firsts.items[s.id - 1]], seed) & nmask);
                while (n[i].id != 0) : (i = (i + 1) & nmask) try work.step();
                n[i] = s;
            }
            a.free(slots);
            slots = n;
        }
        const h64 = hashText(x, seed);
        const h: u32 = @truncate(h64 >> 32);
        const mask = slots.len - 1;
        var i: usize = @intCast(h64 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = slots[i];
            if (s.id == 0) {
                try firsts.append(a, @intCast(ri));
                count += 1;
                slots[i] = .{ .h = h, .id = count };
                id.* = count - 1;
                break;
            }
            if (s.h == h and std.mem.eql(u8, texts[firsts.items[s.id - 1]], x)) {
                id.* = s.id - 1;
                break;
            }
            try work.step();
        }
    }
    const fs = try firsts.toOwnedSlice(a);
    return .{ .ids = ids, .firsts = fs, .table = .{ .byte_slots = slots, .text_mode = true, .texts = texts, .text_firsts = fs, .count = count, .seed = seed, .work = work } };
}

/// One key column pulled out of the rows, so the table loop never touches them.
pub const KeyCol = union(enum) { ints: []i64, texts: [][]const u8, generic };

/// The shape the first row suggests; `.generic` when it cannot be one of the
/// fast ones. A later cell that does not fit turns it `.generic` too.
pub fn keyColFor(a: std.mem.Allocator, rows: []const []const Value, ci: usize) Error!KeyCol {
    if (rows.len == 0) return .generic;
    const c = rows[0][ci];
    if (c == .text) return .{ .texts = try a.alloc([]const u8, rows.len) };
    if (exactInt(c) != null) return .{ .ints = try a.alloc(i64, rows.len) };
    return .generic;
}

pub inline fn keyColPut(col: *KeyCol, a: std.mem.Allocator, i: usize, c: Value) void {
    switch (col.*) {
        .ints => |xs| {
            if (exactInt(c)) |x| xs[i] = x else {
                a.free(xs);
                col.* = .generic;
            }
        },
        .texts => |xs| {
            if (c == .text) xs[i] = c.text else {
                a.free(xs);
                col.* = .generic;
            }
        },
        .generic => {},
    }
}

pub fn factorizeCol(a: std.mem.Allocator, col: KeyCol, rows: []const []const Value, idxs: []const usize, nan: Nan) Error!Factors {
    return switch (col) {
        .ints => |xs| factorizeInts(a, xs),
        .texts => |xs| factorizeTexts(a, xs),
        .generic => factorizeBytes(a, rows, idxs, nan),
    };
}

fn factorizeBytes(a: std.mem.Allocator, rows: []const []const Value, idxs: []const usize, nan: Nan) Error!Factors {
    try checkRows(rows.len);
    const ids = try a.alloc(u32, rows.len);
    var firsts: std.ArrayList(u32) = .empty;
    if (idxs.len == 0) {
        @memset(ids, 0);
        if (rows.len > 0) try firsts.append(a, 0);
        return .{ .ids = ids, .firsts = try firsts.toOwnedSlice(a), .table = .{ .count = @intFromBool(rows.len > 0) } };
    }
    var t = try Table.initBytes(a, rows.len, freshSeed(@intFromPtr(rows.ptr)));
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    for (rows, ids, 0..) |r, *id, ri| {
        scratch.clearRetainingCapacity();
        for (idxs) |ci| try encode(a, &scratch, r[ci], nan);
        const before = t.count;
        id.* = try t.getOrPutBytes(a, scratch.items);
        if (t.count != before) try firsts.append(a, @intCast(ri));
    }
    return .{ .ids = ids, .firsts = try firsts.toOwnedSlice(a), .table = t };
}

/// Row -> dense group id over `idxs`, ids in first-seen order. No key columns:
/// one group, when there is a row. NaN only matters to the bytes shape, the one
/// a NaN cell lands in.
pub fn factorize(a: std.mem.Allocator, rows: []const []const Value, idxs: []const usize, nan: Nan) Error!Factors {
    try checkRows(rows.len);
    if (idxs.len != 1) return factorizeBytes(a, rows, idxs, nan);
    const ci = idxs[0];
    var col = try keyColFor(a, rows, ci);
    for (rows, 0..) |r, i| {
        if (col == .generic) break;
        prefetchCell(rows, i, ci);
        keyColPut(&col, a, i, r[ci]);
    }
    return factorizeCol(a, col, rows, idxs, nan);
}

/// Combine several columns' ids into one id per distinct tuple, first-seen order.
/// The tuple is `(ids so far) * n + next`: the product of two counts each below
/// 2^32, so it fits u64. Direct addressing while the product is small next to the
/// rows, a table otherwise. Consumes nothing the caller keeps but `first_ids`.
pub fn combine(a: std.mem.Allocator, first_ids: []u32, n0: usize, more: []const Factors) Error!Factors {
    var ids = first_ids;
    var n = n0;
    var firsts: []u32 = &.{};
    for (more, 0..) |f, step| {
        const span = @as(u128, n) * f.groups();
        var next_firsts: std.ArrayList(u32) = .empty;
        if (span <= @max(ids.len * 4, 1 << 16)) {
            const slots = try a.alloc(u32, @intCast(span));
            defer a.free(slots);
            @memset(slots, 0);
            const m: u32 = @intCast(f.groups());
            for (ids, f.ids, 0..) |*id, x, ri| {
                const s = &slots[@as(usize, id.*) * m + x];
                if (s.* == 0) {
                    try next_firsts.append(a, @intCast(ri));
                    s.* = @intCast(next_firsts.items.len);
                }
                id.* = s.* - 1;
            }
        } else {
            const comp = try a.alloc(i64, ids.len);
            defer a.free(comp);
            const m: u64 = f.groups();
            for (comp, ids, f.ids) |*c, id, x| c.* = @bitCast(@as(u64, id) * m + x);
            const g = try factorizeInts(a, comp);
            a.free(ids);
            ids = g.ids;
            next_firsts = .fromOwnedSlice(g.firsts);
            a.free(g.table.int_slots);
        }
        a.free(f.ids);
        if (step > 0) a.free(firsts);
        firsts = next_firsts.items;
        n = firsts.len;
    }
    return .{ .ids = ids, .firsts = firsts, .table = .{} };
}

/// `factorize` over columns already extracted (`cols`, parallel to `idxs`): each
/// column's own fast shape, then the tuples. The result has no lookup table.
pub fn factorizeMany(a: std.mem.Allocator, cols: []const KeyCol, rows: []const []const Value, idxs: []const usize, nan: Nan) Error!Factors {
    if (idxs.len == 0) return factorizeBytes(a, rows, idxs, nan);
    const first = try factorizeCol(a, cols[0], rows, idxs[0..1], nan);
    if (idxs.len == 1) return first;
    const more = try a.alloc(Factors, idxs.len - 1);
    defer a.free(more);
    for (more, cols[1..], idxs[1..], 0..) |*m, c, _, j| m.* = try factorizeCol(a, c, rows, idxs[j + 1 ..][0..1], nan);
    return combine(a, first.ids, first.groups(), more);
}

/// The prefetch for a row some way ahead: rows are 100+ bytes apart, so a scan of one
/// column is a cache miss per row without it.
pub inline fn prefetchCell(rows: []const []const Value, i: usize, ci: usize) void {
    if (i + prefetch_rows < rows.len) @prefetch(rows[i + prefetch_rows].ptr + ci, .{});
}

const prefetch_rows = 24;

/// `hits[i]` = the id of `rows[i]`'s key, or `none`. `skip_missing`: a missing key
/// cell matches nothing. The int shape extracts the keys first and prefetches.
pub const none: u32 = std.math.maxInt(u32);

pub fn probeAll(a: std.mem.Allocator, t: *const Table, rows: []const []const Value, idxs: []const usize, nan: Nan, skip_missing: bool, hits: []u32) Error!void {
    t.allow(rows.len);
    if (t.int_slots.len != 0 and idxs.len == 1) {
        const ci = idxs[0];
        const xs = try a.alloc(i64, rows.len);
        defer a.free(xs);
        const ok = try a.alloc(bool, rows.len);
        defer a.free(ok);
        for (rows, xs, ok, 0..) |r, *x, *o, i| {
            prefetchCell(rows, i, ci);
            const e = exactInt(r[ci]);
            o.* = e != null;
            x.* = e orelse 0;
        }
        const mask = t.int_slots.len - 1;
        for (xs, ok, hits, 0..) |x, o, *h, i| {
            if (i + prefetch_ahead < xs.len) {
                @prefetch(&t.int_slots[@intCast(hashInt(xs[i + prefetch_ahead], t.seed) & mask)], .{});
            }
            h.* = if (o) (try t.getInt(x)) orelse none else none;
        }
        return;
    }
    var scratch: std.ArrayList(u8) = .empty;
    defer scratch.deinit(a);
    for (rows, hits) |r, *h| {
        var skip = false;
        if (skip_missing) {
            for (idxs) |ci| skip = skip or isMissing(r[ci]);
        }
        h.* = if (skip) none else (try t.lookup(a, &scratch, r, idxs, nan)) orelse none;
    }
}

/// `probeAll` for keys already in an int column: an int table, and no row to read.
pub fn probeInts(t: *const Table, xs: []const i64, hits: []u32) Error!void {
    t.allow(xs.len);
    const mask = t.int_slots.len - 1;
    for (xs, hits, 0..) |x, *h, i| {
        if (i + prefetch_ahead < xs.len) {
            @prefetch(&t.int_slots[@intCast(hashInt(xs[i + prefetch_ahead], t.seed) & mask)], .{});
        }
        h.* = (try t.getInt(x)) orelse none;
    }
}

/// Rows per group in row order, compressed: group g's rows are
/// `rows[offs[g]..offs[g + 1]]`.
pub const Members = struct {
    offs: []u32,
    rows: []u32,

    pub fn of(m: Members, g: usize) []const u32 {
        return m.rows[m.offs[g]..m.offs[g + 1]];
    }
};

pub fn members(a: std.mem.Allocator, ids: []const u32, n_groups: usize) Error!Members {
    const offs = try a.alloc(u32, n_groups + 1);
    @memset(offs, 0);
    for (ids) |g| offs[g + 1] += 1;
    for (0..n_groups) |g| offs[g + 1] += offs[g];
    const rows = try a.alloc(u32, ids.len);
    const next = try a.dupe(u32, offs[0..n_groups]);
    defer a.free(next);
    for (ids, 0..) |g, ri| {
        rows[next[g]] = @intCast(ri);
        next[g] += 1;
    }
    return .{ .offs = offs, .rows = rows };
}

pub const Pair = struct { key: u64, idx: u32 };

/// Stable LSD radix sort by `key`, skipping bytes every element shares.
pub fn radixSort(a: std.mem.Allocator, pairs: []Pair) Error!void {
    if (pairs.len < 2) return;
    var hist: [8][256]u32 = @splat(@splat(0));
    for (pairs) |p| {
        var k = p.key;
        for (&hist) |*h| {
            h[@as(u8, @truncate(k))] += 1;
            k >>= 8;
        }
    }
    const tmp = try a.alloc(Pair, pairs.len);
    defer a.free(tmp);
    var src = pairs;
    var dst = tmp;
    const first_key = pairs[0].key;
    for (&hist, 0..) |*h, byte| {
        const shift: u6 = @intCast(byte * 8);
        if (h[@as(u8, @truncate(first_key >> shift))] == pairs.len) continue; // all share it
        var sum: u32 = 0;
        for (h) |*c| {
            const n = c.*;
            c.* = sum;
            sum += n;
        }
        for (src) |p| {
            const b: u8 = @truncate(p.key >> shift);
            dst[h[b]] = p;
            h[b] += 1;
        }
        std.mem.swap([]Pair, &src, &dst);
    }
    if (src.ptr != pairs.ptr) @memcpy(pairs, src);
}

/// Total-order image of a float: bitwise comparable, -0.0 == +0.0, NaN above all.
pub inline fn floatKey(f: f64) u64 {
    if (std.math.isNan(f)) return std.math.maxInt(u64);
    const bits: u64 = @bitCast(if (f == 0) @as(f64, 0) else f);
    return if (bits >> 63 != 0) ~bits else bits | (@as(u64, 1) << 63);
}

pub inline fn intKey(i: i64) u64 {
    const u: u64 = @bitCast(i);
    return u ^ (@as(u64, 1) << 63);
}

/// In-place k-th smallest: afterwards `xs[k]` is the value a full sort would put
/// there, everything before it is <= it. No NaN in `xs`. Hoare quickselect, with
/// a sort as the fallback when the partitions stop shrinking.
pub fn selectKth(xs: []f64, k: usize) void {
    var lo: usize = 0;
    var hi: usize = xs.len - 1;
    var fuel: usize = 2 * (std.math.log2_int(usize, xs.len | 1) + 1);
    while (lo < hi) {
        if (fuel == 0) {
            std.mem.sort(f64, xs[lo .. hi + 1], {}, std.sort.asc(f64));
            return;
        }
        fuel -= 1;
        const mid = lo + (hi - lo) / 2;
        if (xs[mid] < xs[lo]) std.mem.swap(f64, &xs[mid], &xs[lo]);
        if (xs[hi] < xs[lo]) std.mem.swap(f64, &xs[hi], &xs[lo]);
        if (xs[hi] < xs[mid]) std.mem.swap(f64, &xs[hi], &xs[mid]);
        const pivot = xs[mid];
        var i = lo;
        var j = hi;
        while (i <= j) {
            while (xs[i] < pivot) i += 1;
            while (xs[j] > pivot) j -= 1;
            if (i <= j) {
                std.mem.swap(f64, &xs[i], &xs[j]);
                i += 1;
                if (j == 0) break;
                j -= 1;
            }
        }
        if (k <= j) {
            hi = j;
        } else if (k >= i) {
            lo = i;
        } else return;
    }
}

const testing = std.testing;

test "encode: one key per value, across kinds; no look-alikes" {
    const a = testing.allocator;
    var x: std.ArrayList(u8) = .empty;
    defer x.deinit(a);
    var y: std.ArrayList(u8) = .empty;
    defer y.deinit(a);
    const same = [_][2]Value{
        .{ .{ .int = 1 }, .{ .float = 1.0 } },
        .{ .{ .int = 1 }, .{ .decimal = ds.decimal_scale } },
        .{ .{ .float = 0.0 }, .{ .float = -0.0 } },
        .{ .{ .float = 0.5 }, .{ .decimal = @divExact(ds.decimal_scale, 2) } },
    };
    for (same) |p| {
        x.clearRetainingCapacity();
        y.clearRetainingCapacity();
        try encode(a, &x, p[0], .own);
        try encode(a, &y, p[1], .own);
        try testing.expectEqualSlices(u8, x.items, y.items);
    }
    const differ = [_][2]Value{
        .{ .{ .int = 1 }, .{ .text = "1" } },
        .{ .{ .int = 5 }, .{ .text = "i5" } },
        .{ .{ .bool = true }, .{ .int = 1 } },
        .{ .null, .{ .text = "" } },
        .{ .{ .float = std.math.nan(f64) }, .null },
        .{ .{ .decimal = 1 }, .{ .float = 1e-12 } },
    };
    for (differ) |p| {
        x.clearRetainingCapacity();
        y.clearRetainingCapacity();
        try encode(a, &x, p[0], .own);
        try encode(a, &y, p[1], .own);
        try testing.expect(!std.mem.eql(u8, x.items, y.items));
    }
}

test "factorize: a separator in the data cannot merge composite keys" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = [_][]const Value{
        &.{ .{ .text = "a\x1fb" }, .{ .text = "c" } },
        &.{ .{ .text = "a" }, .{ .text = "b\x1fc" } },
        &.{ .{ .text = "a" }, .{ .text = "b\x1fc" } },
    };
    const f = try factorize(a, &rows, &.{ 0, 1 }, .as_null);
    try testing.expectEqual(@as(usize, 2), f.groups());
    try testing.expectEqualSlices(u32, &.{ 0, 1, 1 }, f.ids);
    try testing.expectEqualSlices(u32, &.{ 0, 1 }, f.firsts);
}

test "factorize: an int column grows past the initial table, then falls back on a text cell" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const rows = try a.alloc([]const Value, 10_000);
    for (rows, 0..) |*r, i| r.* = try a.dupe(Value, &.{.{ .int = @intCast(i % 5000) }});
    const f = try factorize(a, rows, &.{0}, .as_null);
    try testing.expectEqual(@as(usize, 5000), f.groups());
    try testing.expectEqual(f.ids[17], f.ids[5017]);
    rows[9999] = try a.dupe(Value, &.{.{ .text = "x" }});
    const g = try factorize(a, rows, &.{0}, .as_null);
    try testing.expectEqual(@as(usize, 5001), g.groups());
    try testing.expectEqual(g.ids[17], g.ids[5017]);
}

test "factorizeMany: tuples, small and large spans, against a set of the tuples" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    for ([_]u32{ 4, 100_000 }) |domain| {
        const rows = try a.alloc([]const Value, 3000);
        for (rows) |*row| {
            row.* = try a.dupe(Value, &.{
                .{ .int = r.uintLessThan(u32, domain) },
                .{ .text = if (r.boolean()) "p" else "q" },
                if (r.boolean()) .null else .{ .float = 0.5 },
            });
        }
        const idxs = [_]usize{ 0, 1, 2 };
        const cols = [_]KeyCol{ try keyColFor(a, rows, 0), try keyColFor(a, rows, 1), .generic };
        for (rows, 0..) |row, i| {
            for (cols, idxs) |c, ci| {
                var m = c;
                keyColPut(&m, a, i, row[ci]);
            }
        }
        const f = try factorizeMany(a, &cols, rows, &idxs, .as_null);
        const g = try factorizeBytes(a, rows, &idxs, .as_null);
        try testing.expectEqualSlices(u32, g.ids, f.ids);
        try testing.expectEqualSlices(u32, g.firsts, f.firsts);
    }
}

test "encode: order == .eq and equal key bytes are the same thing, over float, decimal and int" {
    const a = testing.allocator;
    var x: std.ArrayList(u8) = .empty;
    defer x.deinit(a);
    var y: std.ArrayList(u8) = .empty;
    defer y.deinit(a);
    var prng = std.Random.DefaultPrng.init(0xdec1);
    const r = prng.random();
    const check = struct {
        fn f(al: std.mem.Allocator, p: *std.ArrayList(u8), q: *std.ArrayList(u8), l: Value, m: Value) !void {
            p.clearRetainingCapacity();
            q.clearRetainingCapacity();
            try encode(al, p, l, .own);
            try encode(al, q, m, .own);
            try testing.expectEqual(l.order(m) == .eq, std.mem.eql(u8, p.items, q.items));
        }
    }.f;
    var equal: usize = 0;
    for (0..200_000) |_| {
        // A dyadic float with a random number of fractional bits: often a decimal states it.
        const bits = r.uintLessThan(u6, 54);
        const frac = r.uintLessThan(u6, 14);
        const m: i64 = @intCast(r.int(u64) >> (63 - @as(u6, bits)));
        const fv = @as(f64, @floatFromInt(if (r.boolean()) m else -m)) / @as(f64, @floatFromInt(@as(u64, 1) << frac));
        const f: Value = .{ .float = fv };
        // Its decimal, when it has one, and a neighbour; a random raw; an int.
        const scaled = fv * 1e12;
        const raw: i128 = if (@abs(scaled) < 1e30) @intFromFloat(scaled) else r.int(i64);
        const exact: i128 = if (Value.floatToInt(i64, fv * 4096)) |q| @as(i128, q) * 244_140_625 else raw;
        const cases = [_]Value{ .{ .decimal = exact }, .{ .decimal = raw }, .{ .decimal = exact + 1 }, .{ .decimal = r.int(i64) }, .{ .int = if (Value.floatToInt(i64, fv)) |i| i else 0 }, .{ .float = fv * 2 } };
        for (cases) |c| {
            try check(a, &x, &y, f, c);
            try check(a, &x, &y, c, f);
            if (f.order(c) == .eq) equal += 1;
        }
        const i_v: Value = .{ .int = r.int(i64) >> @intCast(r.uintLessThan(u32, 63)) };
        try check(a, &x, &y, i_v, .{ .decimal = @as(i128, i_v.int) * ds.decimal_scale });
        try check(a, &x, &y, i_v, .{ .float = @floatFromInt(i_v.int) });
    }
    try testing.expect(equal > 10_000); // the property was exercised, not vacuous
    // Beyond i64 and beyond 2^53 significand.
    const two63 = @as(i128, 1) << 63;
    try check(a, &x, &y, .{ .float = 0x1p63 }, .{ .decimal = two63 * ds.decimal_scale });
    try check(a, &x, &y, .{ .float = 0x1p70 }, .{ .decimal = (@as(i128, 1) << 70) * ds.decimal_scale });
    try check(a, &x, &y, .{ .decimal = std.math.minInt(i128) }, .{ .decimal = std.math.maxInt(i128) });
    try check(a, &x, &y, .{ .float = std.math.inf(f64) }, .{ .decimal = std.math.maxInt(i128) });
}

test "seed: results do not depend on it; keys built against a known seed hit the cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    const xs = try a.alloc(i64, 20_000);
    for (xs) |*x| x.* = r.intRangeAtMost(i64, -3000, 3000);
    const f1 = try factorizeIntsSeeded(a, xs, 1);
    const f2 = try factorizeIntsSeeded(a, xs, 0xdeadbeef);
    try testing.expectEqualSlices(u32, f1.ids, f2.ids);
    try testing.expectEqualSlices(u32, f1.firsts, f2.firsts);
    try testing.expect(f1.table.work.steps < 2 * xs.len); // about one step per row

    // 2000 keys that share a slot for every table size up to 2^13, under seed 7.
    const seed: u64 = 7;
    const bad = try a.alloc(i64, 2000);
    var at: usize = 0;
    var k: i64 = 0;
    while (at < bad.len) : (k += 1) {
        if (hashInt(k, seed) & 8191 == 5) {
            bad[at] = k;
            at += 1;
        }
    }
    try testing.expectError(error.TooLarge, factorizeIntsSeeded(a, bad, seed));
    // The same keys under any other seed are ordinary.
    const ok = try factorizeIntsSeeded(a, bad, seed ^ 0x1234567);
    try testing.expectEqual(@as(usize, bad.len), ok.groups());
}

test "uniqueNames: first keeps its name, later ones are numbered past existing names" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var cols = [_]ds.Column{
        .{ .name = "x", .type = .int },
        .{ .name = "x_2", .type = .int },
        .{ .name = "x", .type = .int },
        .{ .name = "x", .type = .int },
    };
    try uniqueNames(a, &cols);
    try testing.expectEqualStrings("x", cols[0].name);
    try testing.expectEqualStrings("x_2", cols[1].name);
    try testing.expectEqualStrings("x_3", cols[2].name);
    try testing.expectEqualStrings("x_4", cols[3].name);
}

test "radixSort: stable, against a stable reference" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(42);
    const r = prng.random();
    const ps = try a.alloc(Pair, 3000);
    for (ps, 0..) |*p, i| p.* = .{ .key = r.int(u64) >> @intCast(r.uintLessThan(u32, 64)), .idx = @intCast(i) };
    const ref = try a.dupe(Pair, ps);
    std.mem.sort(Pair, ref, {}, struct {
        fn lt(_: void, l: Pair, m: Pair) bool {
            return l.key < m.key;
        }
    }.lt);
    try radixSort(a, ps);
    try testing.expectEqualSlices(Pair, ref, ps);
}

test "floatKey orders like Value.order" {
    const xs = [_]f64{ -std.math.inf(f64), -1.5, -1e-300, 0, 1e-300, 1.5, std.math.inf(f64), std.math.nan(f64) };
    for (xs[0 .. xs.len - 1], xs[1..]) |l, m| try testing.expect(floatKey(l) < floatKey(m));
    try testing.expectEqual(floatKey(0.0), floatKey(-0.0));
    try testing.expect(intKey(-1) < intKey(0));
}

test "selectKth agrees with a sort, duplicates and adversarial shapes included" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (0..300) |round| {
        const n = 1 + r.uintLessThan(usize, 200);
        const xs = try a.alloc(f64, n);
        for (xs, 0..) |*x, i| x.* = switch (round % 4) {
            0 => r.float(f64),
            1 => @floatFromInt(r.uintLessThan(u32, 4)),
            2 => @floatFromInt(i),
            else => @floatFromInt(n - i),
        };
        const sorted = try a.dupe(f64, xs);
        std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
        const k = r.uintLessThan(usize, n);
        selectKth(xs, k);
        try testing.expectEqual(sorted[k], xs[k]);
        for (xs[0..k]) |x| try testing.expect(x <= xs[k]);
    }
}
