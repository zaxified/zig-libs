// SPDX-License-Identifier: MIT
//! Shared machinery of the keyed verbs: a canonical, injective key encoding, a
//! factorizer (row -> dense group id, pandas' `factorize` shape) and a stable
//! radix sort. Not a public namespace: `aggregate`, `pivot`, `join`, `distinct`,
//! `sort` and `window` sit on it.
//!
//! Key equality is the one `Value.order` gives, by canonical form: int 1, float
//! 1.0 and decimal 1 are one key (-0.0 is 0), text "1" and "i1" are other keys,
//! and text is length-prefixed, so no cell content can make two different
//! composite keys collide (the 0x1f separator used before could).

const std = @import("std");
const ds = @import("dataset");
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
inline fn exactInt(v: Value) ?i64 {
    switch (v) {
        .int => |i| return i,
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

/// Append `v`'s canonical bytes. Self-delimiting, so a composite key is simply
/// the concatenation of its cells' encodings.
pub fn encode(a: std.mem.Allocator, buf: *std.ArrayList(u8), v: Value, nan: Nan) error{OutOfMemory}!void {
    if (exactInt(v)) |i| {
        try buf.append(a, 'i');
        try buf.appendSlice(a, std.mem.asBytes(&i));
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
            const f = v.asFloat().?;
            if ((Value{ .float = f }).order(v) == .eq) {
                try buf.append(a, 'f');
                try buf.appendSlice(a, std.mem.asBytes(&f));
            } else {
                try buf.append(a, 'd');
                try buf.appendSlice(a, std.mem.asBytes(&r));
            }
        },
        .int => unreachable, // exactInt took it
    }
}

inline fn hashInt(x: i64) u64 {
    const u: u64 = @bitCast(x);
    return (u ^ (u >> 32)) *% 0x9E3779B97F4A7C15;
}

const IntSlot = struct { key: i64 = 0, id: u32 = 0 }; // id + 1; 0 = empty
const ByteSlot = struct { h: u32 = 0, id: u32 = 0 }; // id + 1; 0 = empty

inline fn mum(x: u64, y: u64) u64 {
    const m = @as(u128, x) *% y;
    return @truncate(m ^ (m >> 64));
}

/// A short text in a word's time (the wyhash mix); longer ones go to `Wyhash`.
inline fn hashText(t: []const u8) u64 {
    const n = t.len;
    const k0: u64 = 0xa0761d6478bd642f;
    const k1: u64 = 0xe7037ed1a0b428db;
    if (n > 16) return std.hash.Wyhash.hash(0, t);
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
    return mum(lo ^ k0 ^ n, hi ^ k1);
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

    const initial_slots = 64;

    pub fn initInt(a: std.mem.Allocator, expect: usize) Error!Table {
        const s = try a.alloc(IntSlot, capacityFor(expect));
        @memset(s, .{});
        return .{ .int_slots = s };
    }

    pub fn initBytes(a: std.mem.Allocator, expect: usize) Error!Table {
        const s = try a.alloc(ByteSlot, capacityFor(expect));
        @memset(s, .{});
        return .{ .byte_slots = s };
    }

    /// A first guess; the tables grow from it. Not `rows`: a low-cardinality
    /// key would touch a far bigger table than it needs.
    fn capacityFor(expect: usize) usize {
        return std.math.ceilPowerOfTwo(usize, @max(initial_slots, @min(expect, 1 << 12))) catch initial_slots;
    }

    pub inline fn getOrPutInt(t: *Table, a: std.mem.Allocator, k: i64) Error!u32 {
        if ((@as(usize, t.count) + 1) * 2 > t.int_slots.len) try t.growInt(a);
        const mask = t.int_slots.len - 1;
        var i: usize = @intCast(hashInt(k) >> 20 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = &t.int_slots[i];
            if (s.id == 0) {
                t.count += 1;
                s.* = .{ .key = k, .id = t.count };
                return t.count - 1;
            }
            if (s.key == k) return s.id - 1;
        }
    }

    pub inline fn getInt(t: *const Table, k: i64) ?u32 {
        const mask = t.int_slots.len - 1;
        var i: usize = @intCast(hashInt(k) >> 20 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = t.int_slots[i];
            if (s.id == 0) return null;
            if (s.key == k) return s.id - 1;
        }
    }

    fn growInt(t: *Table, a: std.mem.Allocator) Error!void {
        const n = try a.alloc(IntSlot, t.int_slots.len * 2);
        @memset(n, .{});
        const mask = n.len - 1;
        for (t.int_slots) |s| {
            if (s.id == 0) continue;
            var i: usize = @intCast(hashInt(s.key) >> 20 & mask);
            while (n[i].id != 0) i = (i + 1) & mask;
            n[i] = s;
        }
        a.free(t.int_slots);
        t.int_slots = n;
    }

    pub fn getOrPutBytes(t: *Table, a: std.mem.Allocator, key: []const u8) Error!u32 {
        if ((@as(usize, t.count) + 1) * 2 > t.byte_slots.len) try t.growBytes(a);
        const h64 = std.hash.Wyhash.hash(0, key);
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
        }
    }

    pub fn getBytes(t: *const Table, key: []const u8) ?u32 {
        const h64 = std.hash.Wyhash.hash(0, key);
        const h: u32 = @truncate(h64 >> 32);
        const mask = t.byte_slots.len - 1;
        var i: usize = @intCast(h64 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = t.byte_slots[i];
            if (s.id == 0) return null;
            if (s.h == h and std.mem.eql(u8, t.keyOf(s.id - 1), key)) return s.id - 1;
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
            const h64 = std.hash.Wyhash.hash(0, t.keyOf(s.id - 1));
            var i: usize = @intCast(h64 & mask);
            while (n[i].id != 0) i = (i + 1) & mask;
            n[i] = s;
        }
        a.free(t.byte_slots);
        t.byte_slots = n;
    }

    pub inline fn getText(t: *const Table, key: []const u8) ?u32 {
        const h64 = hashText(key);
        const h: u32 = @truncate(h64 >> 32);
        const mask = t.byte_slots.len - 1;
        var i: usize = @intCast(h64 & mask);
        while (true) : (i = (i + 1) & mask) {
            const s = t.byte_slots[i];
            if (s.id == 0) return null;
            if (s.h == h and std.mem.eql(u8, t.texts[t.text_firsts[s.id - 1]], key)) return s.id - 1;
        }
    }

    /// The id of `row`'s key, if present. Works in every shape: an int or text
    /// table holds only such keys, so any other cell is simply absent.
    pub fn lookup(t: *const Table, a: std.mem.Allocator, scratch: *std.ArrayList(u8), row: []const Value, idxs: []const usize, nan: Nan) Error!?u32 {
        if (t.int_slots.len != 0) {
            const k = exactInt(row[idxs[0]]) orelse return null;
            return t.getInt(k);
        }
        if (t.text_mode) {
            const c = row[idxs[0]];
            return if (c == .text) t.getText(c.text) else null;
        }
        if (idxs.len == 0) return if (t.count > 0) 0 else null;
        scratch.clearRetainingCapacity();
        for (idxs) |ci| try encode(a, scratch, row[ci], nan);
        return t.getBytes(scratch.items);
    }
};

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
pub fn factorizeInts(a: std.mem.Allocator, ints: []const i64) Error!Factors {
    try checkRows(ints.len);
    const ids = try a.alloc(u32, ints.len);
    var firsts: std.ArrayList(u32) = .empty;
    var t = try Table.initInt(a, ints.len);
    for (ints, ids, 0..) |x, *id, ri| {
        if (ri + prefetch_ahead < ints.len) {
            const h: usize = @intCast(hashInt(ints[ri + prefetch_ahead]) >> 20 & (t.int_slots.len - 1));
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
    for (texts, ids, 0..) |x, *id, ri| {
        if ((@as(usize, count) + 1) * 2 > slots.len) {
            const n = try a.alloc(ByteSlot, slots.len * 2);
            @memset(n, .{});
            const nmask = n.len - 1;
            for (slots) |s| {
                if (s.id == 0) continue;
                var i: usize = @intCast(hashText(texts[firsts.items[s.id - 1]]) & nmask);
                while (n[i].id != 0) i = (i + 1) & nmask;
                n[i] = s;
            }
            a.free(slots);
            slots = n;
        }
        const h64 = hashText(x);
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
        }
    }
    const fs = try firsts.toOwnedSlice(a);
    return .{ .ids = ids, .firsts = fs, .table = .{ .byte_slots = slots, .text_mode = true, .texts = texts, .text_firsts = fs, .count = count } };
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
    var t = try Table.initBytes(a, rows.len);
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
        keyColPut(&col, a, i, r[ci]);
    }
    return factorizeCol(a, col, rows, idxs, nan);
}

/// `hits[i]` = the id of `rows[i]`'s key, or `none`. `skip_missing`: a missing key
/// cell matches nothing. The int shape extracts the keys first and prefetches.
pub const none: u32 = std.math.maxInt(u32);

pub fn probeAll(a: std.mem.Allocator, t: *const Table, rows: []const []const Value, idxs: []const usize, nan: Nan, skip_missing: bool, hits: []u32) Error!void {
    if (t.int_slots.len != 0 and idxs.len == 1) {
        const ci = idxs[0];
        const xs = try a.alloc(i64, rows.len);
        defer a.free(xs);
        const ok = try a.alloc(bool, rows.len);
        defer a.free(ok);
        for (rows, xs, ok) |r, *x, *o| {
            const e = exactInt(r[ci]);
            o.* = e != null;
            x.* = e orelse 0;
        }
        const mask = t.int_slots.len - 1;
        for (xs, ok, hits, 0..) |x, o, *h, i| {
            if (i + prefetch_ahead < xs.len) {
                @prefetch(&t.int_slots[@intCast(hashInt(xs[i + prefetch_ahead]) >> 20 & mask)], .{});
            }
            h.* = if (o) t.getInt(x) orelse none else none;
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
