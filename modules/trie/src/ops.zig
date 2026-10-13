// SPDX-License-Identifier: MIT

//! ops — set operations over several frozen indexes (BurntSushi/fst's
//! `OpBuilder`, `src/raw/ops.rs`): union, intersection, difference and
//! symmetric difference of the KEY sets, each result key with the value of
//! every input that contributes to it.
//!
//! A k-way merge over one full-key `PrefixIterator` per index (no index is
//! copied): the smallest current key is taken, every index holding that same
//! key is gathered, and the operation decides whether the key is emitted.
//! Output is in ascending key order, so it can feed a `SortedBuilder` directly.
//!
//! Which keys are emitted (fst `raw/ops.rs`):
//!   * `union`                — a key present in at least one index (`Union`, 201-232);
//!   * `intersection`         — a key present in EVERY index (`Intersection`, 234-273);
//!   * `difference`           — a key of index 0 present in no other index
//!                              (`Difference`, 275-317);
//!   * `symmetric_difference` — a key present in an ODD number of indexes
//!                              (`SymmetricDifference`, 319-360; fst:
//!                              "for any number of streams, keys that occur in
//!                              an odd number of streams are returned").
//! `values` of an emitted key lists, in ascending index order, one entry for
//! every index that contains the key: all of them for union, intersection and
//! symmetric difference, exactly index 0 for difference (fst 301-302). fst
//! orders the entries of one key by (value, then heap order), not by index;
//! ascending index order is the one deliberate difference.
//!
//! An index with no keys contributes nothing; `difference` of zero indexes and
//! every operation over zero indexes yield nothing (fst's `difference` panics on
//! zero streams).

const std = @import("std");
const Allocator = std.mem.Allocator;
const query = @import("query.zig");
const Frozen = query.Frozen;
const PrefixIterator = query.PrefixIterator;
const QueryError = query.QueryError;

pub const SetOp = enum { @"union", intersection, difference, symmetric_difference };

/// One input's value for a key: `index` is the position in the `indexes` slice.
pub const IndexedValue = struct { index: u32, value: u32 };

/// One result key and the values of the indexes that contribute to it. Both
/// slices borrow the buffers given to `OpIterator.next`.
pub const OpItem = struct { key: []const u8, values: []const IndexedValue };

/// The most inputs one operation takes (the contributing set is a `u64` mask).
pub const max_indexes: usize = 64;

pub const OpError = QueryError || Allocator.Error || error{ValuesBufferTooSmall};

/// Start `op` over `indexes`. `max_visited` is the TOTAL node budget across all
/// inputs (0 = unbounded, for self-built buffers only — the same warning as
/// `Frozen.prefixIteratorBounded`); when it is spent `next` returns
/// `error.TooComplex` and `truncated()` is true. `indexes.len` 0 yields
/// nothing; more than `max_indexes` (64) is `error.TooManyIndexes`. `indexes`
/// is copied; the buffers behind it must outlive the iterator.
pub fn opIterator(
    gpa: Allocator,
    indexes: []const Frozen,
    op: SetOp,
    max_visited: usize,
) (QueryError || Allocator.Error || error{TooManyIndexes})!OpIterator {
    if (indexes.len > max_indexes) return error.TooManyIndexes;
    var self = OpIterator{ .gpa = gpa, .op = op, .max_visited = max_visited, .iters = try gpa.alloc(PrefixIterator, indexes.len) };
    if (indexes.len == 0) {
        self.done = true;
        return self;
    }
    var made: usize = 0;
    errdefer {
        for (self.iters[0..made]) |*it| it.deinit();
        gpa.free(self.iters);
    }
    while (made < indexes.len) : (made += 1) {
        self.iters[made] = try indexes[made].prefixIterator(gpa, "");
    }
    self.pending = lowBits(indexes.len);
    return self;
}

fn lowBits(n: usize) u64 {
    return if (n == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(n)) - 1;
}

pub const OpIterator = struct {
    gpa: Allocator,
    op: SetOp,
    max_visited: usize,
    iters: []PrefixIterator,
    /// Bit i: input i's current head was consumed (or never read) and must be
    /// advanced before the next key is chosen.
    pending: u64 = 0,
    /// Bit i: input i has a head (its current key is `iters[i].currentKey()`).
    has_head: u64 = 0,
    /// The value of each input's current head.
    head_values: [max_indexes]u32 = [_]u32{0} ** max_indexes,
    done: bool = false,
    spent: bool = false,

    pub fn deinit(self: *OpIterator) void {
        for (self.iters) |*it| it.deinit();
        self.gpa.free(self.iters);
        self.* = undefined;
    }

    /// True once the shared node budget ran out (`next` has then returned
    /// `error.TooComplex`).
    pub fn truncated(self: *const OpIterator) bool {
        return self.spent;
    }

    fn visitedTotal(self: *const OpIterator) usize {
        var n: usize = 0;
        for (self.iters) |*it| n += it.visited;
        return n;
    }

    /// Advance input `i` under what is left of the shared budget.
    fn advance(self: *OpIterator, i: usize) (QueryError || Allocator.Error)!void {
        const it = &self.iters[i];
        if (self.max_visited != 0) {
            // What is left of the shared budget bounds this input's walk; an
            // input that needs no further node still finishes normally.
            const used = self.visitedTotal();
            it.hard_stop = used >= self.max_visited;
            if (!it.hard_stop) it.max_visited = it.visited + (self.max_visited - used);
        }
        const bit = @as(u64, 1) << @intCast(i);
        const got = it.nextValue() catch |e| {
            if (e == error.TooComplex) return self.exhaust();
            return e;
        };
        if (got) |v| {
            self.has_head |= bit;
            self.head_values[i] = v;
        } else {
            self.has_head &= ~bit;
        }
    }

    fn exhaust(self: *OpIterator) error{TooComplex} {
        self.spent = true;
        self.done = true;
        return error.TooComplex;
    }

    /// The next result key (ascending), reconstructed into `key_buf`, with the
    /// contributing values in `values_buf` (at most one per input, so
    /// `indexes.len` entries always suffice). null when exhausted.
    /// `error.KeyTooLong` / `error.ValuesBufferTooSmall` leave the iterator
    /// where it was, so the same call with bigger buffers retries the key.
    pub fn next(self: *OpIterator, key_buf: []u8, values_buf: []IndexedValue) OpError!?OpItem {
        while (!self.done) {
            var p = self.pending;
            while (p != 0) {
                const i: usize = @ctz(p);
                p &= p - 1;
                try self.advance(i);
                self.pending &= ~(@as(u64, 1) << @intCast(i));
            }
            const all = lowBits(self.iters.len);
            // An exhausted input ends an operation that needs it: every key of
            // an intersection is in all inputs, every key of a difference in
            // input 0.
            if (self.op == .intersection and self.has_head != all) return self.finish();
            if (self.op == .difference and self.has_head & 1 == 0) return self.finish();
            if (self.has_head == 0) return self.finish();

            // The smallest current key, and every input holding it.
            var min_i: usize = @ctz(self.has_head);
            var eq: u64 = @as(u64, 1) << @intCast(min_i);
            var rest = self.has_head & (self.has_head - 1);
            while (rest != 0) {
                const i: usize = @ctz(rest);
                rest &= rest - 1;
                switch (std.mem.order(u8, self.iters[i].currentKey(), self.iters[min_i].currentKey())) {
                    .lt => {
                        min_i = i;
                        eq = @as(u64, 1) << @intCast(i);
                    },
                    .eq => eq |= @as(u64, 1) << @intCast(i),
                    .gt => {},
                }
            }

            const wanted = switch (self.op) {
                .@"union" => true,
                .intersection => eq == all,
                .difference => eq == 1,
                .symmetric_difference => @popCount(eq) % 2 == 1,
            };
            if (!wanted) {
                self.pending = eq;
                continue;
            }
            const key = self.iters[min_i].currentKey();
            if (key.len > key_buf.len) return error.KeyTooLong;
            if (@popCount(eq) > values_buf.len) return error.ValuesBufferTooSmall;
            @memcpy(key_buf[0..key.len], key);
            var n: usize = 0;
            var bits = eq;
            while (bits != 0) {
                const i: usize = @ctz(bits);
                bits &= bits - 1;
                values_buf[n] = .{ .index = @intCast(i), .value = self.head_values[i] };
                n += 1;
            }
            self.pending = eq;
            return .{ .key = key_buf[0..key.len], .values = values_buf[0..n] };
        }
        return null;
    }

    fn finish(self: *OpIterator) ?OpItem {
        self.done = true;
        return null;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const builder = @import("builder.zig");

fn buildSet(pairs: []const builder.Pair, fmt: builder.FreezeOptions) ![]u8 {
    return builder.freezeFromPairsWith(testing.allocator, testing.allocator, pairs, fmt);
}

/// Render an item as `key:i=v,i=v` for compact expectations.
fn render(w: *std.Io.Writer, it: OpItem) !void {
    try w.print("{s}:", .{it.key});
    for (it.values, 0..) |v, n| try w.print("{s}{d}={d}", .{ if (n == 0) "" else ",", v.index, v.value });
}

fn runOp(indexes: []const Frozen, op: SetOp, budget: usize, out: *std.Io.Writer.Allocating) !void {
    var it = try opIterator(testing.allocator, indexes, op, budget);
    defer it.deinit();
    var kb: [64]u8 = undefined;
    var vb: [max_indexes]IndexedValue = undefined;
    var first = true;
    while (try it.next(&kb, &vb)) |item| {
        if (!first) try out.writer.writeByte(' ');
        first = false;
        try render(&out.writer, item);
    }
}

test "the four operations over three indexes, by hand (v1, v2, v2 + ordinals)" {
    // A = {a, b, c, d}, B = {b, c, e}, C = {c, d, e, f}
    const a = [_]builder.Pair{ .{ .key = "a", .value = 1 }, .{ .key = "b", .value = 2 }, .{ .key = "c", .value = 3 }, .{ .key = "d", .value = 4 } };
    const b = [_]builder.Pair{ .{ .key = "b", .value = 20 }, .{ .key = "c", .value = 30 }, .{ .key = "e", .value = 50 } };
    const c = [_]builder.Pair{ .{ .key = "c", .value = 300 }, .{ .key = "d", .value = 400 }, .{ .key = "e", .value = 500 }, .{ .key = "f", .value = 600 } };
    const fmts = [_]builder.FreezeOptions{ .v1, .{ .v2 = .{} }, .{ .v2 = .{ .ordinals = true } } };
    for (fmts) |fmt| {
        const ba = try buildSet(&a, fmt);
        defer testing.allocator.free(ba);
        const bb = try buildSet(&b, fmt);
        defer testing.allocator.free(bb);
        const bc = try buildSet(&c, fmt);
        defer testing.allocator.free(bc);
        const idx = [_]Frozen{ try Frozen.load(ba), try Frozen.load(bb), try Frozen.load(bc) };

        const Case = struct { op: SetOp, want: []const u8 };
        const cases = [_]Case{
            .{ .op = .@"union", .want = "a:0=1 b:0=2,1=20 c:0=3,1=30,2=300 d:0=4,2=400 e:1=50,2=500 f:2=600" },
            .{ .op = .intersection, .want = "c:0=3,1=30,2=300" },
            // in A, in neither B nor C: a (b is in B, c in both, d in C)
            .{ .op = .difference, .want = "a:0=1" },
            // odd count: a (1), b (2: even), c (3: odd), d (2), e (2), f (1)
            .{ .op = .symmetric_difference, .want = "a:0=1 c:0=3,1=30,2=300 f:2=600" },
        };
        for (cases) |cs| {
            var out: std.Io.Writer.Allocating = .init(testing.allocator);
            defer out.deinit();
            try runOp(&idx, cs.op, 0, &out);
            try testing.expectEqualStrings(cs.want, out.written());
        }
    }
}

test "edge cases: no inputs, one input, an empty input, the empty key, too many inputs" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    for ([_]SetOp{ .@"union", .intersection, .difference, .symmetric_difference }) |op| {
        try runOp(&.{}, op, 0, &out);
        try testing.expectEqual(@as(usize, 0), out.written().len);
    }

    const some = try buildSet(&.{ .{ .key = "", .value = 7 }, .{ .key = "x", .value = 8 } }, .{ .v2 = .{} });
    defer testing.allocator.free(some);
    const none = try buildSet(&.{}, .{ .v2 = .{} });
    defer testing.allocator.free(none);
    const fs = try Frozen.load(some);
    const fn_ = try Frozen.load(none);

    // One input: union, difference and symmetric difference are the input; the
    // intersection of one set with itself is the set.
    for ([_]SetOp{ .@"union", .intersection, .difference, .symmetric_difference }) |op| {
        out.clearRetainingCapacity();
        try runOp(&.{fs}, op, 0, &out);
        try testing.expectEqualStrings(":0=7 x:0=8", out.written());
    }
    // An empty input: intersection is empty, difference by it changes nothing,
    // difference OF it is empty.
    out.clearRetainingCapacity();
    try runOp(&.{ fs, fn_ }, .intersection, 0, &out);
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try runOp(&.{ fs, fn_ }, .difference, 0, &out);
    try testing.expectEqualStrings(":0=7 x:0=8", out.written());
    out.clearRetainingCapacity();
    try runOp(&.{ fn_, fs }, .difference, 0, &out);
    try testing.expectEqual(@as(usize, 0), out.written().len);
    try runOp(&.{ fn_, fs }, .@"union", 0, &out);
    try testing.expectEqualStrings(":1=7 x:1=8", out.written());

    var many: [max_indexes + 1]Frozen = undefined;
    for (&many) |*m| m.* = fs;
    try testing.expectError(error.TooManyIndexes, opIterator(testing.allocator, &many, .@"union", 0));
    // Exactly 64 inputs work, and every one is listed for a shared key.
    var it = try opIterator(testing.allocator, many[0..max_indexes], .intersection, 0);
    defer it.deinit();
    var kb: [4]u8 = undefined;
    var vb: [max_indexes]IndexedValue = undefined;
    const item = (try it.next(&kb, &vb)).?;
    try testing.expectEqual(@as(usize, max_indexes), item.values.len);
    try testing.expectEqual(@as(u32, 63), item.values[63].index);
}

test "KeyTooLong and ValuesBufferTooSmall leave the iterator where it was" {
    const a = try buildSet(&.{.{ .key = "hello", .value = 1 }}, .{ .v2 = .{} });
    defer testing.allocator.free(a);
    const fa = try Frozen.load(a);
    var it = try opIterator(testing.allocator, &.{ fa, fa }, .@"union", 0);
    defer it.deinit();
    var small: [4]u8 = undefined;
    var big: [8]u8 = undefined;
    var one: [1]IndexedValue = undefined;
    var two: [2]IndexedValue = undefined;
    try testing.expectError(error.KeyTooLong, it.next(&small, &two));
    try testing.expectError(error.ValuesBufferTooSmall, it.next(&big, &one));
    const item = (try it.next(&big, &two)).?;
    try testing.expectEqualStrings("hello", item.key);
    try testing.expectEqual(@as(usize, 2), item.values.len);
    try testing.expect((try it.next(&big, &two)) == null);
}

test "the budget is shared by all inputs and reported" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pa = try arena.alloc(builder.Pair, 300);
    const pb = try arena.alloc(builder.Pair, 300);
    for (0..300) |i| {
        pa[i] = .{ .key = try std.fmt.allocPrint(arena, "k{d:0>5}", .{i * 2}), .value = @intCast(i) };
        pb[i] = .{ .key = try std.fmt.allocPrint(arena, "k{d:0>5}", .{i * 2 + 1}), .value = @intCast(i) };
    }
    const ba = try buildSet(pa, .{ .v2 = .{} });
    defer testing.allocator.free(ba);
    const bb = try buildSet(pb, .{ .v2 = .{} });
    defer testing.allocator.free(bb);
    const idx = [_]Frozen{ try Frozen.load(ba), try Frozen.load(bb) };

    // Measure the work an unbounded union needs...
    var kb: [16]u8 = undefined;
    var vb: [2]IndexedValue = undefined;
    var need: usize = 0;
    {
        var it = try opIterator(testing.allocator, &idx, .@"union", 0);
        defer it.deinit();
        var n: usize = 0;
        while (try it.next(&kb, &vb)) |_| n += 1;
        try testing.expectEqual(@as(usize, 600), n);
        for (it.iters) |*sub| need += sub.visited;
        try testing.expect(!it.truncated());
    }
    // ...exactly that much suffices, one less does not (and is reported).
    {
        var it = try opIterator(testing.allocator, &idx, .@"union", need);
        defer it.deinit();
        var n: usize = 0;
        while (try it.next(&kb, &vb)) |_| n += 1;
        try testing.expectEqual(@as(usize, 600), n);
        try testing.expect(!it.truncated());
    }
    {
        var it = try opIterator(testing.allocator, &idx, .@"union", need - 1);
        defer it.deinit();
        var n: usize = 0;
        var cut = false;
        while (true) {
            const r = it.next(&kb, &vb) catch |e| {
                try testing.expectEqual(error.TooComplex, e);
                cut = true;
                break;
            };
            if (r == null) break;
            n += 1;
        }
        try testing.expect(cut and it.truncated());
        try testing.expect(n < 600);
        var total: usize = 0;
        for (it.iters) |*sub| total += sub.visited;
        try testing.expect(total <= need - 1); // the TOTAL, not per input
        // Once spent, the iterator stays finished.
        try testing.expect((try it.next(&kb, &vb)) == null);
    }
}

test "a union streams straight into SortedBuilder and equals the union index" {
    const a = [_]builder.Pair{ .{ .key = "praha", .value = 1 }, .{ .key = "plzen", .value = 2 }, .{ .key = "brno", .value = 3 } };
    const b = [_]builder.Pair{ .{ .key = "praha", .value = 10 }, .{ .key = "ostrava", .value = 4 } };
    const ba = try buildSet(&a, .{ .v2 = .{} });
    defer testing.allocator.free(ba);
    const bb = try buildSet(&b, .{ .v2 = .{} });
    defer testing.allocator.free(bb);
    const idx = [_]Frozen{ try Frozen.load(ba), try Frozen.load(bb) };

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sb = try @import("stream.zig").SortedBuilder.init(testing.allocator, &out.writer, .{});
    defer sb.deinit();
    var it = try opIterator(testing.allocator, &idx, .@"union", 0);
    defer it.deinit();
    var kb: [32]u8 = undefined;
    var vb: [2]IndexedValue = undefined;
    while (try it.next(&kb, &vb)) |item| try sb.insert(item.key, item.values[item.values.len - 1].value); // the later input wins
    try sb.finish();

    const merged = try Frozen.loadVerified(out.written());
    try testing.expectEqual(@as(u64, 4), merged.keyCount());
    try testing.expectEqual(@as(?u32, 10), try merged.lookup("praha"));
    try testing.expectEqual(@as(?u32, 4), try merged.lookup("ostrava"));
    try testing.expectEqual(@as(?u32, 2), try merged.lookup("plzen"));
    try testing.expectEqual(@as(?u32, null), try merged.lookup("kladno"));
}
