// SPDX-License-Identifier: MIT
//! Block splitting (RFC 7932 §6): cut one category's symbol stream —
//! literals, insert-and-copy symbols, or distance symbols — into blocks, each
//! with a block type, so that each type's own prefix code fits the parts of
//! the stream it covers. A font, an executable or an archive has sections
//! whose statistics differ (outlines, tables, strings); one code per
//! meta-block averages them.
//!
//! The method: start from `k` histograms sampled at spread-out places, then
//! a few rounds of (1) the cheapest assignment of every symbol to a
//! histogram, with a fixed price for switching from one to another (a
//! Viterbi pass over `k` states), and (2) histograms rebuilt from that
//! assignment. Histograms that cost no more coded together are then merged
//! and the assignment is made once more. The result is a list of blocks —
//! runs of one type — with the first block of type 0, as the format starts
//! every category in type 0.
//!
//! Deterministic: the sampling uses a fixed-seed generator, so the same
//! input gives the same split (the encoder's output is pinned by digests).

const std = @import("std");

/// Most histograms the assignment pass tracks: one bit each per symbol in
/// the switch mask.
pub const max_histograms = 64;

pub const Params = struct {
    /// About this many symbols per starting histogram.
    per_histogram: u32,
    /// Symbols in each sampled window.
    sample: u32,
    /// Estimated bits a block switch costs (type and length codes): the
    /// price the assignment pays to leave a histogram.
    switch_cost: f32,
    /// Assignment rounds.
    rounds: u32,
    /// Streams shorter than this are one block.
    min_symbols: u32 = 512,
    /// Most starting histograms (at most `max_histograms`).
    histograms: u32 = max_histograms,
};

pub const Split = struct {
    /// Block type of each block, in stream order; `types[0] == 0`.
    types: []u8,
    /// Symbols in each block (all > 0); they add up to the stream length.
    lens: []u32,
    ntypes: u32,

    pub fn deinit(s: *Split, gpa: std.mem.Allocator) void {
        gpa.free(s.types);
        gpa.free(s.lens);
        s.* = undefined;
    }

    /// One block of type 0 over `n` symbols.
    pub fn single(gpa: std.mem.Allocator, n: usize) std.mem.Allocator.Error!Split {
        const types = try gpa.alloc(u8, 1);
        errdefer gpa.free(types);
        const lens = try gpa.alloc(u32, 1);
        types[0] = 0;
        lens[0] = @intCast(n);
        return .{ .types = types, .lens = lens, .ntypes = 1 };
    }
};

/// Split `syms` (each `< alphabet`). One block when the stream is short or
/// no split pays by the estimate.
pub fn split(comptime T: type, gpa: std.mem.Allocator, syms: []const T, alphabet: u32, p: Params) std.mem.Allocator.Error!Split {
    const n = syms.len;
    if (n < p.min_symbols or n == 0) return Split.single(gpa, n);
    const k: u32 = @intCast(@min(n / p.per_histogram + 1, p.histograms, max_histograms));
    if (k < 2) return Split.single(gpa, n);

    const hist = try gpa.alloc(u32, @as(usize, k) * alphabet);
    defer gpa.free(hist);
    // Per symbol, its bits under each histogram (`lanes`-padded rows).
    const bits = try gpa.alloc(u32, @as(usize, alphabet) * padded(k));
    defer gpa.free(bits);
    const ids = try gpa.alloc(u8, n);
    defer gpa.free(ids);
    const switched = try gpa.alloc(u64, n);
    defer gpa.free(switched);
    const from = try gpa.alloc(u8, n);
    defer gpa.free(from);

    // Starting histograms: histogram j from a window at a random place in
    // the j-th of k equal parts, then more random windows spread over all.
    @memset(hist, 0);
    var prng = std.Random.DefaultPrng.init(0x62726f746c69);
    const r = prng.random();
    const part = n / k;
    const win = @min(p.sample, n);
    for (0..k) |j| {
        const at = j * part + r.uintLessThan(usize, @max(part -| win, 1));
        addWindow(T, hist[j * alphabet ..][0..alphabet], syms, at, win);
    }
    const extra = 2 * n / @max(win, 1);
    for (0..extra) |i| {
        const at = r.uintLessThan(usize, n - win + 1);
        const j = i % k;
        addWindow(T, hist[j * alphabet ..][0..alphabet], syms, at, win);
    }

    var nh = k;
    for (0..p.rounds) |_| {
        priceAll(hist, nh, alphabet, bits);
        assign(T, syms, bits, nh, p.switch_cost, ids, switched, from);
        nh = rebuild(T, syms, ids, hist, alphabet, nh);
        if (nh == 1) return Split.single(gpa, n);
    }

    // Merge histograms that cost no more coded as one, then assign once
    // more against the merged ones.
    nh = try mergeHistograms(gpa, hist, alphabet, nh, nh, null);
    if (nh == 1) return Split.single(gpa, n);
    priceAll(hist, nh, alphabet, bits);
    assign(T, syms, bits, nh, p.switch_cost, ids, switched, from);

    return blocksOf(gpa, ids);
}

fn addWindow(comptime T: type, h: []u32, syms: []const T, at: usize, len: usize) void {
    for (syms[at..][0..len]) |s| h[s] += 1;
}

/// Histograms the assignment pass handles at once.
const lanes = 8;
/// Costs in the assignment pass: bits in fixed point (`one` = 1 bit), so
/// the per-symbol minimum is integer lanes — a float minimum is lowered
/// lane by lane for its NaN rules (perf annotate, 2026-10-15).
const V = @Vector(lanes, u32);
const one = 1 << 12;
/// A padding lane's price: out of reach, and no sum of costs overflows.
const out_of_reach = 1 << 28;

fn padded(nh: u32) usize {
    return std.mem.alignForward(usize, nh, lanes);
}

/// Bits of each symbol under each of the `nh` histograms: `-log2` of its
/// share, a symbol the histogram never saw priced two bits above one it saw
/// once, in `one`s. `bits[s * padded(nh) + j]`; the padding lanes are
/// priced out of reach.
fn priceAll(hist: []const u32, nh: u32, alphabet: u32, bits: []u32) void {
    const np = padded(nh);
    for (0..np) |j| {
        if (j >= nh) {
            for (0..alphabet) |sym| bits[sym * np + j] = out_of_reach;
            continue;
        }
        const h = hist[j * alphabet ..][0..alphabet];
        var total: u64 = 0;
        for (h) |c| total += c;
        const lt = log2f(total + 1);
        for (h, 0..) |c, sym| {
            const b = if (c == 0) lt + 2 else lt - log2f(c);
            bits[sym * np + j] = @intFromFloat(@round(b * one));
        }
    }
}

/// The cheapest assignment of `syms` to `nh` histograms when leaving one
/// costs `switch_cost` bits (a Viterbi pass), `lanes` histograms per vector
/// step. `ids` gets each symbol's histogram.
fn assign(
    comptime T: type,
    syms: []const T,
    bits: []const u32,
    nh: u32,
    switch_cost: f32,
    ids: []u8,
    /// Per symbol: bit j set when the best path ending in histogram j there
    /// switched in from `from` (the cheapest at the symbol before).
    switched: []u64,
    from: []u8,
) void {
    const np = padded(nh);
    const chunks = np / lanes;
    var cost: [max_histograms / lanes]V = @splat(@splat(0));
    const sw: V = @splat(@intFromFloat(@round(switch_cost * one)));
    var best: u8 = 0;
    for (syms, 0..) |s, i| {
        const row = bits[@as(usize, s) * np ..][0..np];
        var mask: u64 = 0;
        var vmin: V = @splat(std.math.maxInt(u32));
        for (0..chunks) |c| {
            // Stay (cost) or switch in from the cheapest (0 after the
            // normalisation below) — at the first symbol neither costs.
            var x = cost[c];
            if (i != 0) {
                const over = x > sw;
                x = @select(u32, over, sw, x);
                mask |= @as(u64, @as(u8, @bitCast(over))) << @intCast(c * lanes);
            }
            x += row[c * lanes ..][0..lanes].*;
            cost[c] = x;
            vmin = @min(vmin, x);
        }
        const min = @reduce(.Min, vmin);
        // The first histogram at the minimum.
        const vm: V = @splat(min);
        var arg: u8 = 0;
        for (0..chunks) |c| {
            const eq: u8 = @bitCast(cost[c] == vm);
            if (eq != 0) {
                arg = @intCast(c * lanes + @ctz(eq));
                break;
            }
        }
        for (cost[0..chunks]) |*c| c.* -= vm;
        switched[i] = mask;
        from[i] = best;
        best = arg;
    }
    // Back from the cheapest end.
    var cur = best;
    var i = syms.len;
    while (i > 0) {
        i -= 1;
        ids[i] = cur;
        if (switched[i] & (@as(u64, 1) << @intCast(cur)) != 0) cur = from[i];
    }
}

/// Histograms from the assignment, the unused dropped and the rest
/// renumbered (`ids` rewritten); returns how many are left.
fn rebuild(comptime T: type, syms: []const T, ids: []u8, hist: []u32, alphabet: u32, nh: u32) u32 {
    var renum: [max_histograms]u8 = @splat(0xff);
    var n: u8 = 0;
    for (ids) |*id| {
        if (renum[id.*] == 0xff) {
            renum[id.*] = n;
            n += 1;
        }
        id.* = renum[id.*];
    }
    _ = nh;
    @memset(hist[0 .. @as(usize, n) * alphabet], 0);
    for (syms, ids) |s, id| hist[@as(usize, id) * alphabet + s] += 1;
    return n;
}

/// `log2(n)` for small counts from a table: `compiler_rt`'s `log2f` per
/// symbol and histogram was most of a split's time.
const log2_table: [4096]f32 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [4096]f32 = undefined;
    t[0] = 0;
    for (1..4096) |i| t[i] = @floatCast(@log2(@as(f64, @floatFromInt(i))));
    break :blk t;
};

fn log2f(n: u64) f32 {
    if (n < log2_table.len) return log2_table[@intCast(n)];
    return @log2(@as(f32, @floatFromInt(n)));
}

/// `n * log2(n)` for small counts, where most counts fall.
const nlog2n_table: [4096]f32 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [4096]f32 = undefined;
    t[0] = 0;
    for (1..4096) |i| {
        const x: f64 = @floatFromInt(i);
        t[i] = @floatCast(x * @log2(x));
    }
    break :blk t;
};

fn nlog2n(n: u64) f64 {
    if (n < nlog2n_table.len) return nlog2n_table[@intCast(n)];
    const x: f64 = @floatFromInt(n);
    return x * @log2(x);
}

/// Estimated bits of coding `h` with its own prefix code: the entropy plus a
/// header guess per symbol used.
fn codeCost(h: []const u32) f64 {
    var total: u64 = 0;
    var used: u32 = 0;
    var sum: f64 = 0;
    for (h) |c| {
        if (c == 0) continue;
        total += c;
        used += 1;
        sum += nlog2n(c);
    }
    if (total == 0) return 0;
    return nlog2n(total) - sum + 40 + 5 * @as(f64, @floatFromInt(used));
}

fn unionCost(a: []const u32, b: []const u32) f64 {
    var total: u64 = 0;
    var used: u32 = 0;
    var sum: f64 = 0;
    for (a, b) |x, y| {
        const c = @as(u64, x) + y;
        if (c == 0) continue;
        total += c;
        used += 1;
        sum += nlog2n(c);
    }
    if (total == 0) return 0;
    return nlog2n(total) - sum + 40 + 5 * @as(f64, @floatFromInt(used));
}

/// Merge pairs of the `nh` histograms in `hist` (`alphabet` counts each)
/// while coding them as one costs fewer estimated bits — or more than `cap`
/// are left — cheapest merge first. The survivors are packed to the front
/// in their old order; `remap[j]` (when given) gets histogram j's new index.
/// Returns how many are left.
pub fn mergeHistograms(gpa: std.mem.Allocator, hist: []u32, alphabet: u32, nh: u32, cap: u32, remap: ?[]u32) std.mem.Allocator.Error!u32 {
    const cost = try gpa.alloc(f64, nh);
    defer gpa.free(cost);
    // delta[a * nh + b] for a < b; each row keeps its cheapest partner.
    const delta = try gpa.alloc(f32, @as(usize, nh) * nh);
    defer gpa.free(delta);
    const alive = try gpa.alloc(bool, nh);
    defer gpa.free(alive);
    const into = try gpa.alloc(u32, nh);
    defer gpa.free(into);
    const row_best = try gpa.alloc(u32, nh);
    defer gpa.free(row_best);
    for (0..nh) |j| {
        cost[j] = codeCost(hist[j * alphabet ..][0..alphabet]);
        alive[j] = true;
        into[j] = @intCast(j);
    }
    for (0..nh) |a| {
        for (a + 1..nh) |b| delta[a * nh + b] = @floatCast(unionCost(hist[a * alphabet ..][0..alphabet], hist[b * alphabet ..][0..alphabet]) - cost[a] - cost[b]);
    }
    for (0..nh) |a| row_best[a] = rowBest(delta, alive, nh, a);

    var left = nh;
    while (left > 1) {
        var best: f32 = std.math.inf(f32);
        var ba: usize = 0;
        for (0..nh) |a| {
            if (!alive[a] or row_best[a] == nh) continue;
            const d = delta[a * nh + row_best[a]];
            if (d < best) {
                best = d;
                ba = a;
            }
        }
        if (best == std.math.inf(f32)) break;
        if (best >= 0 and left <= cap) break;
        const bb: usize = row_best[ba];
        const ha = hist[ba * alphabet ..][0..alphabet];
        for (ha, hist[bb * alphabet ..][0..alphabet]) |*x, y| x.* += y;
        cost[ba] = codeCost(ha);
        alive[bb] = false;
        into[bb] = @intCast(ba);
        left -= 1;
        for (0..nh) |x| {
            if (x == ba or !alive[x]) continue;
            const d: f32 = @floatCast(unionCost(ha, hist[x * alphabet ..][0..alphabet]) - cost[ba] - cost[x]);
            if (x < ba) delta[x * nh + ba] = d else delta[ba * nh + x] = d;
        }
        // Rows that pointed at either of the two, or that see the merged
        // one cheaper now, look again.
        for (0..nh) |x| {
            if (!alive[x]) continue;
            if (x == ba or row_best[x] == ba or row_best[x] == bb or (x < ba and delta[x * nh + ba] < delta[x * nh + row_best[x]])) {
                row_best[x] = rowBest(delta, alive, nh, x);
            }
        }
    }
    // Pack the survivors to the front.
    var pos = try gpa.alloc(u32, nh);
    defer gpa.free(pos);
    var n: u32 = 0;
    for (0..nh) |j| {
        if (!alive[j]) continue;
        if (n != j) @memcpy(hist[n * alphabet ..][0..alphabet], hist[j * alphabet ..][0..alphabet]);
        pos[j] = n;
        n += 1;
    }
    if (remap) |r| {
        for (0..nh) |j| {
            var t = j;
            while (!alive[t]) t = into[t];
            r[j] = pos[t];
        }
    }
    return n;
}

/// The alive partner `b > a` with the smallest `delta`, or `nh`.
fn rowBest(delta: []const f32, alive: []const bool, nh: u32, a: usize) u32 {
    var best: f32 = std.math.inf(f32);
    var arg: u32 = nh;
    for (a + 1..nh) |b| {
        if (alive[b] and delta[a * nh + b] < best) {
            best = delta[a * nh + b];
            arg = @intCast(b);
        }
    }
    return arg;
}

/// The runs of `ids` as blocks, types numbered in order of first use.
fn blocksOf(gpa: std.mem.Allocator, ids: []const u8) std.mem.Allocator.Error!Split {
    var nblocks: usize = 1;
    for (ids[1..], ids[0 .. ids.len - 1]) |a, b| nblocks += @intFromBool(a != b);
    const types = try gpa.alloc(u8, nblocks);
    errdefer gpa.free(types);
    const lens = try gpa.alloc(u32, nblocks);
    var renum: [max_histograms]u8 = @splat(0xff);
    var nt: u8 = 0;
    var b: usize = 0;
    var start: usize = 0;
    for (ids, 0..) |id, i| {
        if (i + 1 == ids.len or ids[i + 1] != id) {
            if (renum[id] == 0xff) {
                renum[id] = nt;
                nt += 1;
            }
            types[b] = renum[id];
            lens[b] = @intCast(i + 1 - start);
            b += 1;
            start = i + 1;
        }
    }
    return .{ .types = types, .lens = lens, .ntypes = nt };
}

const testing = std.testing;

test "split: two different halves become two block types" {
    const gpa = testing.allocator;
    var syms: [8192]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(1);
    for (&syms, 0..) |*s, i| s.* = if (i < 4096) prng.random().uintLessThan(u8, 8) else 200 + prng.random().uintLessThan(u8, 8);
    var s = try split(u8, gpa, &syms, 256, .{ .per_histogram = 512, .sample = 64, .switch_cost = 28, .rounds = 3 });
    defer s.deinit(gpa);
    try testing.expectEqual(@as(u32, 2), s.ntypes);
    try testing.expectEqual(@as(usize, 2), s.lens.len);
    try testing.expectEqual(@as(u8, 0), s.types[0]);
    try testing.expectEqual(@as(u32, 4096), s.lens[0]);
    try testing.expectEqual(@as(u32, 4096), s.lens[1]);
}

test "split: a uniform stream stays one block" {
    const gpa = testing.allocator;
    var syms: [8192]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(2);
    for (&syms) |*s| s.* = prng.random().uintLessThan(u8, 16);
    var s = try split(u8, gpa, &syms, 256, .{ .per_histogram = 512, .sample = 64, .switch_cost = 28, .rounds = 3 });
    defer s.deinit(gpa);
    try testing.expectEqual(@as(u32, 1), s.ntypes);
    try testing.expectEqual(@as(u32, 8192), s.lens[0]);
}

test "split: blocks cover the stream, first type 0, alternating sections" {
    const gpa = testing.allocator;
    var syms: [20000]u16 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    for (&syms, 0..) |*s, i| {
        const sect = (i / 2500) % 2;
        s.* = @intCast(sect * 300 + prng.random().uintLessThan(u16, 20));
    }
    var s = try split(u16, gpa, &syms, 704, .{ .per_histogram = 512, .sample = 40, .switch_cost = 14, .rounds = 3 });
    defer s.deinit(gpa);
    var total: usize = 0;
    for (s.lens) |l| {
        try testing.expect(l > 0);
        total += l;
    }
    try testing.expectEqual(syms.len, total);
    try testing.expectEqual(@as(u8, 0), s.types[0]);
    try testing.expectEqual(@as(u32, 2), s.ntypes);
    try testing.expectEqual(@as(usize, 8), s.lens.len);
    for (s.types, 0..) |t, b| try testing.expectEqual(@as(u8, @intCast(b % 2)), t);
}
