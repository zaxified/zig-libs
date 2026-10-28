// SPDX-License-Identifier: MIT

//! A prefilter for a small set of literal prefixes (`a|b|c` of literals,
//! `(?i)abc`, `foo\d|bar\d`): "Teddy", Geoff Langdale's SIMD literal search
//! from Intel's Hyperscan, as the Rust `aho-corasick` crate's documentation
//! describes it (written from that description; no source ported).
//!
//! The prefixes are spread over eight buckets, one bit each. For each of the
//! first `masks` byte positions, two 16-entry tables give, by the low and by
//! the high nibble of the byte there, the buckets holding a prefix whose
//! byte at that position has that nibble. A position whose bucket bits
//! survive the AND over every table is a candidate, checked against those
//! buckets' prefixes in full; 32 positions are looked up at a time.

const std = @import("std");
const builtin = @import("builtin");
const syntax = @import("syntax.zig");

const Inst = syntax.Inst;
const Range = syntax.Range;

/// Prefixes kept, at most; past it the prefixes are cut shorter, and below
/// two bytes there is no `Teddy`.
pub const max_pats = 32;
/// Bytes kept of each prefix, at most.
pub const max_len = 8;
/// A class of more code points than this ends a prefix.
const max_class = 4;

const lanes = 32;
const V = @Vector(lanes, u8);

const has_avx2 = builtin.cpu.arch == .x86_64 and std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

pub const Teddy = struct {
    /// `lo[j][n]`: the buckets with a prefix whose byte j has low nibble n;
    /// `hi` the same by the high nibble.
    lo: [3][16]u8,
    hi: [3][16]u8,
    /// Byte positions looked up: 2 or 3, no more than the shortest prefix.
    masks: u8,
    /// The prefixes, sorted; bucket b holds `pats[start[b]..start[b + 1]]`.
    pats: [max_pats][max_len]u8,
    lens: [max_pats]u8,
    n: u8,
    start: [9]u8,

    /// The first position at or after `pos` where `input` begins with one
    /// of the prefixes. `noinline`: kept out of `Prefilter.next`, whose
    /// literal search it slowed by ~5 % inlined (bench `lit_all`).
    pub noinline fn find(t: *const Teddy, input: []const u8, pos: usize) ?usize {
        return switch (t.masks) {
            inline 2, 3 => |m| t.findMasks(m, input, pos),
            else => unreachable,
        };
    }

    fn findMasks(t: *const Teddy, comptime m: usize, input: []const u8, pos: usize) ?usize {
        var lo: [m]V = undefined;
        var hi: [m]V = undefined;
        inline for (0..m) |j| {
            // vpshufb looks up within each 128-bit half: the table in both.
            lo[j] = t.lo[j] ++ t.lo[j];
            hi[j] = t.hi[j] ++ t.hi[j];
        }
        const nib: V = @splat(0x0f);
        const zero: V = @splat(0);
        var i = pos;
        while (i + (m - 1) + lanes <= input.len) : (i += lanes) {
            var c: V = @splat(0xff);
            inline for (0..m) |j| {
                const v: V = input[i + j ..][0..lanes].*;
                c &= lookup(lo[j], v & nib) & lookup(hi[j], v >> @splat(@as(u3, 4)));
            }
            var mask: u32 = @bitCast(c != zero);
            if (mask == 0) continue;
            const bits: [lanes]u8 = c;
            while (mask != 0) : (mask &= mask - 1) {
                const at = i + @ctz(mask);
                if (t.verify(input, at, bits[@ctz(mask)])) return at;
            }
        }
        while (i + m <= input.len) : (i += 1) {
            var b: u8 = 0xff;
            inline for (0..m) |j| {
                const x = input[i + j];
                b &= t.lo[j][x & 0x0f] & t.hi[j][x >> 4];
            }
            if (b != 0 and t.verify(input, i, b)) return i;
        }
        return null;
    }

    /// Does `input[at..]` begin with a prefix of one of `buckets`?
    fn verify(t: *const Teddy, input: []const u8, at: usize, buckets: u8) bool {
        var b = buckets;
        while (b != 0) : (b &= b - 1) {
            const k = @ctz(b);
            for (t.start[k]..t.start[k + 1]) |p| {
                const len = t.lens[p];
                if (input.len - at >= len and std.mem.eql(u8, input[at..][0..len], t.pats[p][0..len])) return true;
            }
        }
        return false;
    }

    /// The `Teddy` for the literal prefixes every match of the program
    /// begins with, or null: a match can be empty or begin with `.`, a
    /// larger class or U+FFFD (which also reads an invalid byte), the walk
    /// is too long, or the prefixes are shorter than two bytes. The longest
    /// cut (8, 4, 3, 2 bytes) that yields at most `max_pats` is kept.
    pub fn build(insts: []const Inst, ranges: []const Range) ?Teddy {
        for ([_]u8{ 8, 4, 3, 2 }) |cap| {
            var set: Set = .{};
            switch (collect(insts, ranges, cap, &set)) {
                .ok => return fromSet(&set),
                .too_many => continue,
                .none => return null,
            }
        }
        return null;
    }
};

/// A set of first bytes (`Prefilter.first`), scanned 32 positions at a time
/// by Teddy's two nibble tables over one byte ("shufti", from Hyperscan):
/// the high nibbles whose low-nibble sets are equal share a bucket, at most
/// eight, so a byte is in the set exactly when `lo[low] & hi[high] != 0`.
pub const ByteSet = struct {
    lo: [16]u8,
    hi: [16]u8,

    /// Null for more than eight distinct low-nibble sets, or without vpshufb
    /// (the portable lookup is slower than the plain loop it replaces).
    pub fn build(set: [4]u64) ?ByteSet {
        if (!has_avx2) return null;
        var masks: [8]u16 = undefined;
        var n: u8 = 0;
        var bs: ByteSet = .{ .lo = @splat(0), .hi = @splat(0) };
        for (0..16) |h| {
            var m: u16 = 0;
            for (0..16) |l| {
                const c = h << 4 | l;
                if (set[c >> 6] & (@as(u64, 1) << @intCast(c & 63)) != 0) m |= @as(u16, 1) << @intCast(l);
            }
            if (m == 0) continue;
            const b = for (masks[0..n], 0..) |x, i| {
                if (x == m) break i;
            } else blk: {
                if (n == 8) return null;
                masks[n] = m;
                n += 1;
                break :blk n - 1;
            };
            bs.hi[h] = @as(u8, 1) << @intCast(b);
        }
        for (masks[0..n], 0..) |m, b| {
            for (0..16) |l| if (m & (@as(u16, 1) << @intCast(l)) != 0) {
                bs.lo[l] |= @as(u8, 1) << @intCast(b);
            };
        }
        return bs;
    }

    /// The first position at or after `pos` whose byte is in the set.
    pub noinline fn find(bs: *const ByteSet, input: []const u8, pos: usize) ?usize {
        const lo: V = bs.lo ++ bs.lo;
        const hi: V = bs.hi ++ bs.hi;
        const nib: V = @splat(0x0f);
        const zero: V = @splat(0);
        var i = pos;
        while (i + lanes <= input.len) : (i += lanes) {
            const v: V = input[i..][0..lanes].*;
            const c = lookup(lo, v & nib) & lookup(hi, v >> @splat(@as(u3, 4)));
            const mask: u32 = @bitCast(c != zero);
            if (mask != 0) return i + @ctz(mask);
        }
        while (i < input.len) : (i += 1) {
            const x = input[i];
            if (bs.lo[x & 0x0f] & bs.hi[x >> 4] != 0) return i;
        }
        return null;
    }
};

/// `table[idx[i]]` for every lane (`idx` < 16, `table` the 16 entries twice).
inline fn lookup(table: V, idx: V) V {
    if (has_avx2) {
        return asm ("vpshufb %[idx], %[tbl], %[out]"
            : [out] "=x" (-> V),
            : [tbl] "x" (table),
              [idx] "x" (idx),
        );
    }
    return lookupPortable(table, idx);
}

/// `lookup` without vpshufb: a binary tree of selects over the four index
/// bits (every target; tested against the table on this one too).
inline fn lookupPortable(table: V, idx: V) V {
    var level: [16]V = undefined;
    inline for (0..16) |k| level[k] = @splat(table[k]);
    comptime var width = 16;
    comptime var bit = 0;
    inline while (width > 1) : ({
        width /= 2;
        bit += 1;
    }) {
        const sel = (idx >> @splat(@as(u3, bit))) & @as(V, @splat(1)) == @as(V, @splat(1));
        inline for (0..width / 2) |k| level[k] = @select(u8, sel, level[2 * k + 1], level[2 * k]);
    }
    return level[0];
}

const Set = struct {
    pats: [max_pats][max_len]u8 = undefined,
    lens: [max_pats]u8 = undefined,
    n: usize = 0,
};

const Outcome = enum { ok, too_many, none };

/// A path of the walk: the instruction it is at and the bytes read so far.
const Entry = struct { pc: u16, len: u8, buf: [max_len]u8 };

/// Walk every path from the start, collecting the bytes of the code points
/// it must read, until `cap` bytes, a larger class, `.`, or the match.
/// Assertions are passed (a superset of where matches start is enough).
/// Past the walk's budget: `.too_many`, so a shorter cut is tried.
fn collect(insts: []const Inst, ranges: []const Range, cap: u8, set: *Set) Outcome {
    var stack: [64]Entry = undefined;
    stack[0] = .{ .pc = 0, .len = 0, .buf = undefined };
    var sp: usize = 1;
    var steps: usize = 0;
    while (sp != 0) {
        steps += 1;
        // An empty loop (`(?:\b)*`) would walk forever; a big fan-out may
        // still fit when cut shorter.
        if (steps > 4096) return .too_many;
        sp -= 1;
        var e = stack[sp];
        switch (insts[e.pc]) {
            .jmp => |to| {
                e.pc = to;
                stack[sp] = e;
                sp += 1;
            },
            .split => |sx| {
                if (sp + 2 > stack.len) return .too_many;
                e.pc = sx.y;
                stack[sp] = e;
                e.pc = sx.x;
                stack[sp + 1] = e;
                sp += 2;
            },
            .save, .assert => {
                e.pc += 1;
                stack[sp] = e;
                sp += 1;
            },
            .match, .any, .any_not_nl => if (emit(set, &e)) |o| return o,
            .rune => |r| {
                const rs = ranges[r.start..][0..r.len];
                var count: usize = 0;
                const small = for (rs) |rg| {
                    if (rg.lo <= 0xfffd and 0xfffd <= rg.hi) break false;
                    count += rg.hi - rg.lo + 1;
                    if (count > max_class) break false;
                } else true;
                if (!small) {
                    if (emit(set, &e)) |o| return o;
                    continue;
                }
                for (rs) |rg| {
                    var cp: u21 = rg.lo;
                    while (true) : (cp += 1) {
                        // A surrogate is never read: no text gets past it.
                        if (cp < 0xd800 or cp > 0xdfff) {
                            var enc: [4]u8 = undefined;
                            const w = std.unicode.utf8Encode(cp, &enc) catch unreachable;
                            var ne = e;
                            ne.pc = e.pc + 1;
                            const take: u8 = @intCast(@min(w, cap - e.len));
                            @memcpy(ne.buf[e.len..][0..take], enc[0..take]);
                            ne.len += take;
                            if (ne.len == cap) {
                                if (emit(set, &ne)) |o| return o;
                            } else {
                                if (sp == stack.len) return .too_many;
                                stack[sp] = ne;
                                sp += 1;
                            }
                        }
                        if (cp == rg.hi) break;
                    }
                }
            },
        }
    }
    return if (set.n == 0) .none else .ok;
}

/// Add the path's bytes to `set` (once); an outcome when the walk must stop.
fn emit(set: *Set, e: *const Entry) ?Outcome {
    if (e.len == 0) return .none; // a match can begin here with anything
    for (set.pats[0..set.n], set.lens[0..set.n]) |*p, l| {
        if (l == e.len and std.mem.eql(u8, p[0..l], e.buf[0..l])) return null;
    }
    if (set.n == max_pats) return .too_many;
    set.pats[set.n] = e.buf;
    set.lens[set.n] = e.len;
    set.n += 1;
    return null;
}

fn fromSet(set: *const Set) ?Teddy {
    var t: Teddy = .{ .lo = @splat(@splat(0)), .hi = @splat(@splat(0)), .masks = 0, .pats = undefined, .lens = undefined, .n = 0, .start = undefined };
    // A prefix another one begins is covered by it: drop it.
    for (0..set.n) |p| {
        const covered = for (0..set.n) |q| {
            if (q != p and set.lens[q] <= set.lens[p] and std.mem.eql(u8, set.pats[q][0..set.lens[q]], set.pats[p][0..set.lens[q]])) break true;
        } else false;
        if (covered) continue;
        // Insertion sort by bytes.
        var k: usize = t.n;
        while (k > 0 and lessThan(set.pats[p][0..set.lens[p]], t.pats[k - 1][0..t.lens[k - 1]])) : (k -= 1) {
            t.pats[k] = t.pats[k - 1];
            t.lens[k] = t.lens[k - 1];
        }
        t.pats[k] = set.pats[p];
        t.lens[k] = set.lens[p];
        t.n += 1;
    }
    var shortest: u8 = max_len;
    for (t.lens[0..t.n]) |l| shortest = @min(shortest, l);
    if (shortest < 2) return null;
    t.masks = @min(shortest, 3);
    // Neighbours in sorted order share a bucket: their bytes blur the least.
    for (&t.start, 0..) |*s, b| s.* = @intCast((b * t.n + 7) / 8);
    for (0..8) |b| {
        for (t.start[b]..t.start[b + 1]) |p| {
            for (0..t.masks) |j| {
                const x = t.pats[p][j];
                t.lo[j][x & 0x0f] |= @as(u8, 1) << @intCast(b);
                t.hi[j][x >> 4] |= @as(u8, 1) << @intCast(b);
            }
        }
    }
    return t;
}

fn lessThan(a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

const testing = std.testing;

test "lookup: vpshufb (where present) and the select tree agree with the table" {
    var prng: std.Random.DefaultPrng = .init(0x7465_6464);
    const rng = prng.random();
    for (0..200) |_| {
        var tab: [16]u8 = undefined;
        rng.bytes(&tab);
        var idx: [lanes]u8 = undefined;
        for (&idx) |*x| x.* = rng.uintLessThan(u8, 16);
        const tv: V = tab ++ tab;
        const a: [lanes]u8 = lookup(tv, idx);
        const b: [lanes]u8 = lookupPortable(tv, idx);
        for (idx, a, b) |x, ga, gb| {
            try testing.expectEqual(tab[x], ga);
            try testing.expectEqual(tab[x], gb);
        }
    }
}

test "ByteSet: the nibble tables hold exactly the set, and find agrees with a byte loop" {
    if (!has_avx2) return error.SkipZigTest;
    var prng: std.Random.DefaultPrng = .init(0x6279_7465);
    const rng = prng.random();
    var text: [300]u8 = undefined;
    var built: usize = 0;
    for (0..400) |round| {
        // Sets of a few bytes, or of a few high nibbles' worth (more than
        // eight low-nibble sets give no ByteSet).
        var set: [4]u64 = @splat(0);
        const k = 1 + rng.uintLessThan(usize, if (round % 2 == 0) 6 else 60);
        for (0..k) |_| {
            const c = rng.int(u8);
            set[c >> 6] |= @as(u64, 1) << @intCast(c & 63);
        }
        const bs = ByteSet.build(set) orelse continue;
        built += 1;
        for (0..256) |c| {
            const in = set[c >> 6] & (@as(u64, 1) << @intCast(c & 63)) != 0;
            try testing.expectEqual(in, bs.lo[c & 0x0f] & bs.hi[c >> 4] != 0);
        }
        rng.bytes(&text);
        // Mostly bytes outside the set, so the hits fall anywhere in a block.
        for (&text) |*x| if (rng.uintLessThan(u8, 8) != 0 and set[x.* >> 6] & (@as(u64, 1) << @intCast(x.* & 63)) != 0) {
            x.* = 0;
            if (set[0] & 1 != 0) x.* = 1;
        };
        const len = rng.uintLessThan(usize, text.len + 1);
        const pos = rng.uintLessThan(usize, len + 1);
        const want = for (text[pos..len], pos..) |x, i| {
            if (set[x >> 6] & (@as(u64, 1) << @intCast(x & 63)) != 0) break i;
        } else null;
        try testing.expectEqual(want, bs.find(text[0..len], pos));
    }
    try testing.expect(built > 100);
    // Nine high nibbles with nine different low-nibble sets: no ByteSet.
    var nine: [4]u64 = @splat(0);
    for (0..9) |h| for (0..h + 1) |l| {
        const c = h << 4 | l;
        nine[c >> 6] |= @as(u64, 1) << @intCast(c & 63);
    };
    try testing.expectEqual(null, ByteSet.build(nine));
}
