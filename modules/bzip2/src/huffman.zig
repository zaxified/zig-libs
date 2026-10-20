// SPDX-License-Identifier: MIT

//! Huffman code construction as bzip2 does it. `makeCodeLengths`,
//! `assignCodes` and `DecodeTable.init` are ported from libbzip2 1.0.8
//! huffman.c (BSD-style licence, see ../NOTICE; altered: translated to
//! Zig). The encoder's lengths must match libbzip2's decision for decision
//! (heap tie-breaking, depth in the low byte of the weight, the halving
//! retry), because the byte parity of the whole encoder rests on them.

const std = @import("std");

pub const max_alpha_size = 258;
pub const max_code_len = 23;
/// The longest code the encoder emits (libbzip2 >= 1.0.3).
pub const encode_max_len = 17;
/// The longest code the decoder accepts.
pub const decode_max_len = 20;

inline fn weightOf(w: u32) u32 {
    return w & 0xffff_ff00;
}
inline fn depthOf(w: u32) u32 {
    return w & 0xff;
}
inline fn addWeights(w1: u32, w2: u32) u32 {
    return (weightOf(w1) + weightOf(w2)) | (1 + @max(depthOf(w1), depthOf(w2)));
}

/// Code lengths for `freq[0..alpha_size]` (a zero frequency counts as 1),
/// none longer than `max_len`.
pub fn makeCodeLengths(len: []u8, freq: []const u32, alpha_size: usize, max_len: u32) void {
    var heap: [max_alpha_size + 2]usize = undefined;
    var weight: [max_alpha_size * 2]u32 = undefined;
    var parent: [max_alpha_size * 2]i32 = undefined;

    for (0..alpha_size) |i| weight[i + 1] = (if (freq[i] == 0) 1 else freq[i]) << 8;

    while (true) {
        var n_nodes: usize = alpha_size;
        var n_heap: usize = 0;

        heap[0] = 0;
        weight[0] = 0;
        parent[0] = -2;

        for (1..alpha_size + 1) |i| {
            parent[i] = -1;
            n_heap += 1;
            heap[n_heap] = i;
            // UPHEAP
            var zz = n_heap;
            const tmp = heap[zz];
            while (weight[tmp] < weight[heap[zz >> 1]]) {
                heap[zz] = heap[zz >> 1];
                zz >>= 1;
            }
            heap[zz] = tmp;
        }

        while (n_heap > 1) {
            const n1 = heap[1];
            heap[1] = heap[n_heap];
            n_heap -= 1;
            downHeap(&heap, &weight, n_heap);
            const n2 = heap[1];
            heap[1] = heap[n_heap];
            n_heap -= 1;
            downHeap(&heap, &weight, n_heap);
            n_nodes += 1;
            parent[n1] = @intCast(n_nodes);
            parent[n2] = @intCast(n_nodes);
            weight[n_nodes] = addWeights(weight[n1], weight[n2]);
            parent[n_nodes] = -1;
            n_heap += 1;
            heap[n_heap] = n_nodes;
            var zz = n_heap;
            const tmp = heap[zz];
            while (weight[tmp] < weight[heap[zz >> 1]]) {
                heap[zz] = heap[zz >> 1];
                zz >>= 1;
            }
            heap[zz] = tmp;
        }

        var too_long = false;
        for (1..alpha_size + 1) |i| {
            var j: u32 = 0;
            var k: usize = i;
            while (parent[k] >= 0) {
                k = @intCast(parent[k]);
                j += 1;
            }
            len[i - 1] = @intCast(j);
            if (j > max_len) too_long = true;
        }

        if (!too_long) break;

        for (1..alpha_size + 1) |i| {
            const j = 1 + (weight[i] >> 8) / 2;
            weight[i] = j << 8;
        }
    }
}

fn downHeap(heap: *[max_alpha_size + 2]usize, weight: *const [max_alpha_size * 2]u32, n_heap: usize) void {
    var zz: usize = 1;
    const tmp = heap[zz];
    while (true) {
        var yy = zz << 1;
        if (yy > n_heap) break;
        if (yy < n_heap and weight[heap[yy + 1]] < weight[heap[yy]]) yy += 1;
        if (weight[tmp] < weight[heap[yy]]) break;
        heap[zz] = heap[yy];
        zz = yy;
    }
    heap[zz] = tmp;
}

/// Canonical codes for lengths `length[0..alpha_size]` in `min_len..max_len`.
pub fn assignCodes(code: []u32, length: []const u8, min_len: u32, max_len: u32, alpha_size: usize) void {
    var vec: u32 = 0;
    var n = min_len;
    while (n <= max_len) : (n += 1) {
        for (0..alpha_size) |i| {
            if (length[i] == n) {
                code[i] = vec;
                vec += 1;
            }
        }
        vec <<= 1;
    }
}

/// libbzip2's canonical-code decoding tables for one coding table.
pub const DecodeTable = struct {
    limit: [max_code_len]i32,
    base: [max_code_len]i32,
    perm: [max_alpha_size]u16,
    min_len: u32,

    pub fn init(t: *DecodeTable, length: []const u8, alpha_size: usize) void {
        var min_len: u32 = 32;
        var max_len: u32 = 0;
        for (length[0..alpha_size]) |l| {
            if (l > max_len) max_len = l;
            if (l < min_len) min_len = l;
        }
        t.* = .{ .limit = @splat(0), .base = @splat(0), .perm = @splat(0), .min_len = min_len };
        var pp: usize = 0;
        var i = min_len;
        while (i <= max_len) : (i += 1) {
            for (0..alpha_size) |j| {
                if (length[j] == i) {
                    t.perm[pp] = @intCast(j);
                    pp += 1;
                }
            }
        }
        for (length[0..alpha_size]) |l| t.base[l + 1] += 1;
        for (1..max_code_len) |k| t.base[k] += t.base[k - 1];
        var vec: i32 = 0;
        i = min_len;
        while (i <= max_len) : (i += 1) {
            vec += t.base[i + 1] - t.base[i];
            t.limit[i] = vec - 1;
            vec <<= 1;
        }
        i = min_len + 1;
        while (i <= max_len) : (i += 1) t.base[i] = ((t.limit[i - 1] + 1) << 1) - t.base[i];
    }
};

test "code lengths of a skewed alphabet are a prefix code of the right depth" {
    var len: [8]u8 = undefined;
    const freq = [_]u32{ 100, 50, 25, 12, 6, 3, 2, 1 };
    makeCodeLengths(&len, &freq, 8, 17);
    // Kraft sum exactly 1 for a full Huffman tree.
    var kraft: u64 = 0;
    for (len) |l| kraft += @as(u64, 1) << @intCast(20 - l);
    try std.testing.expectEqual(@as(u64, 1) << 20, kraft);
    try std.testing.expect(len[0] < len[7]);
}

test "length limit forces the halving retry" {
    // Fibonacci-like frequencies give a very deep tree; limited to 5 bits.
    var freq: [20]u32 = undefined;
    var a: u32 = 1;
    var b: u32 = 1;
    for (&freq) |*f| {
        f.* = a;
        const c = a + b;
        a = b;
        b = c;
    }
    var len: [20]u8 = undefined;
    makeCodeLengths(&len, &freq, 20, 5);
    for (len) |l| try std.testing.expect(l >= 1 and l <= 5);
}
