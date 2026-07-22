//! Canonical + simple prefix-code tables for RFC 7932.
//!
//! Codes are read least-significant-bit first, so the canonical (MSB-first)
//! code assigned to each symbol is bit-reversed before being placed into a
//! flat lookup table of size `1 << bits`. Decoding peeks `bits` bits, indexes
//! the table, and drops the entry's actual code length.

const std = @import("std");
const BrotliError = @import("errors.zig").BrotliError;

pub const Entry = struct { sym: u16, len: u8 };

pub const Table = struct {
    entries: []Entry,
    bits: u5, // index width == max code length (0 for a single-symbol code)

    pub fn deinit(self: *Table, gpa: std.mem.Allocator) void {
        gpa.free(self.entries);
        self.* = undefined;
    }
};

fn reverseBits(code: u32, len: u5) u32 {
    var r: u32 = 0;
    var c = code;
    var i: u5 = 0;
    while (i < len) : (i += 1) {
        r = (r << 1) | (c & 1);
        c >>= 1;
    }
    return r;
}

/// Number of bits to represent `x` (bit length): 0 for x==0, else floor(log2(x))+1.
/// Matches google/brotli's `Log2Floor`, used to size simple-code symbol reads.
pub fn symbolBits(x: u32) u5 {
    if (x == 0) return 0;
    return @intCast(32 - @clz(x));
}

fn singleSymbol(gpa: std.mem.Allocator, sym: u16) BrotliError!Table {
    const entries = try gpa.alloc(Entry, 1);
    entries[0] = .{ .sym = sym, .len = 0 };
    return .{ .entries = entries, .bits = 0 };
}

/// Build a table from per-symbol `code_lengths` (complex prefix code, 3.5).
/// Enforces a complete (Kraft-equality) code, except the single-symbol case.
pub fn buildComplex(gpa: std.mem.Allocator, code_lengths: []const u8) BrotliError!Table {
    var count = [_]u16{0} ** 16;
    var max_len: u5 = 0;
    var nonzero: usize = 0;
    var last_sym: u16 = 0;
    for (code_lengths, 0..) |l, sym| {
        if (l == 0) continue;
        if (l > 15) return error.InvalidHuffman;
        count[l] += 1;
        if (l > max_len) max_len = @intCast(l);
        nonzero += 1;
        last_sym = @intCast(sym);
    }
    if (nonzero == 0) return error.InvalidHuffman;
    if (nonzero == 1) return singleSymbol(gpa, last_sym);

    // Kraft completeness check.
    var total: u32 = 0;
    var len: u5 = 1;
    while (len <= max_len) : (len += 1) {
        total += @as(u32, count[len]) << @intCast(max_len - len);
    }
    if (total != (@as(u32, 1) << max_len)) return error.InvalidHuffman;

    var next_code = [_]u32{0} ** 16;
    var code: u32 = 0;
    len = 1;
    while (len <= max_len) : (len += 1) {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    const size = @as(usize, 1) << max_len;
    const entries = try gpa.alloc(Entry, size);
    for (code_lengths, 0..) |l, sym| {
        if (l == 0) continue;
        const L: u5 = @intCast(l);
        const c = next_code[L];
        next_code[L] += 1;
        const rev = reverseBits(c, L);
        const step = @as(usize, 1) << L;
        var idx: usize = rev;
        while (idx < size) : (idx += step) {
            entries[idx] = .{ .sym = @intCast(sym), .len = l };
        }
    }
    return .{ .entries = entries, .bits = max_len };
}

/// Build a simple prefix code (3.4). `num_symbols` is the decoded selector
/// (0..4); `vals` holds the read symbols (its length matches the selector).
pub fn buildSimple(gpa: std.mem.Allocator, num_symbols: u8, vals_in: []const u16) BrotliError!Table {
    var v: [4]u16 = undefined;
    for (vals_in, 0..) |x, i| v[i] = x;

    switch (num_symbols) {
        0 => return singleSymbol(gpa, v[0]),
        1 => {
            const entries = try gpa.alloc(Entry, 2);
            const a = @min(v[0], v[1]);
            const b = @max(v[0], v[1]);
            entries[0] = .{ .sym = a, .len = 1 };
            entries[1] = .{ .sym = b, .len = 1 };
            return .{ .entries = entries, .bits = 1 };
        },
        2 => {
            const entries = try gpa.alloc(Entry, 4);
            const lo = @min(v[1], v[2]);
            const hi = @max(v[1], v[2]);
            entries[0] = .{ .sym = v[0], .len = 1 };
            entries[2] = .{ .sym = v[0], .len = 1 };
            entries[1] = .{ .sym = lo, .len = 2 };
            entries[3] = .{ .sym = hi, .len = 2 };
            return .{ .entries = entries, .bits = 2 };
        },
        3 => {
            // 4 symbols, all length 2. Sort ascending.
            sort4(&v);
            const entries = try gpa.alloc(Entry, 4);
            entries[0] = .{ .sym = v[0], .len = 2 };
            entries[2] = .{ .sym = v[1], .len = 2 };
            entries[1] = .{ .sym = v[2], .len = 2 };
            entries[3] = .{ .sym = v[3], .len = 2 };
            return .{ .entries = entries, .bits = 2 };
        },
        4 => {
            // 4 symbols, lengths [1,2,3,3]; swap v[2],v[3] if out of order.
            if (v[3] < v[2]) {
                const t = v[3];
                v[3] = v[2];
                v[2] = t;
            }
            const entries = try gpa.alloc(Entry, 8);
            entries[0] = .{ .sym = v[0], .len = 1 };
            entries[1] = .{ .sym = v[1], .len = 2 };
            entries[2] = .{ .sym = v[0], .len = 1 };
            entries[3] = .{ .sym = v[2], .len = 3 };
            entries[4] = .{ .sym = v[0], .len = 1 };
            entries[5] = .{ .sym = v[1], .len = 2 };
            entries[6] = .{ .sym = v[0], .len = 1 };
            entries[7] = .{ .sym = v[3], .len = 3 };
            return .{ .entries = entries, .bits = 3 };
        },
        else => return error.InvalidHuffman,
    }
}

fn sort4(v: *[4]u16) void {
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var k: usize = i + 1;
        while (k < 4) : (k += 1) {
            if (v[k] < v[i]) {
                const t = v[k];
                v[k] = v[i];
                v[i] = t;
            }
        }
    }
}
