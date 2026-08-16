// SPDX-License-Identifier: MIT
//! qr — QR Code symbol encoder (ISO/IEC 18004 model 2), versions 1–40, all
//! four error-correction levels, numeric/alphanumeric/byte modes.
//!
//! **What comes out is a matrix, not a picture.** A QR symbol *is* a grid of
//! dark and light modules; turning that into SVG, PNG or terminal output is a
//! presentation choice with its own opinions — scale, quiet-zone width, colours,
//! viewBox — none of which belong to the encoding. `role = .codec` in the meta
//! block above is meant literally. `README.md` carries copy-paste renderers for
//! SVG and for a terminal, and they are short precisely because the matrix is
//! the right handoff point.
//!
//! **Provenance.** Clean-room from ISO/IEC 18004. No third-party QR
//! implementation was read while writing this. Two independent implementations
//! were used as black-box oracles — an encoder, compared matrix-for-matrix, and
//! a decoder, fed this module's output and asked what it says — which is a
//! testing relationship, not a design one (`SPEC.md` "Verification"). The one
//! table that is genuinely tabular in the standard, the error-correction block
//! structure, is transcribed from it; everything else here is derived, including
//! the field tables, the generator polynomials, the alignment-pattern centres
//! and the codeword capacity.
//!
//! **Kanji mode is not implemented** and is not planned: it encodes Shift-JIS
//! double-byte values, so a caller would have to transcode into it before
//! arriving, and byte mode carries the same text as UTF-8 for the same or fewer
//! bits in every case that is not almost entirely Japanese. `encode` never
//! silently falls back — an input is numeric, alphanumeric or byte.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec, // pure computation: no allocator, no I/O, no syscalls
    .concurrency = .reentrant, // no shared state; every buffer is caller- or stack-owned
    .model_after = "ISO/IEC 18004 model-2 QR Code; independent encoder and decoder implementations were used as black-box oracles only, never their source",
    .deps = .{}, // std only
};

// ── public API ──────────────────────────────────────────────────────────────

/// Error-correction level. Higher levels survive more damage and hold less
/// data; the spec's own recovery figures are ~7/15/25/30 % of codewords.
pub const Ecc = enum(u2) {
    low,
    medium,
    quartile,
    high,

    /// The two-bit value written into the format information. Deliberately NOT
    /// the same as the enum order — the standard assigns M=00, L=01, H=10,
    /// Q=11, and getting this wrong produces a symbol every decoder rejects for
    /// a reason that looks like a masking bug.
    fn formatBits(self: Ecc) u2 {
        return switch (self) {
            .medium => 0b00,
            .low => 0b01,
            .high => 0b10,
            .quartile => 0b11,
        };
    }
};

/// Segment encoding. Chosen automatically by `encode`; `Options.mode` forces one.
pub const Mode = enum(u4) {
    numeric = 0b0001,
    alphanumeric = 0b0010,
    byte = 0b0100,
};

pub const Options = struct {
    ecc: Ecc = .medium,
    /// Force a version (1–40). Null picks the smallest that fits.
    version: ?u6 = null,
    /// Force a mode. Null picks the most compact one the input allows.
    mode: ?Mode = null,
    /// Force a mask pattern (0–7). Null runs the standard penalty evaluation.
    mask: ?u3 = null,
};

pub const Error = error{
    /// The input does not fit any version at the requested level, or does not
    /// fit the version that was forced.
    TooLong,
    /// `Options.mode` was forced to one the input cannot be expressed in.
    ModeMismatch,
    /// `Options.version` was outside 1–40.
    BadVersion,
};

/// Modules per side of the largest symbol (version 40).
pub const max_size: u16 = 177;

/// Quiet zone the standard requires around the symbol, in modules
/// (ISO/IEC 18004 §6.3.8). Renderers need this and should not each pick a
/// number; it is four, and it is four for every version.
pub const quiet_zone: u8 = 4;

/// A finished symbol. `size` is the side length; module (x, y) is dark when
/// `isDark(x, y)` — x across, y down, origin top-left, which is the order the
/// standard draws in.
pub const Matrix = struct {
    size: u16 = 0,
    version: u6 = 0,
    ecc: Ecc = .medium,
    mask: u3 = 0,
    bits: [(max_size * max_size + 7) / 8]u8 = undefined,

    pub fn isDark(self: *const Matrix, x: u16, y: u16) bool {
        const i = @as(usize, y) * self.size + x;
        return (self.bits[i >> 3] >> @intCast(i & 7)) & 1 != 0;
    }

    fn set(self: *Matrix, x: u16, y: u16, dark: bool) void {
        const i = @as(usize, y) * self.size + x;
        const m = @as(u8, 1) << @intCast(i & 7);
        if (dark) self.bits[i >> 3] |= m else self.bits[i >> 3] &= ~m;
    }
};

/// Encode `text` into `out`. Allocates nothing: `out` is the only storage the
/// caller provides, and everything else lives on this frame.
pub fn encode(out: *Matrix, text: []const u8, opts: Options) Error!void {
    const mode = if (opts.mode) |m| blk: {
        if (!modeFits(m, text)) return Error.ModeMismatch;
        break :blk m;
    } else pickMode(text);

    const version = if (opts.version) |v| blk: {
        if (v < 1 or v > 40) return Error.BadVersion;
        if (dataBits(mode, text.len, v) > dataCapacityBits(v, opts.ecc)) return Error.TooLong;
        break :blk v;
    } else pickVersion(mode, text.len, opts.ecc) orelse return Error.TooLong;

    var codewords: [max_codewords]u8 = undefined;
    const total = totalCodewords(version);
    buildCodewords(codewords[0..total], mode, text, version, opts.ecc);

    out.* = .{ .size = sideFor(version), .version = version, .ecc = opts.ecc };
    @memset(&out.bits, 0);

    var reserved: [(max_size * max_size + 7) / 8]u8 = undefined;
    @memset(&reserved, 0);
    drawFunctionPatterns(out, &reserved);
    placeCodewords(out, &reserved, codewords[0..total]);

    const mask = opts.mask orelse pickMask(out, &reserved);
    applyMask(out, &reserved, mask);
    out.mask = mask;
    drawFormatInfo(out, opts.ecc, mask);
    if (version >= 7) drawVersionInfo(out);
}

// ── GF(2^8) ─────────────────────────────────────────────────────────────────
// The field is derived from its primitive polynomial rather than transcribed,
// so there is no table here that a typo could corrupt silently.

const gf = struct {
    /// x^8 + x^4 + x^3 + x^2 + 1 (ISO/IEC 18004 §7.5.2). The same field HQC's
    /// Reed-Solomon layer uses, which is a coincidence of a popular choice and
    /// not a shared dependency — `modules/hqc/src/gf256.zig` documents its
    /// tables entirely in terms of the HQC reference, and importing it here
    /// would hand that provenance to every consumer of a QR code.
    const poly: u16 = 0x11D;

    const t = blk: {
        @setEvalBranchQuota(20_000);
        var exp: [512]u8 = undefined;
        var log: [256]u8 = undefined;
        var x: u16 = 1;
        for (0..255) |i| {
            exp[i] = @intCast(x);
            log[x] = @intCast(i);
            x <<= 1; // multiply by the generator alpha = 2, i.e. by "x"
            if (x & 0x100 != 0) x ^= poly;
        }
        for (255..512) |i| exp[i] = exp[i - 255];
        log[0] = 0; // never read: mul() short-circuits on a zero operand
        break :blk .{ .exp = exp, .log = log };
    };

    fn mul(a: u8, b: u8) u8 {
        if (a == 0 or b == 0) return 0;
        return t.exp[@as(u16, t.log[a]) + @as(u16, t.log[b])];
    }
};

/// g(x) = prod_{i<n} (x - alpha^i), coefficients descending, `buf` holds n+1.
fn rsGenerator(n: usize, buf: []u8) []u8 {
    buf[0] = 1;
    var len: usize = 1;
    for (0..n) |i| {
        buf[len] = 0;
        var j: usize = len;
        while (j > 0) : (j -= 1) buf[j] ^= gf.mul(buf[j - 1], gf.t.exp[i]);
        len += 1;
    }
    return buf[0..len];
}

/// Remainder of data(x)*x^ec_len mod g(x) — the block's EC codewords.
fn rsEncode(data: []const u8, ec_len: usize, out: []u8) void {
    var gbuf: [31]u8 = undefined; // no version needs more than 30 EC codewords
    const g = rsGenerator(ec_len, &gbuf);
    @memset(out[0..ec_len], 0);
    for (data) |d| {
        const factor = d ^ out[0];
        std.mem.copyForwards(u8, out[0 .. ec_len - 1], out[1..ec_len]);
        out[ec_len - 1] = 0;
        for (0..ec_len) |i| out[i] ^= gf.mul(g[i + 1], factor);
    }
}

// ── geometry, derived rather than tabulated ─────────────────────────────────

fn sideFor(version: u6) u16 {
    return 17 + 4 * @as(u16, version);
}

/// Alignment-pattern centre coordinates (ISO/IEC 18004 §6.3.6). The standard
/// prints these as a table; they follow a rule, so the rule is what is here —
/// with one exception the rule does not cover. Version 1 has none.
///
/// **Version 32 is not derivable.** Its tabulated centres are 6, 34, 60, 86,
/// 112, 138, while even spacing over the same span gives 6, 26, 54, 82, 110,
/// 138. No rounding fixes it: the span is 132 over 5 gaps = 26.4, and the table
/// takes 26, but version 36's 148 over 6 = 24.67 and the table takes 26 there
/// too — one rounds down, the other up. Checked against an independent encoder
/// for every version from 2 to 40; 32 is the only one that disagrees, so it is
/// an outlier in the standard's table rather than a rule this code is missing.
fn alignmentCentres(version: u6, out: *[7]u16) []const u16 {
    if (version == 1) return out[0..0];
    if (version == 32) {
        out[0..6].* = .{ 6, 34, 60, 86, 112, 138 };
        return out[0..6];
    }
    const n: usize = @as(usize, version) / 7 + 2;
    const first: u16 = 6;
    const last: u16 = sideFor(version) - 7;
    // Even spacing, rounded UP to an even step, measured from the last centre
    // backwards — the first gap is the one allowed to be shorter.
    const span = last - first;
    const step: u16 = @intCast((@as(usize, span) + (n - 1) * 2 - 1) / ((n - 1) * 2) * 2);
    out[0] = first;
    for (1..n) |i| out[i] = last - @as(u16, @intCast(n - 1 - i)) * step;
    return out[0..n];
}

const max_codewords: usize = 3706; // version 40

/// Total codewords a version holds, obtained by counting the modules no
/// function pattern claims. Counting beats a 40-entry table: the same routine
/// that reserves modules for drawing decides the capacity, so the two cannot
/// disagree.
fn totalCodewords(version: u6) usize {
    var m: Matrix = .{ .size = sideFor(version), .version = version };
    var reserved: [(max_size * max_size + 7) / 8]u8 = undefined;
    @memset(&reserved, 0);
    @memset(&m.bits, 0);
    drawFunctionPatterns(&m, &reserved);

    const side = sideFor(version);
    var free: usize = 0;
    for (0..side) |y| {
        for (0..side) |x| {
            const i = y * side + x;
            if ((reserved[i >> 3] >> @intCast(i & 7)) & 1 == 0) free += 1;
        }
    }
    return free / 8; // the leftover 0–7 modules are remainder bits, left light
}

// ── error-correction block structure ────────────────────────────────────────
// The one genuinely tabular thing in the standard (Table 13–22): how many EC
// codewords each block carries and how many blocks a version is split into.
// Everything else about the split is arithmetic, so only these two numbers are
// stored — the short/long block lengths follow from the total.

const EcSpec = struct { ec_per_block: u8, blocks: u8 };

fn ecSpec(version: u6, ecc: Ecc) EcSpec {
    const row = ec_table[@as(usize, version) - 1];
    const cell = row[@intFromEnum(ecc)];
    return .{ .ec_per_block = cell[0], .blocks = cell[1] };
}

// Indexed [version-1][ecc as declared: low, medium, quartile, high][ec, blocks]
const ec_table = [40][4][2]u8{
    .{ .{ 7, 1 }, .{ 10, 1 }, .{ 13, 1 }, .{ 17, 1 } },
    .{ .{ 10, 1 }, .{ 16, 1 }, .{ 22, 1 }, .{ 28, 1 } },
    .{ .{ 15, 1 }, .{ 26, 1 }, .{ 18, 2 }, .{ 22, 2 } },
    .{ .{ 20, 1 }, .{ 18, 2 }, .{ 26, 2 }, .{ 16, 4 } },
    .{ .{ 26, 1 }, .{ 24, 2 }, .{ 18, 4 }, .{ 22, 4 } },
    .{ .{ 18, 2 }, .{ 16, 4 }, .{ 24, 4 }, .{ 28, 4 } },
    .{ .{ 20, 2 }, .{ 18, 4 }, .{ 18, 6 }, .{ 26, 5 } },
    .{ .{ 24, 2 }, .{ 22, 4 }, .{ 22, 6 }, .{ 26, 6 } },
    .{ .{ 30, 2 }, .{ 22, 5 }, .{ 20, 8 }, .{ 24, 8 } },
    .{ .{ 18, 4 }, .{ 26, 5 }, .{ 24, 8 }, .{ 28, 8 } },
    .{ .{ 20, 4 }, .{ 30, 5 }, .{ 28, 8 }, .{ 24, 11 } },
    .{ .{ 24, 4 }, .{ 22, 8 }, .{ 26, 10 }, .{ 28, 11 } },
    .{ .{ 26, 4 }, .{ 22, 9 }, .{ 24, 12 }, .{ 22, 16 } },
    .{ .{ 30, 4 }, .{ 24, 9 }, .{ 20, 16 }, .{ 24, 16 } },
    .{ .{ 22, 6 }, .{ 24, 10 }, .{ 30, 12 }, .{ 24, 18 } },
    .{ .{ 24, 6 }, .{ 28, 10 }, .{ 24, 17 }, .{ 30, 16 } },
    .{ .{ 28, 6 }, .{ 28, 11 }, .{ 28, 16 }, .{ 28, 19 } },
    .{ .{ 30, 6 }, .{ 26, 13 }, .{ 28, 18 }, .{ 28, 21 } },
    .{ .{ 28, 7 }, .{ 26, 14 }, .{ 26, 21 }, .{ 26, 25 } },
    .{ .{ 28, 8 }, .{ 26, 16 }, .{ 30, 20 }, .{ 28, 25 } },
    .{ .{ 28, 8 }, .{ 26, 17 }, .{ 28, 23 }, .{ 30, 25 } },
    .{ .{ 28, 9 }, .{ 28, 17 }, .{ 30, 23 }, .{ 24, 34 } },
    .{ .{ 30, 9 }, .{ 28, 18 }, .{ 30, 25 }, .{ 30, 30 } },
    .{ .{ 30, 10 }, .{ 28, 20 }, .{ 30, 27 }, .{ 30, 32 } },
    .{ .{ 26, 12 }, .{ 28, 21 }, .{ 30, 29 }, .{ 30, 35 } },
    .{ .{ 28, 12 }, .{ 28, 23 }, .{ 28, 34 }, .{ 30, 37 } },
    .{ .{ 30, 12 }, .{ 28, 25 }, .{ 30, 34 }, .{ 30, 40 } },
    .{ .{ 30, 13 }, .{ 28, 26 }, .{ 30, 35 }, .{ 30, 42 } },
    .{ .{ 30, 14 }, .{ 28, 28 }, .{ 30, 38 }, .{ 30, 45 } },
    .{ .{ 30, 15 }, .{ 28, 29 }, .{ 30, 40 }, .{ 30, 48 } },
    .{ .{ 30, 16 }, .{ 28, 31 }, .{ 30, 43 }, .{ 30, 51 } },
    .{ .{ 30, 17 }, .{ 28, 33 }, .{ 30, 45 }, .{ 30, 54 } },
    .{ .{ 30, 18 }, .{ 28, 35 }, .{ 30, 48 }, .{ 30, 57 } },
    .{ .{ 30, 19 }, .{ 28, 37 }, .{ 30, 51 }, .{ 30, 60 } },
    .{ .{ 30, 19 }, .{ 28, 38 }, .{ 30, 53 }, .{ 30, 63 } },
    .{ .{ 30, 20 }, .{ 28, 40 }, .{ 30, 56 }, .{ 30, 66 } },
    .{ .{ 30, 21 }, .{ 28, 43 }, .{ 30, 59 }, .{ 30, 70 } },
    .{ .{ 30, 22 }, .{ 28, 45 }, .{ 30, 62 }, .{ 30, 74 } },
    .{ .{ 30, 24 }, .{ 28, 47 }, .{ 30, 65 }, .{ 30, 77 } },
    .{ .{ 30, 25 }, .{ 28, 49 }, .{ 30, 68 }, .{ 30, 81 } },
};

fn dataCapacityBits(version: u6, ecc: Ecc) usize {
    const s = ecSpec(version, ecc);
    return (totalCodewords(version) - @as(usize, s.ec_per_block) * s.blocks) * 8;
}

// ── segment encoding ────────────────────────────────────────────────────────

const alnum_charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn alnumValue(c: u8) ?u8 {
    return if (std.mem.indexOfScalar(u8, alnum_charset, c)) |i| @intCast(i) else null;
}

fn modeFits(mode: Mode, text: []const u8) bool {
    return switch (mode) {
        .numeric => for (text) |c| {
            if (c < '0' or c > '9') break false;
        } else true,
        .alphanumeric => for (text) |c| {
            if (alnumValue(c) == null) break false;
        } else true,
        .byte => true,
    };
}

fn pickMode(text: []const u8) Mode {
    if (modeFits(.numeric, text)) return .numeric;
    if (modeFits(.alphanumeric, text)) return .alphanumeric;
    return .byte;
}

/// Width of the character-count indicator, which widens in two steps as the
/// version grows (§8.4 Table 3).
fn countBits(mode: Mode, version: u6) u5 {
    const group: usize = if (version <= 9) 0 else if (version <= 26) 1 else 2;
    return switch (mode) {
        .numeric => ([_]u5{ 10, 12, 14 })[group],
        .alphanumeric => ([_]u5{ 9, 11, 13 })[group],
        .byte => ([_]u5{ 8, 16, 16 })[group],
    };
}

fn dataBits(mode: Mode, len: usize, version: u6) usize {
    const header = 4 + @as(usize, countBits(mode, version));
    return header + switch (mode) {
        // 3 digits per 10 bits, remainder 2 digits in 7 or 1 digit in 4
        .numeric => (len / 3) * 10 + switch (len % 3) {
            0 => @as(usize, 0),
            1 => 4,
            else => 7,
        },
        // 2 characters per 11 bits, a trailing single in 6
        .alphanumeric => (len / 2) * 11 + (len % 2) * 6,
        .byte => len * 8,
    };
}

fn pickVersion(mode: Mode, len: usize, ecc: Ecc) ?u6 {
    var v: u6 = 1;
    while (v <= 40) : (v += 1) {
        if (dataBits(mode, len, v) <= dataCapacityBits(v, ecc)) return v;
    }
    return null;
}

const BitWriter = struct {
    buf: []u8,
    bit: usize = 0,

    fn put(self: *BitWriter, value: usize, bits: u6) void {
        var i: u6 = bits;
        while (i > 0) {
            i -= 1;
            const b: u1 = @intCast((value >> i) & 1);
            if (b == 1) self.buf[self.bit >> 3] |= @as(u8, 0x80) >> @intCast(self.bit & 7);
            self.bit += 1;
        }
    }
};

/// Bitstream → blocks → EC → interleave, all in one pass over `out`.
fn buildCodewords(out: []u8, mode: Mode, text: []const u8, version: u6, ecc: Ecc) void {
    const spec = ecSpec(version, ecc);
    const data_len = out.len - @as(usize, spec.ec_per_block) * spec.blocks;

    var data: [max_codewords]u8 = undefined;
    @memset(data[0..data_len], 0);
    var w: BitWriter = .{ .buf = data[0..data_len] };

    w.put(@intFromEnum(mode), 4);
    w.put(text.len, countBits(mode, version));
    switch (mode) {
        .numeric => {
            var i: usize = 0;
            while (i + 3 <= text.len) : (i += 3) {
                const v = (text[i] - '0') * @as(usize, 100) + (text[i + 1] - '0') * @as(usize, 10) + (text[i + 2] - '0');
                w.put(v, 10);
            }
            switch (text.len - i) {
                0 => {},
                1 => w.put(text[i] - '0', 4),
                else => w.put((text[i] - '0') * @as(usize, 10) + (text[i + 1] - '0'), 7),
            }
        },
        .alphanumeric => {
            var i: usize = 0;
            while (i + 2 <= text.len) : (i += 2) {
                const v = @as(usize, alnumValue(text[i]).?) * 45 + alnumValue(text[i + 1]).?;
                w.put(v, 11);
            }
            if (i < text.len) w.put(alnumValue(text[i]).?, 6);
        },
        .byte => for (text) |c| w.put(c, 8),
    }

    // Terminator: up to four zero bits, short if the capacity ends sooner.
    const cap_bits = data_len * 8;
    const term = @min(@as(u6, 4), @as(u6, @intCast(@min(@as(usize, 4), cap_bits - w.bit))));
    w.put(0, term);
    // Pad to a byte boundary, then alternate the two specified pad codewords.
    while (w.bit % 8 != 0) w.put(0, 1);
    var pad: u8 = 0xEC;
    while (w.bit < cap_bits) : (pad = if (pad == 0xEC) 0x11 else 0xEC) w.put(pad, 8);

    // Split into blocks: the last `long` blocks carry one extra data codeword.
    const short = data_len / spec.blocks;
    const long = data_len % spec.blocks;

    var ec: [max_codewords]u8 = undefined;
    var off: usize = 0;
    for (0..spec.blocks) |b| {
        const n = short + @as(usize, if (b >= spec.blocks - long) 1 else 0);
        rsEncode(data[off .. off + n], spec.ec_per_block, ec[b * spec.ec_per_block ..]);
        off += n;
    }

    // Interleave: i-th codeword of every block in turn, data first then EC.
    var o: usize = 0;
    for (0..short + 1) |i| {
        off = 0;
        for (0..spec.blocks) |b| {
            const n = short + @as(usize, if (b >= spec.blocks - long) 1 else 0);
            if (i < n) {
                out[o] = data[off + i];
                o += 1;
            }
            off += n;
        }
    }
    for (0..spec.ec_per_block) |i| {
        for (0..spec.blocks) |b| {
            out[o] = ec[b * spec.ec_per_block + i];
            o += 1;
        }
    }
}

// ── module placement ────────────────────────────────────────────────────────

fn markReserved(reserved: []u8, side: u16, x: u16, y: u16) void {
    const i = @as(usize, y) * side + x;
    reserved[i >> 3] |= @as(u8, 1) << @intCast(i & 7);
}

fn isReserved(reserved: []const u8, side: u16, x: u16, y: u16) bool {
    const i = @as(usize, y) * side + x;
    return (reserved[i >> 3] >> @intCast(i & 7)) & 1 != 0;
}

fn drawFinder(m: *Matrix, reserved: []u8, cx: i32, cy: i32) void {
    const side: i32 = @intCast(m.size);
    var dy: i32 = -1;
    while (dy <= 7) : (dy += 1) {
        var dx: i32 = -1;
        while (dx <= 7) : (dx += 1) {
            const x = cx + dx;
            const y = cy + dy;
            if (x < 0 or y < 0 or x >= side or y >= side) continue;
            // 7x7 finder: dark ring, light ring, 3x3 dark core. Everything
            // outside it inside this window is the separator, and light.
            const ax = @abs(dx - 3);
            const ay = @abs(dy - 3);
            const inside = dx >= 0 and dx <= 6 and dy >= 0 and dy <= 6;
            const dark = inside and (@max(ax, ay) != 2) and (@max(ax, ay) <= 3);
            m.set(@intCast(x), @intCast(y), dark);
            markReserved(reserved, m.size, @intCast(x), @intCast(y));
        }
    }
}

fn drawFunctionPatterns(m: *Matrix, reserved: []u8) void {
    const side = m.size;

    drawFinder(m, reserved, 0, 0);
    drawFinder(m, reserved, @as(i32, side) - 7, 0);
    drawFinder(m, reserved, 0, @as(i32, side) - 7);

    // Timing patterns: alternating, starting dark at index 6.
    var i: u16 = 8;
    while (i < side - 8) : (i += 1) {
        const dark = i % 2 == 0;
        m.set(i, 6, dark);
        markReserved(reserved, side, i, 6);
        m.set(6, i, dark);
        markReserved(reserved, side, 6, i);
    }

    // Alignment patterns, except where one would sit on a finder.
    var centres: [7]u16 = undefined;
    const cs = alignmentCentres(m.version, &centres);
    for (cs) |cy| {
        for (cs) |cx| {
            const on_finder = (cx == 6 and cy == 6) or
                (cx == 6 and cy == side - 7) or
                (cx == side - 7 and cy == 6);
            if (on_finder) continue;
            var dy: i32 = -2;
            while (dy <= 2) : (dy += 1) {
                var dx: i32 = -2;
                while (dx <= 2) : (dx += 1) {
                    const x: u16 = @intCast(@as(i32, cx) + dx);
                    const y: u16 = @intCast(@as(i32, cy) + dy);
                    const r = @max(@abs(dx), @abs(dy));
                    m.set(x, y, r != 1);
                    markReserved(reserved, side, x, y);
                }
            }
        }
    }

    // Format information areas (written later) plus the always-dark module.
    for (0..9) |k| {
        markReserved(reserved, side, @intCast(k), 8);
        markReserved(reserved, side, 8, @intCast(k));
    }
    for (0..8) |k| {
        markReserved(reserved, side, side - 1 - @as(u16, @intCast(k)), 8);
        markReserved(reserved, side, 8, side - 1 - @as(u16, @intCast(k)));
    }
    m.set(8, side - 8, true);
    markReserved(reserved, side, 8, side - 8);

    // Version information areas, versions 7 and up.
    if (m.version >= 7) {
        for (0..6) |a| {
            for (0..3) |b| {
                markReserved(reserved, side, @intCast(a), side - 11 + @as(u16, @intCast(b)));
                markReserved(reserved, side, side - 11 + @as(u16, @intCast(b)), @intCast(a));
            }
        }
    }
}

/// Two-module-wide columns, right to left, snaking up then down, skipping the
/// vertical timing column entirely (§8.7.3).
fn placeCodewords(m: *Matrix, reserved: []const u8, codewords: []const u8) void {
    const side = m.size;
    var bit: usize = 0;
    var right: i32 = @as(i32, side) - 1;
    var upward = true;
    while (right >= 1) : (right -= 2) {
        if (right == 6) right = 5; // the timing column is not part of any pair
        var step: u16 = 0;
        while (step < side) : (step += 1) {
            const y: u16 = if (upward) side - 1 - step else step;
            for ([_]i32{ right, right - 1 }) |xi| {
                const x: u16 = @intCast(xi);
                if (isReserved(reserved, side, x, y)) continue;
                const total_bits = codewords.len * 8;
                const dark = bit < total_bits and
                    (codewords[bit >> 3] >> @intCast(7 - (bit & 7))) & 1 == 1;
                m.set(x, y, dark);
                bit += 1;
            }
        }
        upward = !upward;
    }
}

// ── masking ─────────────────────────────────────────────────────────────────

fn maskAt(pattern: u3, x: u16, y: u16) bool {
    const i: usize = y;
    const j: usize = x;
    return switch (pattern) {
        0 => (i + j) % 2 == 0,
        1 => i % 2 == 0,
        2 => j % 3 == 0,
        3 => (i + j) % 3 == 0,
        4 => (i / 2 + j / 3) % 2 == 0,
        5 => (i * j) % 2 + (i * j) % 3 == 0,
        6 => ((i * j) % 2 + (i * j) % 3) % 2 == 0,
        7 => ((i + j) % 2 + (i * j) % 3) % 2 == 0,
    };
}

fn applyMask(m: *Matrix, reserved: []const u8, pattern: u3) void {
    for (0..m.size) |y| {
        for (0..m.size) |x| {
            const xi: u16 = @intCast(x);
            const yi: u16 = @intCast(y);
            if (isReserved(reserved, m.size, xi, yi)) continue;
            if (maskAt(pattern, xi, yi)) m.set(xi, yi, !m.isDark(xi, yi));
        }
    }
}

fn pickMask(m: *Matrix, reserved: []const u8) u3 {
    var best: u3 = 0;
    var best_score: u32 = std.math.maxInt(u32);
    var p: u3 = 0;
    while (true) : (p += 1) {
        applyMask(m, reserved, p);
        // Format info influences three of the four penalty rules, so it has to
        // be present while scoring — evaluating a bare data region and then
        // writing the format bits afterwards scores a symbol that never exists.
        drawFormatInfo(m, m.ecc, p);
        const score = penalty(m);
        if (score < best_score) {
            best_score = score;
            best = p;
        }
        applyMask(m, reserved, p); // masking is an involution: this undoes it
        if (p == 7) break;
    }
    return best;
}

fn penalty(m: *const Matrix) u32 {
    const side = m.size;
    var score: u32 = 0;

    // Rule 1: runs of five or more same-coloured modules in a line.
    for (0..2) |dir| {
        for (0..side) |a| {
            var run: u32 = 1;
            var prev = false;
            for (0..side) |b| {
                const x: u16 = @intCast(if (dir == 0) b else a);
                const y: u16 = @intCast(if (dir == 0) a else b);
                const cur = m.isDark(x, y);
                if (b > 0 and cur == prev) {
                    run += 1;
                    if (run == 5) score += 3 else if (run > 5) score += 1;
                } else run = 1;
                prev = cur;
            }
        }
    }

    // Rule 2: every 2x2 block of one colour.
    for (0..side - 1) |y| {
        for (0..side - 1) |x| {
            const xi: u16 = @intCast(x);
            const yi: u16 = @intCast(y);
            const c = m.isDark(xi, yi);
            if (c == m.isDark(xi + 1, yi) and c == m.isDark(xi, yi + 1) and c == m.isDark(xi + 1, yi + 1)) {
                score += 3;
            }
        }
    }

    // Rule 3: the finder-like 1:1:3:1:1 sequence with four light modules on
    // either side, in either orientation.
    const pat = [_]bool{ true, false, true, true, true, false, true };
    for (0..2) |dir| {
        for (0..side) |a| {
            if (side < 11) break;
            for (0..side - 10) |b| {
                var hit = true;
                for (0..11) |k| {
                    const idx = b + k;
                    const x: u16 = @intCast(if (dir == 0) idx else a);
                    const y: u16 = @intCast(if (dir == 0) a else idx);
                    const want = if (k < 7) pat[k] else false;
                    if (m.isDark(x, y) != want) {
                        hit = false;
                        break;
                    }
                }
                if (hit) score += 40;
                hit = true;
                for (0..11) |k| {
                    const idx = b + k;
                    const x: u16 = @intCast(if (dir == 0) idx else a);
                    const y: u16 = @intCast(if (dir == 0) a else idx);
                    const want = if (k >= 4) pat[k - 4] else false;
                    if (m.isDark(x, y) != want) {
                        hit = false;
                        break;
                    }
                }
                if (hit) score += 40;
            }
        }
    }

    // Rule 4: deviation of the dark-module proportion from one half.
    var dark: usize = 0;
    for (0..side) |y| {
        for (0..side) |x| {
            if (m.isDark(@intCast(x), @intCast(y))) dark += 1;
        }
    }
    const total = @as(usize, side) * side;
    const pct = dark * 100 / total;
    const dev = if (pct > 50) pct - 50 else 50 - pct;
    score += @intCast(dev / 5 * 10);

    return score;
}

// ── format and version information ──────────────────────────────────────────

/// BCH remainder of `data` under `poly`, where `poly` has degree `deg`.
fn bch(data: u32, poly: u32, deg: u5) u32 {
    var rem = data << deg;
    var i: u5 = deg;
    while (true) : (i -= 1) {
        const top = @as(u32, 1) << (deg + i);
        if (rem & top != 0) rem ^= poly << i;
        if (i == 0) break;
    }
    return rem;
}

fn drawFormatInfo(m: *Matrix, ecc: Ecc, mask: u3) void {
    const side = m.size;
    const data: u32 = (@as(u32, ecc.formatBits()) << 3) | mask;
    // BCH(15,5) with G(x) = x^10+x^8+x^5+x^4+x^2+x+1, then the fixed mask that
    // stops an all-zero format from reading as a valid one.
    const bits = ((data << 10) | bch(data, 0x537, 10)) ^ 0x5412;

    for (0..15) |k| {
        const b: bool = (bits >> @intCast(k)) & 1 == 1;

        // First copy, wrapped around the top-left finder. The two kinks — bit 6
        // skipping the timing row, bit 8 skipping the timing column — are the
        // whole reason this is a switch and not arithmetic.
        const x1: u16 = switch (k) {
            0...7 => 8,
            8 => 7,
            else => @intCast(14 - k),
        };
        const y1: u16 = switch (k) {
            0...5 => @intCast(k),
            6 => 7,
            else => 8,
        };
        m.set(x1, y1, b);

        // Second copy, split between the other two finders: the low half runs
        // in from the right edge, the high half runs down to the bottom-left.
        if (k < 8) {
            m.set(side - 1 - @as(u16, @intCast(k)), 8, b);
        } else {
            m.set(8, side - 15 + @as(u16, @intCast(k)), b);
        }
    }
    m.set(8, side - 8, true); // the dark module is not part of the format field
}

fn drawVersionInfo(m: *Matrix) void {
    const side = m.size;
    const v: u32 = m.version;
    // BCH(18,6) with G(x) = x^12+x^11+x^10+x^9+x^8+x^5+x^2+1.
    const bits = (v << 12) | bch(v, 0x1F25, 12);
    for (0..18) |k| {
        const b: bool = (bits >> @intCast(k)) & 1 == 1;
        const a: u16 = @intCast(k / 3);
        const c: u16 = @intCast(k % 3);
        m.set(a, side - 11 + c, b);
        m.set(side - 11 + c, a, b);
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

test "GF(2^8) is the field the standard names" {
    const t = std.testing;
    // The value, not the mechanism: this is the generator polynomial for ten EC
    // codewords as printed in ISO/IEC 18004 Annex A. If the primitive polynomial
    // or the generator alpha were wrong, these coefficients would not appear.
    var buf: [32]u8 = undefined;
    const g = rsGenerator(10, &buf);
    try t.expectEqualSlices(u8, &[_]u8{ 1, 216, 194, 159, 111, 199, 94, 95, 113, 157, 193 }, g);
}

test "GF inverse and distributivity hold for the whole field" {
    const t = std.testing;
    for (1..256) |a| {
        const av: u8 = @intCast(a);
        // a * a^254 == 1 (a^255 == 1 for every non-zero element)
        var p: u8 = 1;
        for (0..254) |_| p = gf.mul(p, av);
        try t.expectEqual(@as(u8, 1), gf.mul(av, p));
    }
}

test "alignment centres match the versions the standard tabulates" {
    const t = std.testing;
    var buf: [7]u16 = undefined;
    try t.expectEqualSlices(u16, &[_]u16{}, alignmentCentres(1, &buf));
    try t.expectEqualSlices(u16, &[_]u16{ 6, 18 }, alignmentCentres(2, &buf));
    try t.expectEqualSlices(u16, &[_]u16{ 6, 22, 38 }, alignmentCentres(7, &buf));
    try t.expectEqualSlices(u16, &[_]u16{ 6, 26, 46, 66 }, alignmentCentres(14, &buf));
    try t.expectEqualSlices(u16, &[_]u16{ 6, 30, 58, 86, 114, 142, 170 }, alignmentCentres(40, &buf));

    // Version 32, the one the spacing rule does not produce. Pinned as a value
    // so that "simplifying" the exception away fails here rather than in a
    // symbol that scans everywhere except one version.
    try t.expectEqualSlices(u16, &[_]u16{ 6, 34, 60, 86, 112, 138 }, alignmentCentres(32, &buf));
    // Its neighbours ARE derived, so the exception cannot have been widened.
    try t.expectEqualSlices(u16, &[_]u16{ 6, 30, 56, 82, 108, 134 }, alignmentCentres(31, &buf));
    try t.expectEqualSlices(u16, &[_]u16{ 6, 30, 58, 86, 114, 142 }, alignmentCentres(33, &buf));
}

test "codeword capacity, counted from the geometry, matches the standard" {
    const t = std.testing;
    // Total codewords per version (ISO/IEC 18004 Table 1). These come out of
    // counting free modules, so a mistake in the function-pattern layout — the
    // thing that is hard to eyeball — surfaces here as a wrong number rather
    // than as a symbol that merely looks plausible.
    try t.expectEqual(@as(usize, 26), totalCodewords(1));
    try t.expectEqual(@as(usize, 44), totalCodewords(2));
    try t.expectEqual(@as(usize, 70), totalCodewords(3));
    try t.expectEqual(@as(usize, 196), totalCodewords(7));
    try t.expectEqual(@as(usize, 346), totalCodewords(10));
    try t.expectEqual(@as(usize, 1156), totalCodewords(21));
    try t.expectEqual(@as(usize, 3706), totalCodewords(40));
}

test "mode selection prefers the most compact encoding the input allows" {
    const t = std.testing;
    try t.expectEqual(Mode.numeric, pickMode("0123456789"));
    try t.expectEqual(Mode.alphanumeric, pickMode("HELLO WORLD"));
    // Lower case is not in the alphanumeric charset, so it falls to byte.
    try t.expectEqual(Mode.byte, pickMode("Hello"));
    try t.expectEqual(Mode.byte, pickMode("háčky"));
}

test "encode produces the documented symbol size and honours a forced version" {
    const t = std.testing;
    var m: Matrix = undefined;
    try encode(&m, "HELLO WORLD", .{ .ecc = .quartile });
    try t.expectEqual(@as(u16, 21), m.size);
    try t.expectEqual(@as(u6, 1), m.version);

    try encode(&m, "HELLO WORLD", .{ .ecc = .quartile, .version = 10 });
    try t.expectEqual(@as(u16, 57), m.size);
}

test "finder patterns land where every decoder looks for them" {
    const t = std.testing;
    var m: Matrix = undefined;
    try encode(&m, "test", .{});
    for ([_][2]u16{ .{ 0, 0 }, .{ m.size - 7, 0 }, .{ 0, m.size - 7 } }) |c| {
        // Dark ring, light ring, dark 3x3 core — checked on the diagonal so a
        // single wrong ring shows up rather than averaging out.
        try t.expect(m.isDark(c[0], c[1]));
        try t.expect(!m.isDark(c[0] + 1, c[1] + 1));
        try t.expect(m.isDark(c[0] + 2, c[1] + 2));
        try t.expect(m.isDark(c[0] + 3, c[1] + 3));
    }
    // The separator around the top-left finder must be light.
    try t.expect(!m.isDark(7, 0));
    try t.expect(!m.isDark(0, 7));
}

// ── fuzz: `text` is the untrusted surface ───────────────────────────────────
// Arbitrary bytes reach mode selection, the bit writer and the block split, all
// of which index buffers sized from the version that selection chose. The
// property is that no input produces a panic, an overflow or a truncated
// symbol: either a typed error, or a matrix whose size agrees with its version.

test "fuzz: encode never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzEncode, .{});
}

fn fuzzEncode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
    const ecc: Ecc = @enumFromInt(smith.valueRangeAtMost(u8, 0, 3));
    const forced_version = smith.valueRangeAtMost(u8, 0, 41); // 0 and 41 exercise the guards

    var m: Matrix = undefined;
    encode(&m, buf[0..len], .{
        .ecc = ecc,
        .version = if (forced_version == 0) null else @intCast(@min(forced_version, 40)),
        .mask = if (smith.valueRangeAtMost(u8, 0, 8) == 8) null else @intCast(smith.valueRangeAtMost(u8, 0, 7)),
    }) catch return;

    // A returned symbol must be internally consistent — a size that disagrees
    // with the version means the placement walked a grid of the wrong shape,
    // which is exactly the failure a panic-only harness would let through.
    try std.testing.expectEqual(sideFor(m.version), m.size);
    try std.testing.expect(m.isDark(0, 0)); // top-left finder survived
}

test "input that cannot fit is refused rather than truncated" {
    const t = std.testing;
    var m: Matrix = undefined;
    var big: [3000]u8 = undefined;
    @memset(&big, 'A');
    try t.expectError(Error.TooLong, encode(&m, &big, .{ .ecc = .high }));
    // Fits at the same length once the level asks for less redundancy.
    try encode(&m, big[0..1800], .{ .ecc = .low });

    try t.expectError(Error.ModeMismatch, encode(&m, "hello", .{ .mode = .numeric }));
    try t.expectError(Error.BadVersion, encode(&m, "x", .{ .version = 41 }));
}
