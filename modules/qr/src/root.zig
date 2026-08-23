// SPDX-License-Identifier: MIT
//! qr — QR Code symbol encoder and decoder (ISO/IEC 18004 model 2), versions
//! 1–40, all four error-correction levels, numeric/alphanumeric/byte modes.
//! Decoding includes Reed-Solomon error correction, which is the half an
//! encoder never needs and the reason this is not simply `encode` run backwards.
//!
//! **Matrices in and out, not pictures.** A QR symbol *is* a grid of dark and
//! light modules, and that grid is what `encode` produces and `decode` consumes;
//! the codec has no pixel format anywhere in it. `writeSvg` and `writeTerminal`
//! sit on top in `render.zig` as a convenience for the two places a symbol
//! actually leaves a program — an HTTP response and a terminal — and they are
//! separable by construction: nothing in the codec calls them, and neither can
//! change what a symbol says.
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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "QR Code encoder and decoder (ISO/IEC 18004 model 2) — versions 1–40, levels L/M/Q/H, numeric/alphanumeric/byte modes, Reed-Solomon error correction, structured append; SVG and terminal renderers, allocation-free.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .wasm32 },
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

/// One symbol's place in a structured-append sequence (ISO/IEC 18004 §8.4.6):
/// a message too big for one symbol, split across up to sixteen that a reader
/// puts back together. `encodeSequence` fills these in; `decodePart` reports
/// them.
pub const Sequence = struct {
    /// Position of this symbol, counting from zero.
    index: u4,
    /// How many symbols the message was split into, 1–16.
    total: u5,
    /// XOR of every byte of the *whole* message, the same value in every symbol
    /// of the sequence. It is what lets a reader notice that it has mixed two
    /// sequences together, or is missing a symbol it never saw — an index and a
    /// count alone cannot tell a foreign symbol from a missing one.
    parity: u8,
};

/// The parity byte a structured-append sequence carries: XOR of every byte of
/// the message. Exposed because reassembly happens in the caller — this module
/// allocates nothing and cannot hold sixteen decoded parts for you — and the
/// check is the point of the field.
pub fn sequenceParity(message: []const u8) u8 {
    var p: u8 = 0;
    for (message) |c| p ^= c;
    return p;
}

pub const Error = error{
    /// The input does not fit any version at the requested level, does not fit
    /// the version that was forced, or — for `encodeSequence` — needs more
    /// symbols than `out` holds or more than the sixteen the standard allows.
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

// ── rendering (render.zig) ──────────────────────────────────────────────────

const render = @import("render.zig");

/// Write a symbol as a standalone SVG document.
pub const writeSvg = render.writeSvg;
pub const SvgOptions = render.SvgOptions;
/// Write a symbol as UTF-8 half-block text, two module rows per line.
pub const writeTerminal = render.writeTerminal;
pub const TerminalOptions = render.TerminalOptions;

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

    /// Set one module. Public because a decoder's caller has to be able to
    /// BUILD a matrix — a scanner reads modules off an image and hands the grid
    /// to `decode`, and with this private that path does not compile at all.
    /// Encoding never needs it.
    pub fn setDark(self: *Matrix, x: u16, y: u16, dark: bool) void {
        const i = @as(usize, y) * self.size + x;
        const m = @as(u8, 1) << @intCast(i & 7);
        if (dark) self.bits[i >> 3] |= m else self.bits[i >> 3] &= ~m;
    }
};

/// Encode `text` into `out`. Allocates nothing: `out` is the only storage the
/// caller provides, and everything else lives on this frame.
pub fn encode(out: *Matrix, text: []const u8, opts: Options) Error!void {
    return encodeOne(out, text, opts, null);
}

/// Split `text` across a structured-append sequence and encode every symbol
/// into `out`, returning the prefix that was filled.
///
/// `opts.version` fixes the size of *every* symbol; without it the smallest
/// version that fits the message in `out.len` symbols is chosen. Every symbol
/// in the sequence gets the same version either way, which the standard does
/// not require but a reader displaying them one after another very much
/// appreciates — and it keeps the last, short symbol from silently coming out a
/// different size from the rest.
///
/// The 20-bit header each symbol carries (mode, position, count, parity) is
/// pure overhead, so splitting a message that fits in one symbol makes it
/// bigger. This is for messages that do not fit: a signing request, a PSBT, a
/// certificate — anything a phone has to receive through a camera.
pub fn encodeSequence(out: []Matrix, text: []const u8, opts: Options) Error![]Matrix {
    if (out.len == 0) return Error.TooLong;

    const mode = if (opts.mode) |m| blk: {
        if (!modeFits(m, text)) return Error.ModeMismatch;
        break :blk m;
    } else pickMode(text);

    const room = @min(out.len, max_sequence);
    var version: u6 = 0;
    var chunk: usize = 0;
    if (opts.version) |v| {
        if (v < 1 or v > 40) return Error.BadVersion;
        version = v;
        chunk = maxChunk(mode, v, opts.ecc);
        if (chunk == 0 or symbolsNeeded(text.len, chunk) > room) return Error.TooLong;
    } else {
        var v: u6 = 1;
        while (v <= 40) : (v += 1) {
            const c = maxChunk(mode, v, opts.ecc);
            if (c > 0 and symbolsNeeded(text.len, c) <= room) {
                version = v;
                chunk = c;
                break;
            }
        } else return Error.TooLong;
    }

    const n = symbolsNeeded(text.len, chunk);
    const parity = sequenceParity(text);
    var sub = opts;
    sub.version = version;
    sub.mode = mode;

    for (0..n) |i| {
        const start = i * chunk;
        const end = @min(start + chunk, text.len);
        try encodeOne(&out[i], text[start..end], sub, .{
            .index = @intCast(i),
            .total = @intCast(n),
            .parity = parity,
        });
    }
    return out[0..n];
}

/// Sixteen, because the position and count are four bits each (§8.4.6).
const max_sequence = 16;

fn symbolsNeeded(len: usize, chunk: usize) usize {
    if (len == 0) return 1;
    return (len + chunk - 1) / chunk;
}

/// Longest chunk, in characters, that still fits once the structured-append
/// header has taken its 20 bits. Monotonic in the length, so a binary search is
/// exact and does not need `dataBits` inverted per mode.
fn maxChunk(mode: Mode, version: u6, ecc: Ecc) usize {
    const cap = dataCapacityBits(version, ecc);
    if (cap <= sequence_header_bits) return 0;

    var lo: usize = 0;
    var hi: usize = cap; // any length needs at least a bit per character
    while (lo < hi) {
        const mid = (lo + hi + 1) / 2;
        if (sequence_header_bits + dataBits(mode, mid, version) <= cap) lo = mid else hi = mid - 1;
    }
    // The character-count field is finite too, and for a short numeric symbol it
    // is the binding constraint rather than the capacity.
    const count_max = (@as(usize, 1) << countBits(mode, version)) - 1;
    return @min(lo, count_max);
}

/// Mode indicator, position, count, parity (§8.4.6).
const sequence_header_bits = 4 + 4 + 4 + 8;
const sequence_mode: u4 = 0b0011;

fn encodeOne(out: *Matrix, text: []const u8, opts: Options, seq: ?Sequence) Error!void {
    const mode = if (opts.mode) |m| blk: {
        if (!modeFits(m, text)) return Error.ModeMismatch;
        break :blk m;
    } else pickMode(text);

    const extra: usize = if (seq == null) 0 else sequence_header_bits;
    const version = if (opts.version) |v| blk: {
        if (v < 1 or v > 40) return Error.BadVersion;
        if (extra + dataBits(mode, text.len, v) > dataCapacityBits(v, opts.ecc)) return Error.TooLong;
        break :blk v;
    } else pickVersion(mode, text.len, opts.ecc, extra) orelse return Error.TooLong;

    var codewords: [max_codewords]u8 = undefined;
    const total = totalCodewords(version);
    buildCodewords(codewords[0..total], mode, text, version, opts.ecc, seq);

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

    /// Multiplicative inverse; `inverse(0)` is 0 by convention and every caller
    /// here guards the zero case before it matters. Used only by the decoder —
    /// encoding never divides.
    fn inverse(a: u8) u8 {
        if (a == 0) return 0;
        return t.exp[255 - @as(u16, t.log[a])];
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

/// Alignment-pattern centre coordinates (ISO/IEC 18004 §6.3.6), one axis; a
/// pattern sits at every pair of these except the three that would collide with
/// a finder. Public because a scanner needs them: they are the only landmarks
/// inside the symbol, and a grid fitted to the three finder corners alone drifts
/// by half a module across a large version.
///
/// The standard
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
pub fn alignmentCentres(version: u6, out: *[7]u16) []const u16 {
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

fn pickVersion(mode: Mode, len: usize, ecc: Ecc, extra_bits: usize) ?u6 {
    var v: u6 = 1;
    while (v <= 40) : (v += 1) {
        if (extra_bits + dataBits(mode, len, v) <= dataCapacityBits(v, ecc)) return v;
    }
    return null;
}

const BitWriter = struct {
    buf: []u8,
    bit: usize = 0,

    /// `value` is u64 rather than usize on purpose: the shift amount below has
    /// to be valid for the widest value this ever carries, and on a 32-bit
    /// target (wasm32, arm32) `usize` shifts want a u5 while the bit widths here
    /// go to 16. Typing the value instead of the shift keeps one definition
    /// that is correct on both.
    fn put(self: *BitWriter, value: u64, bits: u6) void {
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
fn buildCodewords(out: []u8, mode: Mode, text: []const u8, version: u6, ecc: Ecc, seq: ?Sequence) void {
    const spec = ecSpec(version, ecc);
    const data_len = out.len - @as(usize, spec.ec_per_block) * spec.blocks;

    var data: [max_codewords]u8 = undefined;
    @memset(data[0..data_len], 0);
    var w: BitWriter = .{ .buf = data[0..data_len] };

    // The structured-append header is a segment of its own and comes first
    // (§8.4.6): a reader has to know it is holding a fragment before it reads
    // anything that looks like a message.
    if (seq) |q| {
        w.put(sequence_mode, 4);
        w.put(q.index, 4);
        w.put(@as(u64, q.total) - 1, 4);
        w.put(q.parity, 8);
    }

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
            m.setDark(@intCast(x), @intCast(y), dark);
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
        m.setDark(i, 6, dark);
        markReserved(reserved, side, i, 6);
        m.setDark(6, i, dark);
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
                    m.setDark(x, y, r != 1);
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
    m.setDark(8, side - 8, true);
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
/// The walk itself, shared by writing and reading. Having one definition is the
/// point: a decoder that re-derives the order is a second chance to get it
/// wrong, and the two would disagree only on inputs neither test covers.
const Walk = struct {
    side: u16,
    reserved: []const u8,
    right: i32,
    step: u16 = 0,
    pair: u1 = 0,
    upward: bool = true,

    fn init(side: u16, reserved: []const u8) Walk {
        return .{ .side = side, .reserved = reserved, .right = @as(i32, side) - 1 };
    }

    fn next(self: *Walk) ?[2]u16 {
        while (self.right >= 1) {
            if (self.right == 6) self.right = 5; // timing column joins no pair
            while (self.step < self.side) {
                const y: u16 = if (self.upward) self.side - 1 - self.step else self.step;
                const x: u16 = @intCast(self.right - @as(i32, self.pair));
                const last_of_pair = self.pair == 1;
                self.pair +%= 1;
                if (last_of_pair) self.step += 1;
                if (!isReserved(self.reserved, self.side, x, y)) return .{ x, y };
            }
            self.step = 0;
            self.upward = !self.upward;
            self.right -= 2;
        }
        return null;
    }
};

fn placeCodewords(m: *Matrix, reserved: []const u8, codewords: []const u8) void {
    var w = Walk.init(m.size, reserved);
    var bit: usize = 0;
    const total_bits = codewords.len * 8;
    while (w.next()) |p| : (bit += 1) {
        const dark = bit < total_bits and
            (codewords[bit >> 3] >> @intCast(7 - (bit & 7))) & 1 == 1;
        m.setDark(p[0], p[1], dark);
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
            if (maskAt(pattern, xi, yi)) m.setDark(xi, yi, !m.isDark(xi, yi));
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
        m.setDark(x1, y1, b);

        // Second copy, split between the other two finders: the low half runs
        // in from the right edge, the high half runs down to the bottom-left.
        if (k < 8) {
            m.setDark(side - 1 - @as(u16, @intCast(k)), 8, b);
        } else {
            m.setDark(8, side - 15 + @as(u16, @intCast(k)), b);
        }
    }
    m.setDark(8, side - 8, true); // the dark module is not part of the format field
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
        m.setDark(a, side - 11 + c, b);
        m.setDark(side - 11 + c, a, b);
    }
}

// ── decoding ────────────────────────────────────────────────────────────────
//
// Matrix in, text out — the inverse of everything above, including Reed-Solomon
// error *correction*, which is the half an encoder never needs and the reason a
// decoder is not simply the encoder run backwards.
//
// Reading a symbol off a photograph is a different problem (binarisation,
// locating the symbol, perspective correction, grid sampling) and deliberately
// not here: it is image processing, it would drag `platform` and a pixel format
// into a module that has neither, and every mature ecosystem splits it the same
// way. This entry point is what such a scanner would call once it has a grid.

pub const DecodeError = error{
    /// `size` is not 17 + 4v for some v in 1..40.
    BadSize,
    /// Neither copy of the format information decoded to a valid value.
    BadFormat,
    /// A block carried more errors than its level can correct.
    Uncorrectable,
    /// The corrected codewords are not a well-formed segment stream.
    BadData,
    /// `out` is shorter than the decoded message.
    BufferTooSmall,
    /// The symbol is one part of a structured-append sequence, and `decode`
    /// returns only whole messages. Use `decodePart`. This is an error rather
    /// than a silent fragment on purpose: a caller handed part two of three and
    /// told nothing would act on a truncated message, and for the payloads that
    /// need splitting — a signing request, a PSBT — that is the expensive
    /// failure.
    StructuredAppend,
};

/// One decoded symbol. `sequence` is null for an ordinary symbol and present
/// for one part of a structured-append message; in the second case `data` is
/// that part's fragment, not the message.
pub const Part = struct {
    data: []u8,
    sequence: ?Sequence,
};

/// Decode `m` into `out`, returning the message. Corrects up to the symbol's
/// declared capability; beyond that it reports `Uncorrectable` rather than
/// returning plausible rubbish, which is the failure mode that matters — a
/// silently mis-corrected QR code is worse than one that refuses to read.
pub fn decode(m: *const Matrix, out: []u8) DecodeError![]u8 {
    const part = try decodePart(m, out);
    if (part.sequence != null) return DecodeError.StructuredAppend;
    return part.data;
}

/// Decode a symbol that may be one part of a structured-append sequence.
///
/// Reassembly is the caller's: concatenate the parts in index order and check
/// `qr.sequenceParity` of the result against the `parity` every part carries.
/// This module allocates nothing, so it cannot hold sixteen fragments for you —
/// and the parity check is what distinguishes "a symbol is missing" from "two
/// different sequences were scanned into the same buffer", which an index and a
/// count cannot.
pub fn decodePart(m: *const Matrix, out: []u8) DecodeError!Part {
    if (m.size < 21 or m.size > max_size or (m.size - 17) % 4 != 0) return DecodeError.BadSize;
    const version: u6 = @intCast((m.size - 17) / 4);

    const fmt = readFormatInfo(m) orelse return DecodeError.BadFormat;

    // Rebuild the function-pattern map from the version alone: it is fully
    // determined, so a decoder never has to trust the symbol about it.
    var scratch: Matrix = .{ .size = m.size, .version = version };
    @memset(&scratch.bits, 0);
    var reserved: [(max_size * max_size + 7) / 8]u8 = undefined;
    @memset(&reserved, 0);
    drawFunctionPatterns(&scratch, &reserved);

    // Unmask into a working copy, then read the codewords back along the very
    // same walk the encoder wrote them on.
    var work = m.*;
    applyMask(&work, &reserved, fmt.mask);

    const total = totalCodewords(version);
    var raw: [max_codewords]u8 = undefined;
    @memset(raw[0..total], 0);
    var w = Walk.init(m.size, &reserved);
    var bit: usize = 0;
    while (w.next()) |p| : (bit += 1) {
        if (bit >= total * 8) break;
        if (work.isDark(p[0], p[1])) raw[bit >> 3] |= @as(u8, 0x80) >> @intCast(bit & 7);
    }

    // De-interleave, correct each block, and reassemble the data half.
    const spec = ecSpec(version, fmt.ecc);
    const data_len = total - @as(usize, spec.ec_per_block) * spec.blocks;
    const short = data_len / spec.blocks;
    const long = data_len % spec.blocks;

    var data: [max_codewords]u8 = undefined;
    var block: [255]u8 = undefined;
    var o: usize = 0;
    for (0..spec.blocks) |b| {
        const n = short + @as(usize, if (b >= spec.blocks - long) 1 else 0);
        // data codewords: column b of the interleave, skipping the shorter
        // blocks once the round passes their length
        for (0..n) |i| {
            var idx: usize = 0;
            for (0..@min(i + 1, short + 1)) |round| {
                for (0..spec.blocks) |bb| {
                    const nn = short + @as(usize, if (bb >= spec.blocks - long) 1 else 0);
                    if (round < nn) {
                        if (round == i and bb == b) {
                            block[i] = raw[idx];
                        }
                        idx += 1;
                    }
                }
            }
        }
        for (0..spec.ec_per_block) |i| {
            block[n + i] = raw[data_len + i * spec.blocks + b];
        }
        try rsDecode(block[0 .. n + spec.ec_per_block], spec.ec_per_block);
        @memcpy(data[o .. o + n], block[0..n]);
        o += n;
    }

    var seq: ?Sequence = null;
    const text = try parseSegments(data[0..data_len], version, out, &seq);
    return .{ .data = text, .sequence = seq };
}

/// Both copies of the format information are read and the nearer valid codeword
/// wins. There are only 32 legal values, so "nearest by Hamming distance" is
/// exact rather than a heuristic, and it recovers the 3-bit errors the BCH code
/// is specified to survive without implementing BCH decoding at all.
fn readFormatInfo(m: *const Matrix) ?struct { ecc: Ecc, mask: u3 } {
    const side = m.size;
    var copies: [2]u32 = .{ 0, 0 };
    for (0..15) |k| {
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
        if (m.isDark(x1, y1)) copies[0] |= @as(u32, 1) << @intCast(k);

        const dark2 = if (k < 8)
            m.isDark(side - 1 - @as(u16, @intCast(k)), 8)
        else
            m.isDark(8, side - 15 + @as(u16, @intCast(k)));
        if (dark2) copies[1] |= @as(u32, 1) << @intCast(k);
    }

    var best_dist: u32 = 16;
    var best: u5 = 0;
    for (copies) |c| {
        for (0..32) |candidate| {
            const cand: u5 = @intCast(candidate);
            const encoded = ((@as(u32, cand) << 10) | bch(cand, 0x537, 10)) ^ 0x5412;
            const dist = @popCount(encoded ^ c);
            if (dist < best_dist) {
                best_dist = dist;
                best = cand;
            }
        }
    }
    if (best_dist > 3) return null; // beyond what the code can correct

    const ecc: Ecc = switch (@as(u2, @intCast(best >> 3))) {
        0b00 => .medium,
        0b01 => .low,
        0b10 => .high,
        0b11 => .quartile,
    };
    return .{ .ecc = ecc, .mask = @intCast(best & 0b111) };
}

/// Reed-Solomon decode in place: syndromes → Berlekamp-Massey → Chien → Forney.
fn rsDecode(block: []u8, ec_len: usize) DecodeError!void {
    const n = block.len;

    var synd: [30]u8 = undefined;
    var any = false;
    for (0..ec_len) |j| {
        var s: u8 = 0;
        for (block) |c| s = gf.mul(s, gf.t.exp[j]) ^ c; // Horner at alpha^j
        synd[j] = s;
        if (s != 0) any = true;
    }
    if (!any) return; // clean block, and the common case

    // Berlekamp-Massey: the shortest LFSR that generates the syndromes is the
    // error locator.
    var lambda: [31]u8 = [_]u8{0} ** 31;
    var prev: [31]u8 = [_]u8{0} ** 31;
    lambda[0] = 1;
    prev[0] = 1;
    var l: usize = 0;
    var shift: usize = 1;
    var b: u8 = 1;

    for (0..ec_len) |k| {
        var d: u8 = synd[k];
        for (1..l + 1) |i| d ^= gf.mul(lambda[i], synd[k - i]);
        if (d == 0) {
            shift += 1;
        } else if (2 * l <= k) {
            var t: [31]u8 = lambda;
            const scale = gf.mul(d, gf.inverse(b));
            for (0..31 - shift) |i| lambda[i + shift] ^= gf.mul(scale, prev[i]);
            l = k + 1 - l;
            prev = t;
            b = d;
            shift = 1;
            t = undefined;
        } else {
            const scale = gf.mul(d, gf.inverse(b));
            for (0..31 - shift) |i| lambda[i + shift] ^= gf.mul(scale, prev[i]);
            shift += 1;
        }
    }
    if (l > ec_len / 2) return DecodeError.Uncorrectable;

    // Chien search: the locator's roots are the INVERSE error locations, and
    // position i sits at alpha^(n-1-i) because the codeword is indexed with the
    // highest power first. Testing alpha^-i instead finds roots for a codeword
    // written the other way round — which still "corrects" a block, into
    // something that fails the syndrome re-check at the end rather than
    // decoding, so the mistake looks like an uncorrectable symbol.
    var positions: [15]usize = undefined;
    var count: usize = 0;
    for (0..n) |i| {
        const xinv = gf.t.exp[(255 - ((n - 1 - i) % 255)) % 255];
        var v: u8 = 0;
        var p: u8 = 1;
        for (0..l + 1) |j| {
            v ^= gf.mul(lambda[j], p);
            p = gf.mul(p, xinv);
        }
        if (v == 0) {
            if (count == positions.len) return DecodeError.Uncorrectable;
            positions[count] = i;
            count += 1;
        }
    }
    if (count != l) return DecodeError.Uncorrectable; // locator disagrees with itself

    // Forney: omega = synd * lambda mod x^ec_len, magnitude = omega/lambda'.
    var omega: [31]u8 = [_]u8{0} ** 31;
    for (0..ec_len) |i| {
        for (0..l + 1) |j| {
            if (i + j < ec_len) omega[i + j] ^= gf.mul(synd[i], lambda[j]);
        }
    }

    for (positions[0..count]) |pos| {
        // The codeword is indexed with the highest power first, so position
        // `pos` carries alpha^(n-1-pos).
        const x = gf.t.exp[(n - 1 - pos) % 255];
        const xinv = gf.inverse(x);

        var num: u8 = 0;
        var p: u8 = 1;
        for (0..ec_len) |j| {
            num ^= gf.mul(omega[j], p);
            p = gf.mul(p, xinv);
        }

        // Formal derivative in characteristic 2: only the odd-index terms survive.
        var den: u8 = 0;
        p = 1;
        var j: usize = 1;
        while (j <= l) : (j += 2) {
            den ^= gf.mul(lambda[j], p);
            p = gf.mul(p, gf.mul(xinv, xinv));
        }
        if (den == 0) return DecodeError.Uncorrectable;

        block[pos] ^= gf.mul(gf.mul(num, gf.inverse(den)), x);
    }

    // Re-check: a locator can be satisfied by a wrong correction, and silently
    // handing back mis-corrected data is the one outcome worse than refusing.
    for (0..ec_len) |j| {
        var s: u8 = 0;
        for (block) |c| s = gf.mul(s, gf.t.exp[j]) ^ c;
        if (s != 0) return DecodeError.Uncorrectable;
    }
}

const BitReader = struct {
    buf: []const u8,
    bit: usize = 0,

    fn take(self: *BitReader, bits: u6) ?usize {
        if (self.bit + bits > self.buf.len * 8) return null;
        var v: usize = 0;
        for (0..bits) |_| {
            const b = (self.buf[self.bit >> 3] >> @intCast(7 - (self.bit & 7))) & 1;
            v = (v << 1) | b;
            self.bit += 1;
        }
        return v;
    }
};

fn parseSegments(data: []const u8, version: u6, out: []u8, seq_out: *?Sequence) DecodeError![]u8 {
    var r: BitReader = .{ .buf = data };
    var n: usize = 0;
    var first = true;

    while (true) : (first = false) {
        const raw_mode = r.take(4) orelse break;
        if (raw_mode == 0) break; // terminator
        if (raw_mode == sequence_mode) {
            // Only as the opening segment. A second one, or one after data, is
            // not a sequence this module will guess the meaning of.
            if (!first) return DecodeError.BadData;
            const index = r.take(4) orelse return DecodeError.BadData;
            const total = r.take(4) orelse return DecodeError.BadData;
            const parity = r.take(8) orelse return DecodeError.BadData;
            if (index > total) return DecodeError.BadData;
            seq_out.* = .{
                .index = @intCast(index),
                .total = @intCast(total + 1),
                .parity = @intCast(parity),
            };
            continue;
        }
        const mode: Mode = switch (raw_mode) {
            0b0001 => .numeric,
            0b0010 => .alphanumeric,
            0b0100 => .byte,
            else => return DecodeError.BadData, // incl. ECI and kanji
        };
        const count = r.take(countBits(mode, version)) orelse return DecodeError.BadData;

        switch (mode) {
            .numeric => {
                var left: usize = count;
                while (left >= 3) : (left -= 3) {
                    const v = r.take(10) orelse return DecodeError.BadData;
                    if (v > 999) return DecodeError.BadData;
                    if (n + 3 > out.len) return DecodeError.BufferTooSmall;
                    out[n] = '0' + @as(u8, @intCast(v / 100));
                    out[n + 1] = '0' + @as(u8, @intCast(v / 10 % 10));
                    out[n + 2] = '0' + @as(u8, @intCast(v % 10));
                    n += 3;
                }
                if (left > 0) {
                    const bits: u6 = if (left == 1) 4 else 7;
                    const v = r.take(bits) orelse return DecodeError.BadData;
                    if (n + left > out.len) return DecodeError.BufferTooSmall;
                    if (left == 1) {
                        if (v > 9) return DecodeError.BadData;
                        out[n] = '0' + @as(u8, @intCast(v));
                    } else {
                        if (v > 99) return DecodeError.BadData;
                        out[n] = '0' + @as(u8, @intCast(v / 10));
                        out[n + 1] = '0' + @as(u8, @intCast(v % 10));
                    }
                    n += left;
                }
            },
            .alphanumeric => {
                var left: usize = count;
                while (left >= 2) : (left -= 2) {
                    const v = r.take(11) orelse return DecodeError.BadData;
                    if (v >= 45 * 45) return DecodeError.BadData;
                    if (n + 2 > out.len) return DecodeError.BufferTooSmall;
                    out[n] = alnum_charset[v / 45];
                    out[n + 1] = alnum_charset[v % 45];
                    n += 2;
                }
                if (left == 1) {
                    const v = r.take(6) orelse return DecodeError.BadData;
                    if (v >= 45) return DecodeError.BadData;
                    if (n + 1 > out.len) return DecodeError.BufferTooSmall;
                    out[n] = alnum_charset[v];
                    n += 1;
                }
            },
            .byte => {
                if (n + count > out.len) return DecodeError.BufferTooSmall;
                for (0..count) |_| {
                    const v = r.take(8) orelse return DecodeError.BadData;
                    out[n] = @intCast(v);
                    n += 1;
                }
            },
        }
    }
    return out[0..n];
}

// ── tests ───────────────────────────────────────────────────────────────────

// A bare re-export does NOT pull a submodule's tests into the test binary
// (CONVENTIONS.md §6 step 3); every submodule has to be named here.
test {
    _ = render;
    _ = @import("golden_test.zig");
}

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

test "round trip: every mode, every level, across the version range" {
    const t = std.testing;
    const cases = [_][]const u8{
        "0123456789",
        "HELLO WORLD $%*+-./:",
        "https://example.com/path?q=1",
        "Příliš žluťoučký kůň úpěl ďábelské ódy",
        "8",
        "A",
    };
    var m: Matrix = undefined;
    var out: [4096]u8 = undefined;
    for (cases) |text| {
        for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
            for ([_]?u6{ null, 12, 27, 40 }) |version| {
                try encode(&m, text, .{ .ecc = ecc, .version = version });
                const got = try decode(&m, &out);
                try t.expectEqualStrings(text, got);
            }
        }
    }
}

test "decoding corrects damage up to the level's capability" {
    const t = std.testing;
    var m: Matrix = undefined;
    var out: [256]u8 = undefined;

    // Version 1-H carries 17 EC codewords in one block, so the code corrects up
    // to 8 symbol errors. Damage one module in each of the first 8 codewords —
    // exactly at capability, and counted rather than estimated, because a patch
    // of modules corrupts an unpredictable number of codewords and would make
    // this test pass or fail for reasons unrelated to the correction.
    try encode(&m, "HELLO", .{ .ecc = .high, .version = 1 });
    const clean = m;

    var scratch: Matrix = .{ .size = m.size, .version = m.version };
    @memset(&scratch.bits, 0);
    var reserved: [(max_size * max_size + 7) / 8]u8 = undefined;
    @memset(&reserved, 0);
    drawFunctionPatterns(&scratch, &reserved);

    // Collect the first module of each codeword up front, so "the ninth
    // codeword" means the ninth and not another bit of the eighth.
    var first_of_codeword: [9][2]u16 = undefined;
    var w = Walk.init(m.size, &reserved);
    var bit: usize = 0;
    var found: usize = 0;
    while (w.next()) |p| : (bit += 1) {
        if (bit % 8 != 0) continue;
        first_of_codeword[found] = p;
        found += 1;
        if (found == 9) break;
    }
    try t.expectEqual(@as(usize, 9), found);

    for (first_of_codeword[0..8]) |p| m.setDark(p[0], p[1], !m.isDark(p[0], p[1]));
    try t.expect(!std.mem.eql(u8, &clean.bits, &m.bits)); // the damage is real
    try t.expectEqualStrings("HELLO", try decode(&m, &out));

    // A ninth corrupted codeword is past the limit and must be refused.
    const ninth = first_of_codeword[8];
    m.setDark(ninth[0], ninth[1], !m.isDark(ninth[0], ninth[1]));
    try t.expectError(DecodeError.Uncorrectable, decode(&m, &out));
}

test "damage beyond capability is refused, not mis-corrected" {
    const t = std.testing;
    var m: Matrix = undefined;
    var out: [256]u8 = undefined;

    // Low correction plus a large contiguous wipe: the decoder must say so.
    // Returning a plausible wrong string here is the worst outcome a QR library
    // has, and it is the one a syndrome check alone does not rule out — hence
    // the re-check after Forney correction.
    //
    // The wipe (rows 9-20 of a 21x21 symbol) is chosen to land on the data
    // region and leave the format-information area readable: copy 0 of the
    // format bits lives entirely in rows 0-8, so it survives untouched and
    // `readFormatInfo` still succeeds via that copy even though copy 1's
    // second half (column 8, rows 6-12) is partly overwritten — the decoder
    // only needs ONE readable copy. That makes `BadFormat` unreachable from
    // this specific corruption, and the corruption is heavy enough (12 of 21
    // data+EC rows) that Berlekamp-Massey fails the block before
    // `parseSegments` ever runs, so `BadData` is unreachable too. Only
    // `Uncorrectable` is exercised here; `BadFormat` and `BadData` each have
    // their own dedicated, independently-reachable test below.
    try encode(&m, "HELLO WORLD", .{ .ecc = .low, .version = 1 });
    for (9..21) |y| {
        for (0..21) |x| {
            m.setDark(@intCast(x), @intCast(y), (x + y) % 2 == 0);
        }
    }
    try t.expectError(DecodeError.Uncorrectable, decode(&m, &out));
}

test "decode reports BadFormat when neither copy of the format info is readable" {
    const t = std.testing;
    var m: Matrix = undefined;
    var out: [64]u8 = undefined;

    try encode(&m, "TEST", .{});

    // Clear every module either copy of the format information occupies —
    // mirroring `drawFormatInfo`'s own write loop, so this touches exactly
    // the 15+15 bits `readFormatInfo` reads and nothing else. The resulting
    // 15-bit value (all zero) sits at Hamming distance 5 from every one of
    // the 32 valid BCH(15,5) codewords (checked exhaustively offline —
    // `bch(0, 0x537, 10) ^ 0x5412` and its 31 siblings), which is beyond the
    // format code's declared 3-bit correction radius, so both copies are
    // unreadable and `BadFormat` is the only possible outcome — unlike the
    // "damage beyond capability" test above, which corrupts data and leaves
    // one format copy intact.
    for (0..15) |k| {
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
        m.setDark(x1, y1, false);

        if (k < 8) {
            m.setDark(m.size - 1 - @as(u16, @intCast(k)), 8, false);
        } else {
            m.setDark(8, m.size - 15 + @as(u16, @intCast(k)), false);
        }
    }
    try t.expectError(DecodeError.BadFormat, decode(&m, &out));
}

test "decode reports BadData when the corrected codewords are not a well-formed segment stream" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    var seq: ?Sequence = null;

    // `parseSegments` directly, bypassing the matrix/RS-correction machinery
    // entirely: an RS-corrected block that happens to decode to this byte is
    // indistinguishable from one that was never damaged, so there is no
    // module-level corruption that reliably reaches this path (any single
    // flipped module is either undone by error correction or pushes the
    // block past capability into `Uncorrectable` instead — see the
    // "damage beyond capability" test above). Mode indicator 0b0011 is ECI,
    // which this module does not implement and rejects as malformed data
    // rather than silently mishandling.
    const data = [_]u8{0b0011_0000};
    try t.expectError(DecodeError.BadData, parseSegments(&data, 1, &out, &seq));
}

test "decode rejects a malformed symbol rather than guessing" {
    const t = std.testing;
    var m: Matrix = undefined;
    var out: [64]u8 = undefined;

    try encode(&m, "TEST", .{});
    var bad = m;
    bad.size = 22; // not 17 + 4v
    try t.expectError(DecodeError.BadSize, decode(&bad, &out));

    // A too-small output buffer is reported, never overrun.
    try encode(&m, "0123456789012345", .{});
    var tiny: [4]u8 = undefined;
    try t.expectError(DecodeError.BufferTooSmall, decode(&m, &tiny));
}

test "fuzz: decode never panics on an arbitrary grid" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    // A scanner builds this matrix from an image, so every field of it is
    // attacker-influenced — including a size and a format that never came from
    // an encoder. The Reed-Solomon path is the part that matters here: a
    // corrupted locator must end in an error, not an out-of-range index.
    var m: Matrix = .{};
    m.size = @as(u16, 17) + 4 * @as(u16, smith.valueRangeAtMost(u8, 0, 42));
    if (m.size > max_size) m.size = max_size;
    for (0..m.bits.len) |i| m.bits[i] = smith.valueRangeAtMost(u8, 0, 255);

    var out: [4096]u8 = undefined;
    _ = decode(&m, &out) catch return;
}

test "fuzz: decode survives damage to a real symbol" {
    try std.testing.fuzz({}, fuzzDamage, .{});
}

fn fuzzDamage(_: void, smith: *std.testing.Smith) !void {
    // Random noise rarely reaches the interesting branches; a valid symbol with
    // modules flipped does, because the format still decodes and the corrupted
    // blocks then exercise Berlekamp-Massey, Chien and Forney for real.
    var m: Matrix = undefined;
    encode(&m, "FUZZ TARGET 12345", .{
        .ecc = @enumFromInt(smith.valueRangeAtMost(u8, 0, 3)),
    }) catch return;

    const flips = smith.valueRangeAtMost(u16, 0, 200);
    for (0..flips) |_| {
        const x = smith.valueRangeAtMost(u16, 0, m.size - 1);
        const y = smith.valueRangeAtMost(u16, 0, m.size - 1);
        m.setDark(x, y, !m.isDark(x, y));
    }

    var out: [4096]u8 = undefined;
    const got = decode(&m, &out) catch return;
    // If it claims success, the message must be the one that was encoded —
    // a decoder that returns confident nonsense is worse than one that refuses.
    try std.testing.expectEqualStrings("FUZZ TARGET 12345", got);
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

// ── structured append ───────────────────────────────────────────────────────

test "a sequence round-trips: split, read each part, put it back together" {
    const t = std.testing;
    // Long enough to need several symbols at a size a phone screen shows well.
    const message = "signed-payload:" ++ ("0123456789abcdef" ** 40);

    var symbols: [16]Matrix = undefined;
    const seq = try encodeSequence(&symbols, message, .{ .ecc = .quartile, .version = 6 });
    try t.expect(seq.len > 1);

    var joined: [1024]u8 = undefined;
    var n: usize = 0;
    for (seq, 0..) |*sym, i| {
        // Every symbol in the sequence is the size that was asked for, including
        // the last and short one.
        try t.expectEqual(sideFor(6), sym.size);

        var buf: [512]u8 = undefined;
        const part = try decodePart(sym, &buf);
        const q = part.sequence orelse return error.NotASequence;
        try t.expectEqual(@as(u4, @intCast(i)), q.index);
        try t.expectEqual(@as(u5, @intCast(seq.len)), q.total);
        try t.expectEqual(sequenceParity(message), q.parity);

        @memcpy(joined[n..][0..part.data.len], part.data);
        n += part.data.len;
    }
    try t.expectEqualStrings(message, joined[0..n]);
    try t.expectEqual(sequenceParity(message), sequenceParity(joined[0..n]));
}

test "a part is refused by decode rather than returned as a message" {
    const t = std.testing;
    var symbols: [8]Matrix = undefined;
    const seq = try encodeSequence(&symbols, "N" ** 200, .{ .version = 2, .ecc = .low });
    try t.expect(seq.len > 1);

    var buf: [256]u8 = undefined;
    // This is the whole reason the error exists: the fragment decodes perfectly
    // well, and a caller handed it would act on a truncated message.
    try t.expectError(DecodeError.StructuredAppend, decode(&seq[0], &buf));
    const part = try decodePart(&seq[0], &buf);
    try t.expect(part.data.len > 0);
    try t.expect(part.data.len < 200);
}

test "parity separates two sequences that arrive interleaved" {
    const t = std.testing;
    var a: [8]Matrix = undefined;
    var b: [8]Matrix = undefined;
    const sa = try encodeSequence(&a, "the first message, split in two or more", .{ .version = 1, .ecc = .low });
    const sb = try encodeSequence(&b, "a different message, also split up here", .{ .version = 1, .ecc = .low });
    try t.expect(sa.len > 1 and sb.len > 1);

    var buf: [128]u8 = undefined;
    const pa = (try decodePart(&sa[0], &buf)).sequence.?;
    const pb = (try decodePart(&sb[0], &buf)).sequence.?;
    // Index and count are identical between the two; only the parity is not,
    // which is exactly the case the field exists for.
    try t.expectEqual(pa.index, pb.index);
    try t.expect(pa.parity != pb.parity);
}

test "a message that needs more symbols than there is room for is refused" {
    const t = std.testing;
    var two: [2]Matrix = undefined;
    try t.expectError(Error.TooLong, encodeSequence(&two, "N" ** 400, .{ .version = 1, .ecc = .high }));
    // Room is what is missing, not capacity: the same message splits happily
    // once there are symbols to put it in.
    var plenty: [16]Matrix = undefined;
    _ = try encodeSequence(&plenty, "N" ** 400, .{ .version = 6, .ecc = .high });

    // Sixteen is the standard's ceiling, not ours, so a message that needs a
    // seventeenth symbol at the forced version is refused even with room.
    var many: [16]Matrix = undefined;
    try t.expectError(Error.TooLong, encodeSequence(&many, "N" ** 5000, .{ .version = 1, .ecc = .high }));

    // Without a forced version the encoder grows the symbol instead of the count.
    const seq = try encodeSequence(&many, "N" ** 5000, .{ .ecc = .high });
    try t.expect(seq.len <= 16);
    try t.expect(seq[0].version > 1);
}

test "the header costs capacity, and the accounting says so" {
    const t = std.testing;
    // A message that exactly fills a version 1-L symbol on its own cannot also
    // carry a 20-bit sequence header, and the split has to notice.
    const chunk = maxChunk(.byte, 1, .low);
    var text: [64]u8 = undefined;
    @memset(&text, 'x');
    const fits_alone = text[0 .. chunk + 2];

    var m: Matrix = undefined;
    try encode(&m, fits_alone, .{ .version = 1, .ecc = .low });

    var symbols: [16]Matrix = undefined;
    const seq = try encodeSequence(&symbols, fits_alone, .{ .version = 1, .ecc = .low });
    try t.expectEqual(@as(usize, 2), seq.len);
}

test "fuzz: a sequence survives the round trip whatever the message" {
    try std.testing.fuzz({}, fuzzSequence, .{});
}

fn fuzzSequence(_: void, smith: *std.testing.Smith) !void {
    var message: [600]u8 = undefined;
    const len = smith.valueRangeAtMost(u16, 0, message.len);
    for (0..len) |i| message[i] = smith.valueRangeAtMost(u8, 0, 255);
    const text = message[0..len];

    var symbols: [16]Matrix = undefined;
    const seq = encodeSequence(&symbols, text, .{
        .ecc = @enumFromInt(smith.valueRangeAtMost(u8, 0, 3)),
    }) catch return;

    var joined: [600]u8 = undefined;
    var n: usize = 0;
    for (seq, 0..) |*sym, i| {
        var buf: [600]u8 = undefined;
        const part = try decodePart(sym, &buf);
        // A one-symbol sequence is a legal thing to produce, so the header is
        // present or absent consistently — never present with the wrong place
        // in it.
        const q = part.sequence orelse return error.SequenceHeaderMissing;
        try std.testing.expectEqual(@as(u4, @intCast(i)), q.index);
        try std.testing.expectEqual(@as(u5, @intCast(seq.len)), q.total);
        try std.testing.expectEqual(sequenceParity(text), q.parity);
        @memcpy(joined[n..][0..part.data.len], part.data);
        n += part.data.len;
    }
    try std.testing.expectEqualSlices(u8, text, joined[0..n]);
}
