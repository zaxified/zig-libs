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
//! **Kanji mode** (`Options.mode = .kanji`) packs Shift-JIS double-byte values
//! at 13 bits each, as libqrencode does: the input is Shift-JIS *bytes* (the
//! caller transcodes, there is no table here), never chosen automatically (byte
//! mode carries the same text as UTF-8 for the same or fewer bits unless it is
//! almost entirely Japanese), and the decoder returns the Shift-JIS bytes of a
//! kanji segment. `encode` never silently falls back — an input is numeric,
//! alphanumeric, byte, or kanji when forced.

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
    /// Shift-JIS double-byte characters, 13 bits each (ISO/IEC 18004 §7.4.6). Never picked by
    /// `encode` on its own: force it with `Options.mode`, with the text given as Shift-JIS bytes
    /// (an even length; each pair 0x8140..0x9FFC or 0xE040..0xEBBF with a trail byte 0x40..0xFC
    /// other than 0x7F, else `error.ModeMismatch`). The decoder returns the Shift-JIS bytes.
    kanji = 0b1000,
};

pub const Options = struct {
    ecc: Ecc = .medium,
    /// Force a version (1–40). Null picks the smallest that fits.
    version: ?u6 = null,
    /// Force a mode. Null picks the most compact one the input allows.
    mode: ?Mode = null,
    /// Force a mask pattern (0–7). Null runs the standard penalty evaluation.
    mask: ?u3 = null,
    /// Declare the character set of the data with an ECI designator segment
    /// (ISO/IEC 18004 §7.4.2) in front of it, e.g. `26` for UTF-8, `3` for
    /// ISO-8859-1. Valid values are 0–999999; a larger one is `error.BadEci`.
    /// An ECI designates how *bytes* are read, so it implies byte mode (a
    /// forced `mode` other than `.byte` is `error.ModeMismatch`). In a
    /// structured-append sequence every symbol carries the designator. The
    /// designator is as short as its value allows (8, 16 or 24 bits) and is
    /// counted in the capacity and version selection. Null (the default)
    /// writes none, which is what a reader expects for ISO-8859-1 / UTF-8
    /// sniffing and is smallest.
    eci: ?u32 = null,
    /// Opt in to mixed-mode segmentation: the text is split into numeric /
    /// alphanumeric / byte segments by an exact dynamic program (the approach of
    /// nayuki's `makeSegmentsOptimally`; mode indicator, character-count width of
    /// the version range and per-mode data bits all counted), so a payload like
    /// `"HELLO WORLD 2026"` or a URL with a long digit run can come out smaller
    /// or in a lower version. Never larger than the single-mode default, whose
    /// segmentation is one of the candidates. Off by default so the default
    /// output stays byte-identical. Cannot be combined with a forced `mode` or an
    /// `eci` (both pin a single byte/forced segment): that is `error.ModeMismatch`.
    /// `encodeSequence` ignores it (each chunk of a sequence keeps one mode).
    /// Text longer than 7089 bytes (the most any symbol holds) is `error.TooLong`.
    optimize_segments: bool = false,
};

/// Largest ECI assignment number (ISO/IEC 18004 §7.4.2.2: six decimal digits).
pub const max_eci: u32 = 999_999;

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
    /// `Options.eci` was above `max_eci`.
    BadEci,
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
/// caller provides, and everything else lives on this frame — which is not
/// small. Measured (A1 audit F5, native Debug, version 40 / ECC high): a
/// 40 KB call stack still overflows, a 64 KB one does not. A caller on a
/// constrained thread (a thread pool sized for a small default, a `wasm32`
/// host with its own limit) should give this call at least that much room.
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

    const mode = try resolveMode(text, opts);
    const head_bits = sequence_header_bits + eciBits(opts.eci);

    const room = @min(out.len, max_sequence);
    var version: u6 = 0;
    var chunk: usize = 0;
    if (opts.version) |v| {
        if (v < 1 or v > 40) return Error.BadVersion;
        version = v;
        chunk = maxChunk(mode, v, opts.ecc, head_bits);
        if (chunk == 0 or symbolsNeeded(text.len, chunk) > room) return Error.TooLong;
    } else {
        var v: u6 = 1;
        while (v <= 40) : (v += 1) {
            const c = maxChunk(mode, v, opts.ecc, head_bits);
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
fn maxChunk(mode: Mode, version: u6, ecc: Ecc, head_bits: usize) usize {
    const cap = dataCapacityBits(version, ecc);
    if (cap <= head_bits) return 0;

    var lo: usize = 0;
    var hi: usize = cap; // any length needs at least a bit per character
    while (lo < hi) {
        const mid = (lo + hi + 1) / 2;
        if (head_bits + dataBits(mode, mid, version) <= cap) lo = mid else hi = mid - 1;
    }
    // The character-count field is finite too, and for a short numeric symbol it
    // is the binding constraint rather than the capacity.
    var count_max = (@as(usize, 1) << countBits(mode, version)) - 1;
    if (mode == .kanji) {
        count_max *= 2; // the count is characters, `lo` and the chunk are bytes
        lo &= ~@as(usize, 1); // a chunk never splits a double-byte character
    }
    return @min(lo, count_max);
}

/// Mode indicator, position, count, parity (§8.4.6).
const sequence_header_bits = 4 + 4 + 4 + 8;
const sequence_mode: u4 = 0b0011;

const eci_mode: u4 = 0b0111;

/// Bits of the ECI segment header: mode indicator plus the designator, which is
/// 8, 16 or 24 bits by value (§7.4.2.2). Zero when there is none.
fn eciBits(eci: ?u32) usize {
    const v = eci orelse return 0;
    return 4 + @as(usize, if (v < 1 << 7) 8 else if (v < 1 << 14) 16 else 24);
}

fn putEci(w: *BitWriter, v: u32) void {
    w.put(eci_mode, 4);
    if (v < 1 << 7) {
        w.put(v, 8); // 0xxxxxxx
    } else if (v < 1 << 14) {
        w.put(0b10 << 14 | v, 16); // 10xxxxxx xxxxxxxx
    } else {
        w.put(0b110 << 21 | v, 24); // 110xxxxx xxxxxxxx xxxxxxxx
    }
}

/// The segment mode, honouring `Options.mode` and `Options.eci`.
fn resolveMode(text: []const u8, opts: Options) Error!Mode {
    if (opts.eci) |e| {
        if (e > max_eci) return Error.BadEci;
        if (opts.mode) |m| if (m != .byte) return Error.ModeMismatch;
        return .byte;
    }
    if (opts.mode) |m| {
        if (!modeFits(m, text)) return Error.ModeMismatch;
        return m;
    }
    return pickMode(text);
}

fn encodeOne(out: *Matrix, text: []const u8, opts: Options, seq: ?Sequence) Error!void {
    const mixed = opts.optimize_segments and seq == null and text.len > 0;
    if (mixed and (opts.eci != null or opts.mode != null)) return Error.ModeMismatch;
    const mode = if (mixed) Mode.byte else try resolveMode(text, opts);

    var plan_buf: [max_mixed]u8 = undefined;
    var plan: ?[]const u8 = null;
    const extra: usize = (if (seq == null) @as(usize, 0) else sequence_header_bits) + eciBits(opts.eci);
    const version = if (mixed) blk: {
        if (text.len > max_mixed) return Error.TooLong;
        const v = try pickMixedVersion(text, opts.ecc, opts.version, &plan_buf);
        plan = plan_buf[0..text.len];
        break :blk v;
    } else if (opts.version) |v| blk: {
        if (v < 1 or v > 40) return Error.BadVersion;
        if (extra + dataBits(mode, text.len, v) > dataCapacityBits(v, opts.ecc)) return Error.TooLong;
        break :blk v;
    } else pickVersion(mode, text.len, opts.ecc, extra) orelse return Error.TooLong;

    var codewords: [max_codewords]u8 = undefined;
    const total = totalCodewords(version);
    buildCodewords(codewords[0..total], mode, text, version, opts.ecc, seq, opts.eci, plan);

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
///
/// ⚠ That check was real but was never committed: `golden_matrices.zig` covers
/// **10** versions, not 40, so nothing in the repo re-ran it. Re-verified
/// Against segno across all 40 versions, and the claim holds — but
/// the lesson is that "checked against an independent encoder" in a comment is
/// a past event, not a standing property, unless the check is in the tree.
/// `testdata/decode_vectors.bin` now covers all 40 versions on the decode side;
/// the encode side above still rests on 10.
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
    const cell = row[@backingInt(ecc)];
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
    return if (std.mem.findScalar(u8, alnum_charset, c)) |i| @intCast(i) else null;
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
        .kanji => kanjiFits(text),
    };
}

/// Shift-JIS double-byte values the Kanji mode can carry (§7.4.6): 0x8140..0x9FFC and 0xE040..0xEBBF,
/// trail byte 0x40..0xFC without 0x7F.
fn kanjiFits(text: []const u8) bool {
    if (text.len % 2 != 0) return false;
    var i: usize = 0;
    while (i < text.len) : (i += 2) {
        const hi = text[i];
        const lo = text[i + 1];
        if (lo < 0x40 or lo > 0xFC or lo == 0x7F) return false;
        const ok = (hi >= 0x81 and hi <= 0x9F) or (hi >= 0xE0 and hi <= 0xEB);
        if (!ok) return false;
        const v = @as(u16, hi) << 8 | lo;
        if (v > 0x9FFC and v < 0xE040) return false; // gap cannot occur given the lead check, kept for clarity
        if (v > 0xEBBF) return false;
    }
    return true;
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
        .kanji => ([_]u5{ 8, 10, 12 })[group],
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
        // `len` is bytes (two per character), 13 bits per character.
        .kanji => (len / 2) * 13,
    };
}

fn pickVersion(mode: Mode, len: usize, ecc: Ecc, extra_bits: usize) ?u6 {
    var v: u6 = 1;
    while (v <= 40) : (v += 1) {
        if (extra_bits + dataBits(mode, len, v) <= dataCapacityBits(v, ecc)) return v;
    }
    return null;
}

/// Most characters any symbol can hold (version 40, ECC low, numeric).
const max_mixed: usize = 7089;
const mixed_modes = [3]Mode{ .numeric, .alphanumeric, .byte };

/// Optimal segmentation of `text` for the character-count widths of
/// `rep_version`'s range (1-9 / 10-26 / 27-40): an exact shortest path over the
/// three modes, costs in sixths of a bit (numeric 20, alphanumeric 33, byte 48
/// per character; every segment end rounds up to a whole bit, which is exactly
/// the 4/7-bit and 6-bit remainders). Leaves the mode index of every character
/// in `buf[0..text.len]` and returns the total data bits, headers included.
fn planSegments(text: []const u8, rep_version: u6, buf: []u8) usize {
    const inf = std.math.maxInt(u32);
    const char_cost = [3]u32{ 20, 33, 48 };
    var head: [3]u32 = undefined;
    for (mixed_modes, 0..) |m, k| head[k] = (4 + @as(u32, countBits(m, rep_version))) * 6;

    var cost = [3]u32{ inf, inf, inf };
    for (text, 0..) |c, i| {
        const allowed = [3]bool{ c >= '0' and c <= '9', alnumValue(c) != null, true };
        var next = [3]u32{ inf, inf, inf };
        var packed_from: u8 = 0;
        for (0..3) |m| {
            if (!allowed[m]) continue;
            if (i == 0) {
                next[m] = head[m] + char_cost[m];
                continue;
            }
            var best: u32 = inf;
            var from: u8 = @intCast(m);
            if (cost[m] != inf) best = cost[m] + char_cost[m];
            for (0..3) |j| {
                if (j == m or cost[j] == inf) continue;
                const cand = (cost[j] + 5) / 6 * 6 + head[m] + char_cost[m];
                if (cand < best) {
                    best = cand;
                    from = @intCast(j);
                }
            }
            next[m] = best;
            packed_from |= from << @intCast(2 * m);
        }
        buf[i] = packed_from;
        cost = next;
    }

    var cur: u8 = 2;
    for (0..2) |m| if (cost[m] < cost[cur]) {
        cur = @intCast(m);
    };
    var i = text.len;
    while (i > 0) {
        i -= 1;
        const pr = buf[i];
        buf[i] = cur;
        if (i > 0) cur = (pr >> @intCast(2 * cur)) & 3;
    }

    var bits: usize = 0;
    var s: usize = 0;
    while (s < text.len) {
        var e = s + 1;
        while (e < text.len and buf[e] == buf[s]) e += 1;
        const m = mixed_modes[buf[s]];
        if (e - s >= @as(usize, 1) << countBits(m, rep_version)) return std.math.maxInt(usize);
        bits += dataBits(m, e - s, rep_version);
        s = e;
    }
    return bits;
}

/// Smallest version (or the forced one) that holds the optimal segmentation;
/// leaves that segmentation in `buf`.
fn pickMixedVersion(text: []const u8, ecc: Ecc, forced: ?u6, buf: []u8) Error!u6 {
    if (forced) |v| {
        if (v < 1 or v > 40) return Error.BadVersion;
        const bits = planSegments(text, v, buf);
        if (bits > dataCapacityBits(v, ecc)) return Error.TooLong;
        return v;
    }
    const reps = [3]u6{ 1, 10, 27 };
    const ends = [3]u6{ 9, 26, 40 };
    for (reps, ends) |first, last| {
        const bits = planSegments(text, first, buf);
        var v = first;
        while (v <= last) : (v += 1) {
            if (bits <= dataCapacityBits(v, ecc)) return v;
        }
    }
    return Error.TooLong;
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
fn buildCodewords(out: []u8, mode: Mode, text: []const u8, version: u6, ecc: Ecc, seq: ?Sequence, eci: ?u32, plan: ?[]const u8) void {
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

    if (eci) |e| putEci(&w, e);

    if (plan) |p| {
        var s: usize = 0;
        while (s < text.len) {
            var e = s + 1;
            while (e < text.len and p[e] == p[s]) e += 1;
            putSegment(&w, mixed_modes[p[s]], text[s..e], version);
            s = e;
        }
    } else putSegment(&w, mode, text, version);

    // Terminator: up to four zero bits, short if the capacity ends sooner.
    const cap_bits = data_len * 8;
    const term = @min(@as(u6, 4), @as(u6, @intCast(@min(@as(usize, 4), cap_bits - w.bit))));
    w.put(0, term);
    // Pad to a byte boundary, then alternate the two specified pad codewords.
    while (w.bit % 8 != 0) w.put(0, 1);
    var pad: u8 = 0xEC;
    while (w.bit < cap_bits) : (pad = if (pad == 0xEC) 0x11 else 0xEC) w.put(pad, 8);

    buildBlocks(out, data[0..data_len], spec);
}

/// One segment: mode indicator, character count, data.
fn putSegment(w: *BitWriter, mode: Mode, text: []const u8, version: u6) void {
    w.put(@backingInt(mode), 4);
    w.put(if (mode == .kanji) text.len / 2 else text.len, countBits(mode, version));
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
        .kanji => {
            var i: usize = 0;
            while (i < text.len) : (i += 2) {
                const val: u16 = @as(u16, text[i]) << 8 | text[i + 1];
                const off = val - @as(u16, if (val <= 0x9FFC) 0x8140 else 0xC140);
                w.put((off >> 8) * @as(usize, 0xC0) + (off & 0xFF), 13);
            }
        },
    }
}

/// Data codewords → blocks → EC → interleave into `out`.
fn buildBlocks(out: []u8, data: []const u8, spec: EcSpec) void {
    const data_len = data.len;
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
    // k = floor(|dark/total - 1/2| * 20): steps of 5% of the EXACT deviation
    // (ISO/IEC 18004 Table 11; ZXing, nayuki and segno agree).
    const k = (if (dark * 20 > total * 10) dark * 20 - total * 10 else total * 10 - dark * 20) / total;
    score += @intCast(k * 10);

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
    /// The ECI assignment number the symbol declared for `data`, or null if it
    /// carried no designator (then the reader's default applies). `decode`
    /// drops it; use `decodePart` when the character set matters.
    eci: ?u32 = null,
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
///
/// Like `encode`, this frame is not small — see its doc comment for the
/// measured stack floor (F5).
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
    var eci: ?u32 = null;
    const text = try parseSegments(data[0..data_len], version, out, &seq, &eci);
    return .{ .data = text, .sequence = seq, .eci = eci };
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
    var lambda: [31]u8 = @as([31]u8, @splat(0));
    var prev: [31]u8 = @as([31]u8, @splat(0));
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
    var omega: [31]u8 = @as([31]u8, @splat(0));
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

fn parseSegments(data: []const u8, version: u6, out: []u8, seq_out: *?Sequence, eci_out: *?u32) DecodeError![]u8 {
    var r: BitReader = .{ .buf = data };
    var n: usize = 0;
    var data_seen = false;
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
        if (raw_mode == eci_mode) {
            // One designator, ahead of the data it governs. A later one would
            // switch character set mid-message, which this API cannot report.
            if (data_seen or eci_out.* != null) return DecodeError.BadData;
            const b0 = r.take(8) orelse return DecodeError.BadData;
            if (b0 & 0x80 == 0) {
                eci_out.* = @intCast(b0);
            } else if (b0 & 0xC0 == 0x80) {
                const b1 = r.take(8) orelse return DecodeError.BadData;
                eci_out.* = @intCast((b0 & 0x3F) << 8 | b1);
            } else if (b0 & 0xE0 == 0xC0) {
                const rest = r.take(16) orelse return DecodeError.BadData;
                const v: u32 = @intCast((b0 & 0x1F) << 16 | rest);
                if (v > max_eci) return DecodeError.BadData;
                eci_out.* = v;
            } else return DecodeError.BadData; // 111xxxxx is reserved
            continue;
        }
        data_seen = true;
        const mode: Mode = switch (raw_mode) {
            0b0001 => .numeric,
            0b0010 => .alphanumeric,
            0b0100 => .byte,
            0b1000 => .kanji,
            else => return DecodeError.BadData,
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
            .kanji => {
                // 13 bits per character back to the Shift-JIS pair (§7.4.6): hi * 0xC0 + lo, with the
                // two ranges 0x8140..0x9FFC and 0xE040..0xEBBF told apart by the offset. Every 13-bit
                // value with lo <= 0xBC lands in one of them (0x1FFF is 0xEBBF), so lo is the only check.
                for (0..count) |_| {
                    const v = r.take(13) orelse return DecodeError.BadData;
                    const hi: usize = v / 0xC0;
                    const lo: usize = v % 0xC0;
                    if (lo > 0xBC) return DecodeError.BadData;
                    const off: usize = hi << 8 | lo;
                    const val: usize = if (off <= 0x1EBC) off + 0x8140 else off + 0xC140;
                    if (n + 2 > out.len) return DecodeError.BufferTooSmall;
                    out[n] = @intCast(val >> 8);
                    out[n + 1] = @intCast(val & 0xFF);
                    n += 2;
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
    _ = @import("fuzz_test.zig");
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

// ⚠ Every harness in this file collapsed to a single fixed input, and the
// four of them collapsed in three different ways.
//
// `fuzzEncode` opened with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`: `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain -- so `len` was 0 and the
// text was empty. Every knob after it was drawn from an exhausted input too:
// `ecc` was always `.low`, `version` always null and `mask` always 0. The
// comment "0 and 41 exercise the guards" described a version draw that was 0
// every time and 41 never.
//
// The fix that works for all four is the same one: take the seed in ONE
// `smith.slice` draw and read the choices out of the octets, so a knob cannot
// be drawn from input that is no longer there. It also makes a seed a
// reviewable script instead of a sequence of `u64` words.

/// `testkit.fuzz.Cursor` over one corpus seed. See `testkit/src/fuzz.zig` for
/// why a shape-drawing harness wants this rather than a ranged draw.
const Script = @import("testkit").fuzz.Cursor;
const seed = @import("testkit").fuzz.seed;
const seedHex = @import("testkit").fuzz.seedHex;

/// What one encode script produced, so the guard measures the corpus rather
/// than asserting it ran.
const EncodeOutcome = struct {
    ecc: Ecc = .low,
    encoded: bool = false,
    /// The symbol's version, 0 when nothing was encoded.
    version: u6 = 0,
    /// Whether the text round-tripped back out of `decode`.
    round_tripped: bool = false,
};

/// The body of `fuzzEncode`, factored out so the harness and the corpus guard
/// drive the SAME encode from the same octets.
///
/// The seed layout is `ecc, version, mask, text...`: `ecc` selects the level
/// (mod 4), `version` is 0 for "let the encoder choose" and 1..40 to force one
/// (41 and up exercise `BadVersion`), `mask` is 8 for "let the encoder choose"
/// and 0..7 to force one, and everything after the third octet is the text.
fn runEncodeScript(bytes: []const u8) !EncodeOutcome {
    var out: EncodeOutcome = .{};
    const ecc_byte: u8 = if (bytes.len > 0) bytes[0] else 0;
    const version_byte: u8 = if (bytes.len > 1) bytes[1] else 0;
    const mask_byte: u8 = if (bytes.len > 2) bytes[2] else 8;
    const text: []const u8 = if (bytes.len > 3) bytes[3..] else "";

    out.ecc = @fromBackingInt(@intCast(ecc_byte % 4));
    // ⭐ `% 42` and NOT `@min(.., 40)`. The old harness wrote
    // `@intCast(@min(forced_version, 40))` under a comment saying "0 and 41
    // exercise the guards" — but the clamp turns 41 into 40, so `BadVersion`
    // was unreachable from this harness whatever the draw returned. Two
    // separate reasons the same guard never ran.
    const forced_version: u8 = version_byte % 42; // 0 = auto, 1..40 valid, 41 = BadVersion

    var m: Matrix = undefined;
    encode(&m, text, .{
        .ecc = out.ecc,
        .version = if (forced_version == 0) null else @intCast(forced_version),
        .mask = if (mask_byte % 9 == 8) null else @intCast(mask_byte % 8),
    }) catch return out;

    // A returned symbol must be internally consistent — a size that disagrees
    // with the version means the placement walked a grid of the wrong shape,
    // which is exactly the failure a panic-only harness would let through.
    try std.testing.expectEqual(sideFor(m.version), m.size);
    try std.testing.expect(m.isDark(0, 0)); // top-left finder survived
    out.encoded = true;
    out.version = m.version;

    // And the symbol must read back as what went in. A matrix that is
    // self-consistent but decodes to something else is the silent-corruption
    // failure this module's TEETH section is about.
    var decoded: [4096]u8 = undefined;
    if (decode(&m, &decoded)) |got| {
        try std.testing.expectEqualStrings(text, got);
        out.round_tripped = true;
    } else |_| {}
    return out;
}

/// Encode scripts: `ecc, version, mask, text...`. The three leading octets are
/// spelled in hex so the knobs read as the choices they are, and the text
/// follows verbatim.
const encode_seeds = [_][]const u8{
    seed("\x00\x00\x08" ++ "HELLO WORLD"), // low / auto version / auto mask, alphanumeric
    seed("\x01\x00\x08" ++ "HELLO WORLD"), // the same at medium
    seed("\x02\x00\x08" ++ "HELLO WORLD"), // quartile
    seed("\x03\x00\x08" ++ "HELLO WORLD"), // high
    seed("\x00\x00\x08" ++ "0123456789012345"), // the numeric mode
    seed("\x00\x00\x08" ++ "https://example.com/path?q=1"), // byte mode, a URL
    seed("\x00\x00\x08" ++ "P\xc5\x99\xc3\xadli\xc5\xa1 \xc5\xbelu\xc5\xa5ou\xc4\x8dk\xc3\xbd k\xc5\xaf\xc5\x88"), // multi-byte UTF-8
    seed("\x00\x01\x08" ++ "A"), // version 1 forced: the smallest symbol
    seed("\x00\x28\x08" ++ "A"), // version 40 forced: the largest
    seed("\x00\x29\x08" ++ "A"), // ⭐ version 41: `BadVersion`, which the old harness's own comment claimed to exercise and never did
    seed("\x00\x01\x08" ++ (strRepeat("A", 60))), // too long for the forced version: `TooLong`
    seed("\x00\x00\x00" ++ "MASK ZERO"), // every mask forced, 0 through 7
    seed("\x00\x00\x01" ++ "MASK ONE"),
    seed("\x00\x00\x02" ++ "MASK TWO"),
    seed("\x00\x00\x03" ++ "MASK THREE"),
    seed("\x00\x00\x04" ++ "MASK FOUR"),
    seed("\x00\x00\x05" ++ "MASK FIVE"),
    seed("\x00\x00\x06" ++ "MASK SIX"),
    seed("\x00\x00\x07" ++ "MASK SEVEN"),
    seed("\x03\x00\x08" ++ (strRepeat("A", 480))), // high ECC and a long message: near the capacity ceiling
    seed("\x00\x00\x08" ++ "\x00\x01\x02\xfd\xfe\xff"), // control and high bytes
    seed("\x00\x00\x08"), // the knobs with an EMPTY text
    seed(""), // the empty script: exactly what the collapsed harness ran
};

const fz = @import("fuzz_test.zig");
const EncodeMark = fz.Marker(enum { encoded, refused, round_tripped });
const DecodeMark = fz.Marker(enum { grid });
const DamageMark = fz.Marker(enum { undamaged, damaged, recovered, refused });
const SequenceMark = fz.Marker(enum { encoded, multi_symbol });

test "fuzz: encode never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzEncodeSmith, .{ .corpus = &encode_seeds });
}

test "fuzz driver: QR_FUZZ (encode)" {
    try fz.fuzz_driver.run(fuzzEncode, .{ .prefix = "QR_FUZZ", .name = "qr-encode", .scale = 4 });
}

test "fuzz harness: encode, 300 seeds, reaches every outcome" {
    try EncodeMark.reach(fuzzEncode, "qr-encode", 300);
}

fn fuzzEncodeSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzEncode(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzEncode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &encode_seeds);
    const out = try runEncodeScript(buf[0..len]);
    if (out.encoded) EncodeMark.mark(.encoded) else EncodeMark.mark(.refused);
    if (out.round_tripped) EncodeMark.mark(.round_tripped);
}

test "corpus: every encode seed reaches the encoder, and the symbols built are pinned" {
    // ⭐ Three numbers, and none of them is "accepted". `encode("")` SUCCEEDS —
    // an empty byte segment is a legal QR payload — so "some seeds encoded"
    // would have been satisfied by the single empty input the collapsed harness
    // ran, and read as a pass. The numbers that only real text can produce are
    // the distinct ECC levels reached, the distinct versions built, and the
    // seeds that decoded back to exactly what went in.
    var nonempty: usize = 0;
    var encoded: usize = 0;
    var round_tripped: usize = 0;
    var ecc_seen = @as([4]bool, @splat(false));
    var versions_seen = @as([41]bool, @splat(false));
    for (encode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const out = try runEncodeScript(buf[0..len]);
        ecc_seen[@backingInt(out.ecc)] = true;
        if (out.encoded) {
            encoded += 1;
            versions_seen[out.version] = true;
        }
        if (out.round_tripped) round_tripped += 1;
    }
    var eccs: usize = 0;
    for (ecc_seen) |b| {
        if (b) eccs += 1;
    }
    var versions: usize = 0;
    for (versions_seen, 0..) |b, v| {
        if (b and v != 0) versions += 1;
    }
    // One seed is deliberately the empty script.
    try std.testing.expectEqual(encode_seeds.len - 1, nonempty);
    // Measured: 1 seed of 1 non-empty, 1 ECC level, 1 version and
    // 1 round trip before the draws were fixed — and that one symbol was the
    // encoding of the EMPTY string.
    try std.testing.expectEqual(@as(usize, 4), eccs);
    try std.testing.expectEqual(@as(usize, 21), encoded);
    try std.testing.expectEqual(@as(usize, 4), versions);
    try std.testing.expectEqual(@as(usize, 21), round_tripped);
}

// F8: every golden vector in `golden_test.zig` forces `.mask`, so nothing in
// the suite ever exercises `pickMask`/`penalty` choosing on its own -- a
// regression there (wrong rule, wrong tie-break, wrong `< ` vs `<=`) changes
// which mask a real caller gets and nothing catches it. This is not a
// standard byte-for-byte anchor (no independent encoder to compare against
// forces a *specific* auto choice, only that its own penalty score is no
// worse than a hand implementation's -- see the audit's three-way vote in
// A1 audit F8), so it pins today's own output instead: a behavior change
// in the tie-break or a scoring rule is still caught, because the winner
// moves.
test "auto-selected mask is pinned across a spread of inputs (F8 anchor)" {
    const Case = struct { text: []const u8, ecc: Ecc, version: ?u6, want_mask: u3 };
    const cases = [_]Case{
        .{ .text = "HELLO WORLD", .ecc = .low, .version = null, .want_mask = 7 },
        .{ .text = "0123456789012345", .ecc = .medium, .version = null, .want_mask = 6 },
        .{ .text = "https://example.com/path?q=1", .ecc = .quartile, .version = null, .want_mask = 7 },
        .{ .text = "A", .ecc = .high, .version = 1, .want_mask = 4 },
        .{ .text = "A", .ecc = .low, .version = 40, .want_mask = 2 },
        .{ .text = "P\xc5\x99\xc3\xadli\xc5\xa1 \xc5\xbelu\xc5\xa5ou\xc4\x8dk\xc3\xbd k\xc5\xaf\xc5\x88", .ecc = .medium, .version = null, .want_mask = 2 },
    };
    var m: Matrix = undefined;
    for (cases) |c| {
        try encode(&m, c.text, .{ .ecc = c.ecc, .version = c.version });
        try std.testing.expectEqual(c.want_mask, m.mask);
    }
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
    var eci: ?u32 = null;

    // `parseSegments` directly, bypassing the matrix/RS-correction machinery
    // entirely: an RS-corrected block that happens to decode to this byte is
    // indistinguishable from one that was never damaged, so there is no
    // module-level corruption that reliably reaches this path (any single
    // flipped module is either undone by error correction or pushes the
    // block past capability into `Uncorrectable` instead — see the
    // "damage beyond capability" test above).
    //
    // ⚠ This comment used to say "Mode indicator 0b0011 is ECI, which this
    // module does not implement and rejects as malformed data". **0b0011 is
    // structured append** — this file's own `sequence_mode` — and ECI is
    // 0b0111. The vector below does return `BadData`, but from a TRUNCATED
    // structured-append header (the four bits are followed by nothing), not
    // from the unimplemented-mode branch the comment named. The branch the
    // comment pointed at had no test at all; it has one now, in
    // "TEETH: an unimplemented segment mode is REFUSED, not read as bytes".
    // A test whose comment names a different code path from the one it
    // reaches is worse than no comment: it is why that branch survived to a
    // first audit unguarded.
    const data = [_]u8{0b0011_0000};
    try t.expectError(DecodeError.BadData, parseSegments(&data, 1, &out, &seq, &eci));
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

test "kanji: the worked example of ISO/IEC 18004 §7.4.6 packs to 13 bits per character, the count is in characters" {
    const t = std.testing;
    // 0x935F -> 0x0D9F = 0110110011111, 0xE4AA -> 0x1AAA = 1101010101010 (the standard's two examples).
    var buf: [8]u8 = @splat(0);
    var w: BitWriter = .{ .buf = &buf };
    putSegment(&w, .kanji, &.{ 0x93, 0x5F, 0xE4, 0xAA }, 1);
    // 1000 | 00000010 (two characters, 8 count bits at version 1) | 13 bits | 13 bits
    try t.expectEqual(@as(usize, 4 + 8 + 26), w.bit);
    var want_buf: [8]u8 = @splat(0);
    var want: BitWriter = .{ .buf = &want_buf };
    want.put(0b1000, 4);
    want.put(2, 8);
    want.put(0b0110110011111, 13);
    want.put(0b1101010101010, 13);
    try t.expectEqualSlices(u8, &want_buf, &buf);
}

test "kanji: forced mode round-trips through decode at every version range; the decoder returns Shift-JIS bytes" {
    const t = std.testing;
    var m: Matrix = undefined;
    var out: [512]u8 = undefined;
    // 点茗 and a few more valid pairs, including both range ends and the 0x7F-adjacent trail bytes.
    const text = [_]u8{ 0x93, 0x5F, 0xE4, 0xAA, 0x81, 0x40, 0x9F, 0xFC, 0xE0, 0x40, 0xEB, 0xBF, 0x88, 0x7E, 0x88, 0x80 };
    for ([_]u6{ 2, 9, 10, 26, 27, 40 }) |v| {
        for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
            try encode(&m, &text, .{ .mode = .kanji, .version = v, .ecc = ecc });
            try t.expectEqualSlices(u8, &text, try decode(&m, &out));
        }
    }
    // Picked version: 8 characters need version 1 at ECC L (capacity 10), version 2 at H (capacity 4 at v1).
    try encode(&m, &text, .{ .mode = .kanji, .ecc = .low });
    try t.expectEqual(@as(u6, 1), m.version);
    try encode(&m, &text, .{ .mode = .kanji, .ecc = .high });
    try t.expect(m.version > 1);
}

test "kanji: capacity in characters matches the standard (version 1: 10 at L, 4 at H; version 40-L: 1817), one more is TooLong" {
    const t = std.testing;
    var m: Matrix = undefined;
    var big: [3640]u8 = undefined;
    var i: usize = 0;
    while (i < big.len) : (i += 2) {
        big[i] = 0x88;
        big[i + 1] = 0x9F;
    }
    try encode(&m, big[0 .. 10 * 2], .{ .mode = .kanji, .version = 1, .ecc = .low });
    try t.expectError(Error.TooLong, encode(&m, big[0 .. 11 * 2], .{ .mode = .kanji, .version = 1, .ecc = .low }));
    try encode(&m, big[0 .. 4 * 2], .{ .mode = .kanji, .version = 1, .ecc = .high });
    try t.expectError(Error.TooLong, encode(&m, big[0 .. 5 * 2], .{ .mode = .kanji, .version = 1, .ecc = .high }));
    try encode(&m, big[0 .. 1817 * 2], .{ .mode = .kanji, .version = 40, .ecc = .low });
    try t.expectError(Error.TooLong, encode(&m, big[0 .. 1818 * 2], .{ .mode = .kanji, .version = 40, .ecc = .low }));
}

test "kanji: input that is not Shift-JIS double bytes is ModeMismatch; eci and optimize_segments cannot be combined; never chosen automatically" {
    const t = std.testing;
    var m: Matrix = undefined;
    const good = [_]u8{ 0x93, 0x5F };
    try t.expectError(Error.ModeMismatch, encode(&m, "abc", .{ .mode = .kanji }));
    try t.expectError(Error.ModeMismatch, encode(&m, good[0..1], .{ .mode = .kanji })); // odd length
    for ([_][2]u8{ .{ 0x80, 0x40 }, .{ 0xA0, 0x40 }, .{ 0xEC, 0x40 }, .{ 0xEB, 0xC0 }, .{ 0x88, 0x3F }, .{ 0x88, 0x7F }, .{ 0x88, 0xFD }, .{ 0x00, 0x00 } }) |bad| {
        try t.expectError(Error.ModeMismatch, encode(&m, &bad, .{ .mode = .kanji }));
    }
    try t.expectError(Error.ModeMismatch, encode(&m, &good, .{ .mode = .kanji, .eci = 20 }));
    try t.expectError(Error.ModeMismatch, encode(&m, &good, .{ .mode = .kanji, .optimize_segments = true }));
    try encode(&m, &good, .{}); // default: byte mode, as ever
    var out: [8]u8 = undefined;
    try t.expectEqualSlices(u8, &good, try decode(&m, &out));
    try t.expectEqual(Mode.byte, pickMode(&good));
}

test "kanji: a structured-append sequence splits on character boundaries and the parts reassemble" {
    const t = std.testing;
    var ms: [4]Matrix = undefined;
    var text: [16]u8 = undefined;
    var i: usize = 0;
    while (i < text.len) : (i += 2) {
        text[i] = 0x88 + @as(u8, @intCast(i / 2 % 4));
        text[i + 1] = 0x40 + @as(u8, @intCast(i / 2 % 100));
    }
    const parts = try encodeSequence(&ms, &text, .{ .mode = .kanji, .version = 1, .ecc = .high });
    try t.expect(parts.len > 1);
    var got: [16]u8 = undefined;
    var n: usize = 0;
    for (parts) |*pm| {
        var out: [64]u8 = undefined;
        const part = try decodePart(pm, &out);
        try t.expectEqual(@as(usize, 0), part.data.len % 2);
        @memcpy(got[n..][0..part.data.len], part.data);
        n += part.data.len;
    }
    try t.expectEqualSlices(u8, &text, got[0..n]);
}

test "kanji: the decoder refuses a 13-bit value outside both Shift-JIS ranges and a trail past 0xBC, and reads the two ranges" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    var seq: ?Sequence = null;
    var eci: ?u32 = null;
    // One-character kanji segment at version 1 (8 count bits) carrying the raw 13-bit value `v`.
    const Case = struct { v: u32, want: ?[2]u8 };
    const cases = [_]Case{
        .{ .v = 0, .want = .{ 0x81, 0x40 } }, // first of the low range
        .{ .v = 0x173C, .want = .{ 0x9F, 0xFC } }, // last of the low range (0x1E * 0xC0 + 0xBC)
        .{ .v = 0xD9F, .want = .{ 0x93, 0x5F } }, // the standard's first example
        .{ .v = 0x1AAA, .want = .{ 0xE4, 0xAA } }, // the second
        .{ .v = 0xBD, .want = null }, // trail offset 0xBD: past 0xFC
        .{ .v = 0x1FFF, .want = .{ 0xEB, 0xBF } }, // the largest 13-bit value is the last of the high range
        .{ .v = 0x1EBD, .want = null }, // hi 0x1E, lo 0xBD: past the 0xBC trail offset (the gap between the ranges)
    };
    for (cases) |c| {
        var b: TestBits = .{};
        b.put(0b1000, 4);
        b.put(1, 8);
        b.put(c.v, 13);
        if (c.want) |w| {
            try t.expectEqualSlices(u8, &w, try parseSegments(b.bytes(), 1, &out, &seq, &eci));
        } else {
            try t.expectError(DecodeError.BadData, parseSegments(b.bytes(), 1, &out, &seq, &eci));
        }
    }
    // A buffer one byte short of a character is BufferTooSmall, never a write past it.
    var one: [1]u8 = undefined;
    var b: TestBits = .{};
    b.put(0b1000, 4);
    b.put(1, 8);
    b.put(0xD9F, 13);
    try t.expectError(DecodeError.BufferTooSmall, parseSegments(b.bytes(), 1, &one, &seq, &eci));
}

/// The body of `fuzzDecode`. The seed layout is `sizeIndex, grid...`: the first
/// octet picks the side (17 + 4*n, clamped to `max_size`) and the rest fills the
/// module bits, cycling if the script is shorter than the grid.
///
/// ⚠ The old body drew the size with `smith.valueRangeAtMost(u8, 0, 42)` as
/// its FIRST draw and then filled every bit with another ranged draw, so
/// outside `--fuzz` it built a 17x17 grid of entirely light modules -- one
/// fixed input, every iteration, for the life of the harness. The Reed-Solomon
/// path the comment below is about was never entered: an all-light grid fails
/// the format-information BCH check long before it.
fn runDecodeScript(bytes: []const u8) bool {
    // A scanner builds this matrix from an image, so every field of it is
    // attacker-influenced — including a size and a format that never came from
    // an encoder. The Reed-Solomon path is the part that matters here: a
    // corrupted locator must end in an error, not an out-of-range index.
    var s = Script{ .bytes = bytes };
    var m: Matrix = .{};
    m.size = @as(u16, 17) + 4 * @as(u16, @intCast(s.ranged(0, 42)));
    if (m.size > max_size) m.size = max_size;
    for (0..m.bits.len) |i| m.bits[i] = s.byte();

    var out: [4096]u8 = undefined;
    if (decode(&m, &out)) |_| return true else |_| return false;
}

/// Grid scripts. The first octet is the size index; the rest is the module
/// pattern, cycled to fill the grid.
const decode_seeds = [_][]const u8{
    seedHex("00" ++ "00"), // the all-light 17×17 grid: exactly what the collapsed harness ran
    seedHex("00" ++ "ff"), // the all-dark 17×17 grid
    seedHex("00" ++ "55"), // a 17×17 checkerboard
    seedHex("00" ++ "0f0f3333"), // a repeating pattern with the period of a byte boundary
    seedHex("01" ++ "55"), // version 2 (21×21)
    seedHex("0a" ++ "55"), // a mid-range version
    seedHex("28" ++ "55"), // version 41's index: clamped to `max_size`
    seedHex("2a" ++ "ff"), // the index maximum: also clamped
    seedHex("2a" ++ "0123456789abcdef"), // the largest grid with a long pattern
    seedHex("00"), // the size index alone: the grid cycles a single zero octet
    seedHex(""), // the empty script
};

test "fuzz: decode never panics on an arbitrary grid" {
    try std.testing.fuzz({}, fuzzDecodeSmith, .{ .corpus = &decode_seeds });
}

test "fuzz driver: QR_FUZZ (decode)" {
    try fz.fuzz_driver.run(fuzzDecode, .{ .prefix = "QR_FUZZ", .name = "qr-decode" });
}

test "fuzz harness: decode, 200 seeds, reaches every outcome" {
    try DecodeMark.reach(fuzzDecode, "qr-decode", 200);
}

fn fuzzDecodeSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDecode(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script: [512]u8 = undefined;
    const n: usize = fz.drawInput(S, src, &script, &decode_seeds);
    _ = runDecodeScript(script[0..n]);
    DecodeMark.mark(.grid);
}

/// What one damage script did to a real symbol.
const DamageOutcome = struct {
    ecc: Ecc = .low,
    /// Modules actually flipped.
    flips: usize = 0,
    /// Whether `decode` recovered the message anyway.
    recovered: bool = false,
};

/// The body of `fuzzDamage`. The seed layout is `ecc, flipCount(2)`, then two
/// octets per flip giving the x and y of the module to invert.
///
/// ⛔ The old body drew `flips = smith.valueRangeAtMost(u16, 0, 200)` from an
/// exhausted input, so it was **0**: the harness encoded a symbol, flipped
/// nothing, decoded it and asserted it round-tripped. A test named "decode
/// survives damage to a real symbol" that never damaged anything -- and the
/// Berlekamp-Massey, Chien and Forney paths its own comment says it exists to
/// reach had never seen a single corrupted block. `ecc` was stuck at `.low`
/// for the same reason, so three of the four redundancy levels were never
/// built either.
fn runDamageScript(bytes: []const u8) !DamageOutcome {
    // Random noise rarely reaches the interesting branches; a valid symbol with
    // modules flipped does, because the format still decodes and the corrupted
    // blocks then exercise Berlekamp-Massey, Chien and Forney for real.
    var s = Script{ .bytes = bytes };
    var out: DamageOutcome = .{};
    out.ecc = @fromBackingInt(@intCast(s.byte() % 4));

    var m: Matrix = undefined;
    encode(&m, "FUZZ TARGET 12345", .{ .ecc = out.ecc }) catch return out;

    const orig = m;
    const flips = s.word() % 201;
    out.flips = flips;
    for (0..flips) |_| {
        const x: u16 = @intCast(s.byte() % m.size);
        const y: u16 = @intCast(s.byte() % m.size);
        m.setDark(x, y, !m.isDark(x, y));
    }

    var buf: [4096]u8 = undefined;
    // Net damage of at most two modules lies within what every ECC level
    // repairs (two modules touch at most two codewords, and the format and
    // version information carry their own BCH): it must be recovered.
    var net: usize = 0;
    for (0..m.size) |y| for (0..m.size) |x| {
        if (m.isDark(@intCast(x), @intCast(y)) != orig.isDark(@intCast(x), @intCast(y))) net += 1;
    };
    const got = decode(&m, &buf) catch {
        if (net <= 2) return error.RecoverableDamageNotRecovered;
        return out;
    };
    // If it claims success, the message must be the one that was encoded —
    // a decoder that returns confident nonsense is worse than one that refuses.
    try std.testing.expectEqualStrings("FUZZ TARGET 12345", got);
    out.recovered = true;
    return out;
}

/// Damage scripts: `ecc, flipCount(2)`, then `x, y` per flip. The flip
/// coordinates cycle, so a short script hits a repeating set of modules — which
/// is what makes a two-flip script reproducible rather than a lottery.
const damage_seeds = [_][]const u8{
    seedHex("00" ++ "0000"), // low ECC, undamaged: the round trip must hold
    seedHex("01" ++ "0000"), // medium, undamaged
    seedHex("02" ++ "0000"), // quartile, undamaged
    seedHex("03" ++ "0000"), // high, undamaged
    seedHex("00" ++ "0001" ++ "0a0a"), // ⭐ ONE flipped module at low ECC: the first real damage this harness has ever seen
    seedHex("03" ++ "0001" ++ "0a0a"), // one flip at high ECC
    seedHex("00" ++ "0004" ++ "0a0a0b0b0c0c0d0d"), // four flips in the data region
    seedHex("03" ++ "0004" ++ "0a0a0b0b0c0c0d0d"), // the same at high ECC, which should recover more
    seedHex("00" ++ "0010" ++ "0a0b"), // 16 flips cycling over two coordinates
    seedHex("03" ++ "0010" ++ "0a0b0c0d0e0f1011"), // 16 flips spread out, high ECC
    seedHex("00" ++ "0040" ++ "0102030405060708"), // 64 flips: past what low ECC can repair
    seedHex("03" ++ "00c8" ++ "0102030405060708"), // the 200-flip maximum
    seedHex("00" ++ "0002" ++ "00000000"), // both flips on the SAME module: a net no-op
    // ⚠ A 61-octet (ODD-length) coordinate tail, so the x/y pairing shifts on
    // every cycle instead of hitting the same modules again and again. With an
    // even-length tail a high flip count silently CANCELS -- flipping one module
    // twice is a no-op -- and a "200 flips" seed damages nothing, which is the
    // same class of quiet nothing the collapsed draw was.
    seedHex("00" ++ "0032" ++ "7160d26a7ee0833f7754b392bf077abe1c3d111e035a36cac03a0f842f336dac5270a517fb8e3194e0cf5a736fa1028ab239bdb72f2d03e321ff995d50"), // 50 scattered flips at low ECC
    seedHex("03" ++ "0032" ++ "7160d26a7ee0833f7754b392bf077abe1c3d111e035a36cac03a0f842f336dac5270a517fb8e3194e0cf5a736fa1028ab239bdb72f2d03e321ff995d50"), // the same 50 at high ECC, which repairs more
    seedHex("00" ++ "00c8" ++ "7160d26a7ee0833f7754b392bf077abe1c3d111e035a36cac03a0f842f336dac5270a517fb8e3194e0cf5a736fa1028ab239bdb72f2d03e321ff995d50"), // 200 scattered flips at low ECC: past any repair
    seedHex("00"), // one octet: the ecc byte alone, flips cycle to 0
    seedHex(""), // the empty script: exactly what the collapsed harness ran
};

test "fuzz: decode survives damage to a real symbol" {
    try std.testing.fuzz({}, fuzzDamageSmith, .{ .corpus = &damage_seeds });
}

test "fuzz driver: QR_FUZZ (damage)" {
    try fz.fuzz_driver.run(fuzzDamage, .{ .prefix = "QR_FUZZ", .name = "qr-damage", .scale = 2 });
}

test "fuzz harness: damage, 300 seeds, reaches every outcome" {
    try DamageMark.reach(fuzzDamage, "qr-damage", 300);
}

fn fuzzDamageSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDamage(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzDamage(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script: [512]u8 = undefined;
    const n: usize = fz.drawInput(S, src, &script, &damage_seeds);
    const out = try runDamageScript(script[0..n]);
    if (out.flips == 0) DamageMark.mark(.undamaged) else DamageMark.mark(.damaged);
    if (out.recovered) DamageMark.mark(.recovered) else DamageMark.mark(.refused);
}

test "corpus: the grid and damage scripts reach the decoder, and what they did is pinned" {
    // ⭐ Two guards in one, because the two harnesses share a failure: both
    // asserted something about a symbol they never varied.
    //
    // For the grid scripts the pinned number is the distinct SIZES built. A
    // decode that succeeds is not the interesting outcome here — an arbitrary
    // grid essentially never decodes — so "accepted" would be 0 for any corpus
    // and says nothing. What the collapsed harness could not do was try a
    // second grid shape at all.
    var grid_nonempty: usize = 0;
    var sizes_seen = @as([max_size + 1]bool, @splat(false));
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [512]u8 = undefined;
        const n: usize = smith.slice(&script);
        if (n != 0) grid_nonempty += 1;
        var s = Script{ .bytes = script[0..n] };
        var side: u16 = @as(u16, 17) + 4 * @as(u16, @intCast(s.ranged(0, 42)));
        if (side > max_size) side = max_size;
        sizes_seen[side] = true;
        _ = runDecodeScript(script[0..n]);
    }
    var sizes: usize = 0;
    for (sizes_seen) |b| {
        if (b) sizes += 1;
    }
    try std.testing.expectEqual(decode_seeds.len - 1, grid_nonempty);
    // Measured: 1 size (17), one all-light grid, before the draws
    // were fixed.
    try std.testing.expectEqual(@as(usize, 4), sizes);

    // For the damage scripts the pinned numbers are the modules actually
    // flipped and the symbols recovered despite them. `flips` was 0 for the
    // life of the harness, so the Reed-Solomon correction the whole target is
    // named after had never run on a corrupted block.
    var damage_nonempty: usize = 0;
    var total_flips: usize = 0;
    var recovered: usize = 0;
    var damaged_and_recovered: usize = 0;
    var ecc_seen = @as([4]bool, @splat(false));
    for (damage_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [512]u8 = undefined;
        const n: usize = smith.slice(&script);
        if (n != 0) damage_nonempty += 1;
        const out = try runDamageScript(script[0..n]);
        ecc_seen[@backingInt(out.ecc)] = true;
        total_flips += out.flips;
        if (out.recovered) {
            recovered += 1;
            if (out.flips != 0) damaged_and_recovered += 1;
        }
    }
    var eccs: usize = 0;
    for (ecc_seen) |b| {
        if (b) eccs += 1;
    }
    try std.testing.expectEqual(damage_seeds.len - 1, damage_nonempty);
    // Measured: 1 ECC level, 0 flips, and every "recovery" was of an
    // undamaged symbol.
    try std.testing.expectEqual(@as(usize, 4), eccs);
    try std.testing.expectEqual(@as(usize, 608), total_flips);
    // 17 of 18: the 200-flip low-ECC script is the ONE that cannot be repaired,
    // so both the correction path and the refusal after it are exercised. A
    // corpus where everything recovers proves only half of what this harness
    // claims.
    try std.testing.expectEqual(@as(usize, 17), recovered);
    // The one that matters: symbols that were actually damaged and still read
    // back correctly. This is the Reed-Solomon correction working, and it was
    // 0 before.
    try std.testing.expectEqual(@as(usize, 11), damaged_and_recovered);
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
    const message = "signed-payload:" ++ (strRepeat("0123456789abcdef", 40));

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
    const seq = try encodeSequence(&symbols, strRepeat("N", 200), .{ .version = 2, .ecc = .low });
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
    try t.expectError(Error.TooLong, encodeSequence(&two, strRepeat("N", 400), .{ .version = 1, .ecc = .high }));
    // Room is what is missing, not capacity: the same message splits happily
    // once there are symbols to put it in.
    var plenty: [16]Matrix = undefined;
    _ = try encodeSequence(&plenty, strRepeat("N", 400), .{ .version = 6, .ecc = .high });

    // Sixteen is the standard's ceiling, not ours, so a message that needs a
    // seventeenth symbol at the forced version is refused even with room.
    var many: [16]Matrix = undefined;
    try t.expectError(Error.TooLong, encodeSequence(&many, strRepeat("N", 5000), .{ .version = 1, .ecc = .high }));

    // Without a forced version the encoder grows the symbol instead of the count.
    const seq = try encodeSequence(&many, strRepeat("N", 5000), .{ .ecc = .high });
    try t.expect(seq.len <= 16);
    try t.expect(seq[0].version > 1);
}

test "the header costs capacity, and the accounting says so" {
    const t = std.testing;
    // A message that exactly fills a version 1-L symbol on its own cannot also
    // carry a 20-bit sequence header, and the split has to notice.
    const chunk = maxChunk(.byte, 1, .low, sequence_header_bits);
    var text: [64]u8 = undefined;
    @memset(&text, 'x');
    const fits_alone = text[0 .. chunk + 2];

    var m: Matrix = undefined;
    try encode(&m, fits_alone, .{ .version = 1, .ecc = .low });

    var symbols: [16]Matrix = undefined;
    const seq = try encodeSequence(&symbols, fits_alone, .{ .version = 1, .ecc = .low });
    try t.expectEqual(@as(usize, 2), seq.len);
}

/// What one sequence script produced.
const SequenceOutcome = struct {
    ecc: Ecc = .low,
    text_len: usize = 0,
    /// Symbols the split produced, 0 when `encodeSequence` refused.
    symbols: usize = 0,
};

/// The body of `fuzzSequence`. The seed layout is `ecc, text...`.
///
/// ⛔ The old body drew the message length FIRST, from a ranged draw, so
/// outside `--fuzz` it was 0: the harness split an EMPTY message, got one
/// symbol back, and asserted the round trip on nothing. `ecc` was stuck at
/// `.low` for the same reason. The whole point of the target -- that a message
/// too long for one symbol comes back in order and with the right parity --
/// requires a message longer than one symbol's capacity, and it never had one.
fn runSequenceScript(bytes: []const u8) !SequenceOutcome {
    var out: SequenceOutcome = .{};
    const ecc_byte: u8 = if (bytes.len > 0) bytes[0] else 0;
    const text: []const u8 = if (bytes.len > 1) bytes[1..] else "";
    out.ecc = @fromBackingInt(@intCast(ecc_byte % 4));
    out.text_len = text.len;

    var symbols: [16]Matrix = undefined;
    const seq = encodeSequence(&symbols, text, .{ .ecc = out.ecc }) catch return out;
    out.symbols = seq.len;

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
    return out;
}

/// Sequence scripts: `ecc, text...`.
const sequence_seeds = [_][]const u8{
    seed("\x00" ++ "SHORT"), // one symbol: the degenerate sequence, header still present
    seed("\x00" ++ (strRepeat("A", 100))), // still one symbol at low ECC
    seed("\x00" ++ (strRepeat("A", 400))), // ⭐ several symbols: the split this target exists for
    seed("\x01" ++ (strRepeat("A", 400))), // the same message at medium
    seed("\x02" ++ (strRepeat("A", 400))), // quartile: more symbols again
    seed("\x03" ++ (strRepeat("A", 400))), // high: the most symbols
    seed("\x03" ++ (strRepeat("N", 599))), // the longest message that fits the 600-octet buffer
    seed("\x00" ++ strRepeat("0123456789", 40)), // numeric mode across a split
    seed("\x00" ++ strRepeat("HELLO WORLD $%*+-./: ", 15)), // alphanumeric across a split
    seed("\x00" ++ strRepeat("\x00\xff", 150)), // bytes that force byte mode across a split
    seed("\x00" ++ strRepeat("P\xc5\x99\xc3\xadli\xc5\xa1 \xc5\xbelu\xc5\xa5ou\xc4\x8dk\xc3\xbd ", 12)), // multi-byte UTF-8 split mid-codepoint
    seed("\x00"), // the ecc byte with an EMPTY message
    seed(""), // the empty script: exactly what the collapsed harness ran
};

test "fuzz: a sequence survives the round trip whatever the message" {
    try std.testing.fuzz({}, fuzzSequenceSmith, .{ .corpus = &sequence_seeds });
}

test "fuzz driver: QR_FUZZ (sequence)" {
    try fz.fuzz_driver.run(fuzzSequence, .{ .prefix = "QR_FUZZ", .name = "qr-sequence", .scale = 8 });
}

test "fuzz harness: sequence, 300 seeds, reaches every outcome" {
    try SequenceMark.reach(fuzzSequence, "qr-sequence", 300);
}

fn fuzzSequenceSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzSequence(std.testing.Smith, smith, std.testing.allocator);
}

fn fuzzSequence(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var script: [601]u8 = undefined;
    const n: usize = fz.drawInput(S, src, &script, &sequence_seeds);
    const out = try runSequenceScript(script[0..n]);
    if (out.symbols != 0) SequenceMark.mark(.encoded);
    if (out.symbols > 1) SequenceMark.mark(.multi_symbol);
}

test "corpus: the sequence scripts really split, and the symbol counts are pinned" {
    // ⭐ The number that matters is `multi_symbol`: sequences that came back
    // as MORE THAN ONE symbol. `encodeSequence("")` succeeds and returns one
    // symbol, so "some sequences encoded" -- and even the whole round-trip
    // assertion -- was satisfied by the empty message the collapsed harness ran
    // every iteration, with the index/total/parity checks comparing 0 against 0
    // and 1 against 1. A sequence target that never produces a sequence proves
    // nothing about ordering or parity.
    var nonempty: usize = 0;
    var encoded: usize = 0;
    var multi_symbol: usize = 0;
    var total_symbols: usize = 0;
    var ecc_seen = @as([4]bool, @splat(false));
    for (sequence_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [601]u8 = undefined;
        const n: usize = smith.slice(&script);
        if (n != 0) nonempty += 1;
        const out = try runSequenceScript(script[0..n]);
        ecc_seen[@backingInt(out.ecc)] = true;
        if (out.symbols != 0) encoded += 1;
        if (out.symbols > 1) multi_symbol += 1;
        total_symbols += out.symbols;
    }
    var eccs: usize = 0;
    for (ecc_seen) |b| {
        if (b) eccs += 1;
    }
    // One seed is deliberately the empty script.
    try std.testing.expectEqual(sequence_seeds.len - 1, nonempty);
    // Measured: 1 ECC level, 1 sequence of 1 symbol carrying an
    // EMPTY message, and 0 multi-symbol splits before the draws were fixed.
    try std.testing.expectEqual(@as(usize, 4), eccs);
    try std.testing.expectEqual(@as(usize, 13), encoded);
    try std.testing.expectEqual(@as(usize, 10), multi_symbol);
    try std.testing.expectEqual(@as(usize, 120), total_symbols);
}

// ── TEETH: the decoder's refusal guards, none of which had a test ───────────
//
// A first audit deleted seven refusal guards in `parseSegments`
// and `rsDecode` one at a time. **Six of the seven left all 33 tests green** —
// only the format-info BCH radius was pinned. Two of the six are
// silent-corruption guards, not crash guards: without them a malformed symbol
// decodes to a *different string* rather than being refused, which is the
// failure mode a decoder must never have.
//
// These drive `parseSegments` directly, because building a full symbol for each
// case would test the encoder as much as the guard.

/// Bit-appender for hand-built segment streams, MSB first — the order
/// `BitReader` reads.
const TestBits = struct {
    buf: [64]u8 = @splat(0),
    n: usize = 0,

    fn put(self: *TestBits, value: u32, bits: u5) void {
        var i: u5 = bits;
        while (i > 0) {
            i -= 1;
            const bit: u1 = @intCast((value >> i) & 1);
            if (bit == 1) self.buf[self.n >> 3] |= @as(u8, 0x80) >> @intCast(self.n & 7);
            self.n += 1;
        }
    }
    fn bytes(self: *const TestBits) []const u8 {
        return self.buf[0 .. (self.n + 7) / 8];
    }
};

test "TEETH: an unimplemented segment mode is REFUSED, not read as bytes" {
    // Mutating `else => return DecodeError.BadData` to `else => .byte` left the whole
    // suite green: an FNC1 (0b0101 / 0b1001) segment would have been silently
    // reinterpreted as byte data (ECI and Kanji are implemented and are no longer in the refused list
    // below), i.e. decoded to a different string, with nothing to say so.
    var out: [128]u8 = undefined;
    var seq: ?Sequence = null;
    var eci: ?u32 = null;

    // ⚠ The payload behind the bad indicator is a WELL-FORMED byte segment.
    // A first version of this test put arbitrary bytes there, and it passed
    // under the mutation for the wrong reason: reinterpreted as byte mode, the
    // next octet read as a count of 65, which did not fit the buffer, so it
    // still errored — by a route that has nothing to do with the guard. With a
    // count of 2 and two bytes behind it, the mutated decoder succeeds and
    // returns "hi", so only the guard itself can produce the refusal.
    for ([_]u32{ 0b0101, 0b1001, 0b1111 }) |raw_mode| {
        var b: TestBits = .{};
        b.put(raw_mode, 4);
        b.put(2, 8); // a count a byte-mode reader would accept
        b.put('h', 8);
        b.put('i', 8);
        try std.testing.expectError(
            DecodeError.BadData,
            parseSegments(b.bytes(), 1, &out, &seq, &eci),
        );
    }

    // Control: a byte segment on the same path still decodes, so the refusal is
    // about the mode and not about the fixture being unreadable.
    var ok: TestBits = .{};
    ok.put(0b0100, 4); // byte mode
    ok.put(2, 8); // count, 8 bits at version 1
    ok.put('h', 8);
    ok.put('i', 8);
    const got = try parseSegments(ok.bytes(), 1, &out, &seq, &eci);
    try std.testing.expectEqualStrings("hi", got);
}

test "TEETH: a structured-append index past its total is REFUSED" {
    // `if (index > total) return BadData` deleted cleanly. A symbol claiming
    // "part 9 of 3" would have been accepted and handed to the caller to
    // reassemble.
    var out: [128]u8 = undefined;
    var seq: ?Sequence = null;
    var eci: ?u32 = null;
    var b: TestBits = .{};
    b.put(sequence_mode, 4);
    b.put(9, 4); // index
    b.put(3, 4); // total
    b.put(0xAB, 8); // parity
    b.put(0b0100, 4); // a byte segment after it
    b.put(1, 8);
    b.put('x', 8);
    try std.testing.expectError(DecodeError.BadData, parseSegments(b.bytes(), 1, &out, &seq, &eci));

    // Control: index == total is legal (part 3 of 3) and must be accepted.
    var ok: TestBits = .{};
    ok.put(sequence_mode, 4);
    ok.put(2, 4); // index 2, i.e. the third part, 0-based
    ok.put(2, 4);
    ok.put(0xAB, 8);
    ok.put(0b0100, 4);
    ok.put(1, 8);
    ok.put('x', 8);
    const got = try parseSegments(ok.bytes(), 1, &out, &seq, &eci);
    try std.testing.expectEqualStrings("x", got);
    try std.testing.expect(seq != null);
}

test "TEETH: out-of-range numeric and alphanumeric groups are REFUSED, not folded" {
    // Both range checks deleted cleanly. These are the silent-corruption pair:
    // a 10-bit numeric group above 999, or an 11-bit alphanumeric pair above
    // 44*45+44, is not a legal encoding, and without the check it decodes to
    // *some other string* rather than being refused.
    var out: [128]u8 = undefined;
    var seq: ?Sequence = null;
    var eci: ?u32 = null;

    // Numeric: one group of three digits, value 1000 (the smallest illegal).
    var num: TestBits = .{};
    num.put(0b0001, 4); // numeric mode
    num.put(3, 10); // count = 3 digits, 10 bits at version 1
    num.put(1000, 10);
    try std.testing.expectError(DecodeError.BadData, parseSegments(num.bytes(), 1, &out, &seq, &eci));

    // Alphanumeric: one pair, value 45*45 (the smallest illegal).
    var alnum: TestBits = .{};
    alnum.put(0b0010, 4); // alphanumeric mode
    alnum.put(2, 9); // count = 2 chars, 9 bits at version 1
    alnum.put(45 * 45, 11);
    try std.testing.expectError(DecodeError.BadData, parseSegments(alnum.bytes(), 1, &out, &seq, &eci));

    // Controls: the largest LEGAL value in each encoding still decodes.
    var num_ok: TestBits = .{};
    num_ok.put(0b0001, 4);
    num_ok.put(3, 10);
    num_ok.put(999, 10);
    try std.testing.expectEqualStrings("999", try parseSegments(num_ok.bytes(), 1, &out, &seq, &eci));

    var alnum_ok: TestBits = .{};
    alnum_ok.put(0b0010, 4);
    alnum_ok.put(2, 9);
    alnum_ok.put(44 * 45 + 44, 11); // ":" ":" — the last pair in the table
    _ = try parseSegments(alnum_ok.bytes(), 1, &out, &seq, &eci);
}

test "EXTERNAL ORACLE: 160 segno-produced grids decode back to segno's own input" {
    // SPEC.md named the gap in its own words: "It does not anchor decoding,
    // error correction, structured append, or the renderers ... Extending the
    // oracle to decoding (e.g. segno's matrices fed to this module's decoder)
    // is future work, not something this pass claims to have done." The
    // committed golden set anchors the ENCODER, and only 10 of 40 versions —
    // so a shared misreading of the standard on the decode side would have
    // gone unseen.
    //
    // These grids were produced by segno (BSD-3, independently authored) and
    // this module must read segno's own bytes back out of them. It is not a
    // round trip: nothing here was encoded by this module.
    //
    // 160 vectors: every version (1-40) at every level (L/M/Q/H), with the mode
    // cycling so all three appear across the version range. The generator
    // (`scripts/gen/gen-qr-decode-vectors.py`) emits all 960; all 960 passed when
    // this landed, and 308 KB is what is worth committing.
    const blob = @embedFile("testdata/decode_vectors.bin");
    var off: usize = 0;
    const count = std.mem.readInt(u32, blob[0..4], .little);
    off = 4;
    try std.testing.expect(count == 160);

    var seen_versions = @as([41]bool, @splat(false));
    var seen_ecc = @as([4]bool, @splat(false));
    var decoded: usize = 0;

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const version = blob[off];
        const ecc_raw = blob[off + 1];
        off += 4; // version, ecc, mode, mask
        const size = std.mem.readInt(u16, blob[off..][0..2], .little);
        const clen = std.mem.readInt(u16, blob[off + 2 ..][0..2], .little);
        off += 4;
        const content = blob[off..][0..clen];
        off += clen;
        const bit_bytes = (@as(usize, size) * size + 7) / 8;
        const bits = blob[off..][0..bit_bytes];
        off += bit_bytes;

        var m: Matrix = .{ .size = size };
        var idx: usize = 0;
        while (idx < @as(usize, size) * size) : (idx += 1) {
            // Row-major, MSB first, continuous across rows — the generator's
            // documented layout.
            const dark = (bits[idx >> 3] >> @intCast(7 - (idx & 7))) & 1 != 0;
            m.setDark(@intCast(idx % size), @intCast(idx / size), dark);
        }

        var out: [4096]u8 = undefined;
        const got = decode(&m, &out) catch |err| {
            std.debug.print(
                "vector {d} (version {d}, ecc {d}, size {d}) failed to decode: {any}\n",
                .{ i, version, ecc_raw, size, err },
            );
            return err;
        };
        try std.testing.expectEqualStrings(content, got);
        seen_versions[version] = true;
        seen_ecc[ecc_raw] = true;
        decoded += 1;
    }

    // The corpus must actually span what it claims to span, or a shrunken
    // regenerated file would quietly narrow the anchor.
    try std.testing.expectEqual(@as(usize, 160), decoded);
    for (1..41) |v| try std.testing.expect(seen_versions[v]);
    for (0..4) |e| try std.testing.expect(seen_ecc[e]);
    try std.testing.expectEqual(blob.len, off);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

// ── ECI ─────────────────────────────────────────────────────────────────────

test "ECI: header bits match ISO/IEC 18004 §7.4.2.2 for the three designator lengths" {
    var b: [8]u8 = @splat(0);
    var w: BitWriter = .{ .buf = &b };
    putEci(&w, 26); // 0111 00011010
    try std.testing.expectEqual(@as(usize, 12), w.bit);
    try std.testing.expectEqualSlices(u8, &.{ 0x71, 0xA0 }, b[0..2]);

    @memset(&b, 0);
    w = .{ .buf = &b };
    putEci(&w, 128); // 0111 10 00000010000000
    try std.testing.expectEqual(@as(usize, 20), w.bit);
    try std.testing.expectEqualSlices(u8, &.{ 0x78, 0x08, 0x00 }, b[0..3]);

    @memset(&b, 0);
    w = .{ .buf = &b };
    putEci(&w, 999_999); // 0111 110_01111 01000010 00111111
    try std.testing.expectEqual(@as(usize, 28), w.bit);
    try std.testing.expectEqualSlices(u8, &.{ 0x7C, 0xF4, 0x23, 0xF0 }, b[0..4]);

    try std.testing.expectEqual(@as(usize, 0), eciBits(null));
    try std.testing.expectEqual(@as(usize, 12), eciBits(127));
    try std.testing.expectEqual(@as(usize, 20), eciBits(128));
    try std.testing.expectEqual(@as(usize, 20), eciBits(16383));
    try std.testing.expectEqual(@as(usize, 28), eciBits(16384));
}

test "ECI 26 + UTF-8 text round-trips and decode reports the number" {
    const t = std.testing;
    const text = "Žluťoučký kůň — 日本語";
    var m: Matrix = undefined;
    try encode(&m, text, .{ .eci = 26 });
    var buf: [128]u8 = undefined;
    const part = try decodePart(&m, &buf);
    try t.expectEqualStrings(text, part.data);
    try t.expectEqual(@as(?u32, 26), part.eci);
    try t.expect(part.sequence == null);
    // `decode` returns the data of an ECI symbol too.
    try t.expectEqualStrings(text, try decode(&m, &buf));

    // Without the option there is no designator.
    try encode(&m, text, .{});
    try t.expectEqual(@as(?u32, null), (try decodePart(&m, &buf)).eci);
}

test "ECI: all three designator lengths round-trip through a symbol" {
    const t = std.testing;
    var buf: [64]u8 = undefined;
    for ([_]u32{ 0, 3, 26, 127, 128, 900, 16383, 16384, 123_456, max_eci }) |e| {
        var m: Matrix = undefined;
        try encode(&m, "hi\xC3\xA9", .{ .eci = e });
        const part = try decodePart(&m, &buf);
        try t.expectEqualStrings("hi\xC3\xA9", part.data);
        try t.expectEqual(@as(?u32, e), part.eci);
    }
}

test "ECI: version selection counts the header bits" {
    const t = std.testing;
    // Version 1-L holds 152 data bits: 4 + 8 + 8n for n bytes -> 17 bytes fit,
    // so 17 bytes without ECI is version 1, and with ECI (12 bits) it is not.
    const msg = "ABCDEFGHIJKLMNOPQ".*; // 17 bytes
    var m: Matrix = undefined;
    try encode(&m, &msg, .{ .ecc = .low, .mode = .byte });
    try t.expectEqual(@as(u6, 1), m.version);
    try encode(&m, &msg, .{ .ecc = .low, .eci = 26 });
    try t.expectEqual(@as(u6, 2), m.version);
    // A forced version that the header pushes over is refused, not truncated.
    try t.expectError(Error.TooLong, encode(&m, &msg, .{ .ecc = .low, .eci = 26, .version = 1 }));
    // 16 bytes: 12 (ECI) + 4 + 8 + 128 = 152 bits, exactly version 1-L.
    try encode(&m, msg[0..16], .{ .ecc = .low, .eci = 26, .version = 1 });
    var buf: [32]u8 = undefined;
    try t.expectEqualStrings(msg[0..16], (try decodePart(&m, &buf)).data);
}

test "ECI: option errors" {
    const t = std.testing;
    var m: Matrix = undefined;
    try t.expectError(Error.BadEci, encode(&m, "x", .{ .eci = max_eci + 1 }));
    try t.expectError(Error.ModeMismatch, encode(&m, "123", .{ .eci = 3, .mode = .numeric }));
    // Unforced mode with ECI is byte mode even for digits.
    try encode(&m, "123", .{ .eci = 3 });
    var buf: [8]u8 = undefined;
    try t.expectEqualStrings("123", (try decodePart(&m, &buf)).data);
}

test "ECI: every symbol of a structured-append sequence carries it" {
    const t = std.testing;
    var big: [200]u8 = undefined;
    for (&big, 0..) |*c, i| c.* = @intCast('a' + i % 26);
    var ms: [16]Matrix = undefined;
    const parts = try encodeSequence(&ms, &big, .{ .ecc = .low, .eci = 26 });
    try t.expect(parts.len > 1);
    var buf: [64]u8 = undefined;
    var total: usize = 0;
    for (parts) |*pm| {
        const p = try decodePart(pm, &buf);
        try t.expectEqual(@as(?u32, 26), p.eci);
        try t.expect(p.sequence != null);
        try t.expectEqualSlices(u8, big[total..][0..p.data.len], p.data);
        total += p.data.len;
    }
    try t.expectEqual(big.len, total);
}

test "ECI decode: 1/2/3-byte forms, refusals" {
    var out: [16]u8 = undefined;
    var seq: ?Sequence = null;

    // Non-minimal forms are accepted: ECI 3 as 2 and 3 bytes.
    inline for (.{ .{ 16, 0b10 << 14 | 3 }, .{ 24, 0b110 << 21 | 3 } }) |f| {
        var eci: ?u32 = null;
        var b: TestBits = .{};
        b.put(eci_mode, 4);
        b.put(f[1], f[0]);
        b.put(0b0100, 4);
        b.put(1, 8);
        b.put('x', 8);
        try std.testing.expectEqualStrings("x", try parseSegments(b.bytes(), 1, &out, &seq, &eci));
        try std.testing.expectEqual(@as(?u32, 3), eci);
    }

    // Truncated designators: 2-byte form missing its second byte, 3-byte form
    // missing its tail, bare mode indicator, and the reserved 111xxxxx prefix.
    inline for (.{ .{ 8, 0b10_000011 }, .{ 16, 0b110_00000 << 8 | 1 }, .{ 0, 0 }, .{ 8, 0b1110_0000 } }) |f| {
        var eci: ?u32 = null;
        var b: TestBits = .{};
        b.put(eci_mode, 4);
        if (f[0] > 0) b.put(f[1], f[0]);
        // No data and no padding: the bit stream just ends (byte-aligned zeros
        // would read as a terminator, so give it a stream that is cut short).
        const bytes = b.bytes();
        const r = parseSegments(bytes, 1, &out, &seq, &eci);
        try std.testing.expectError(DecodeError.BadData, r);
    }

    // 24-bit value above 999999.
    {
        var eci: ?u32 = null;
        var b: TestBits = .{};
        b.put(eci_mode, 4);
        b.put(0b110 << 21 | 1_000_000, 24);
        try std.testing.expectError(DecodeError.BadData, parseSegments(b.bytes(), 1, &out, &seq, &eci));
    }

    // A second designator, and one after data, are refused.
    {
        var eci: ?u32 = null;
        var b: TestBits = .{};
        b.put(eci_mode, 4);
        b.put(26, 8);
        b.put(eci_mode, 4);
        b.put(3, 8);
        try std.testing.expectError(DecodeError.BadData, parseSegments(b.bytes(), 1, &out, &seq, &eci));
        eci = null;
        var c: TestBits = .{};
        c.put(0b0100, 4);
        c.put(1, 8);
        c.put('x', 8);
        c.put(eci_mode, 4);
        c.put(26, 8);
        try std.testing.expectError(DecodeError.BadData, parseSegments(c.bytes(), 1, &out, &seq, &eci));
    }
}

// ── mixed-mode segments (Options.optimize_segments) ─────────────────────────

test "mixed: exact bit count against a hand count" {
    const t = std.testing;
    // "HELLO" + 30 digits. Single alphanumeric (v1-9 widths): 4 + 9 + 17*11 + 6 = 206.
    // Mixed: alnum "HELLO" = 4 + 9 + 2*11 + 6 = 41, numeric 30 digits = 4 + 10 + 10*10 = 114 -> 155.
    const text = "HELLO123456789012345678901234567890";
    var buf: [max_mixed]u8 = undefined;
    try t.expectEqual(@as(usize, 206), dataBits(.alphanumeric, text.len, 1));
    try t.expectEqual(@as(usize, 155), planSegments(text, 1, &buf));
    for (buf[0..5]) |m| try t.expectEqual(@as(u8, 1), m);
    for (buf[5..text.len]) |m| try t.expectEqual(@as(u8, 0), m);
    // Lower-case head: byte "hello" = 4 + 8 + 40 = 52, plus 114 -> 166 vs 292 single byte.
    try t.expectEqual(@as(usize, 166), planSegments("hello123456789012345678901234567890", 1, &buf));
    // A pure payload stays one segment at the single-mode cost.
    try t.expectEqual(dataBits(.numeric, 7, 1), planSegments("1234567", 1, &buf));
    try t.expectEqual(dataBits(.alphanumeric, 5, 1), planSegments("AB CD", 1, &buf));
}

test "mixed: smaller version than the single-mode default, decoder reads the segment list" {
    const t = std.testing;
    const text = "HELLO123456789012345678901234567890";
    var a: Matrix = undefined;
    var b: Matrix = undefined;
    try encode(&a, text, .{ .ecc = .quartile });
    try encode(&b, text, .{ .ecc = .quartile, .optimize_segments = true });
    try t.expectEqual(@as(u6, 3), a.version);
    try t.expectEqual(@as(u6, 2), b.version);
    var out: [64]u8 = undefined;
    try t.expectEqualStrings(text, try decode(&b, &out));
    // Mixed + digits/upper/bytes at v1: "HELLO WORLD 2026" never worse than default.
    try encode(&a, "HELLO WORLD 2026", .{});
    try encode(&b, "HELLO WORLD 2026", .{ .optimize_segments = true });
    try t.expect(b.version <= a.version);
    try t.expectEqualStrings("HELLO WORLD 2026", try decode(&b, &out));
}

test "mixed: default output is untouched and the option conflicts are refused" {
    const t = std.testing;
    var a: Matrix = undefined;
    var b: Matrix = undefined;
    try encode(&a, "12345", .{});
    try encode(&b, "12345", .{ .optimize_segments = false });
    try t.expectEqualSlices(u8, &a.bits, &b.bits);
    // A pure payload under mixed encodes to the very same symbol.
    try encode(&b, "12345", .{ .optimize_segments = true });
    try t.expectEqualSlices(u8, &a.bits, &b.bits);
    try t.expectError(Error.ModeMismatch, encode(&b, "12345", .{ .optimize_segments = true, .mode = .numeric }));
    try t.expectError(Error.ModeMismatch, encode(&b, "12345", .{ .optimize_segments = true, .eci = 26 }));
    try t.expectError(Error.BadVersion, encode(&b, "A1", .{ .optimize_segments = true, .version = 41 }));
    try t.expectError(Error.TooLong, encode(&b, "HELLO123456789012345678901234567890", .{ .optimize_segments = true, .version = 1 }));
    // Empty text falls back to the default path.
    try encode(&b, "", .{ .optimize_segments = true });
}

test "mixed: a payload that only fits with mixing" {
    const t = std.testing;
    var text: [4500]u8 = undefined;
    @memset(text[0..1500], 'a');
    @memset(text[1500..], '7');
    var m: Matrix = undefined;
    try t.expectError(Error.TooLong, encode(&m, &text, .{ .ecc = .low }));
    try encode(&m, &text, .{ .ecc = .low, .optimize_segments = true });
    try t.expect(m.version >= 38);
    var out: [4600]u8 = undefined;
    try t.expectEqualSlices(u8, &text, try decode(&m, &out));
    // Over the absolute maximum.
    var big: [max_mixed + 1]u8 = undefined;
    @memset(&big, '1');
    try t.expectError(Error.TooLong, encode(&m, &big, .{ .ecc = .low, .optimize_segments = true }));
}

test "mixed: random digit/upper/byte payloads round-trip, never a larger version" {
    const t = std.testing;
    var prng = std.Random.DefaultPrng.init(0x51c0de);
    const rnd = prng.random();
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    var m: Matrix = undefined;
    var d: Matrix = undefined;
    var out: [512]u8 = undefined;
    for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
        for (0..40) |_| {
            var text: [200]u8 = undefined;
            const len = rnd.uintLessThan(usize, 120) + 1;
            var i: usize = 0;
            while (i < len) {
                const run = @min(len - i, rnd.uintLessThan(usize, 14) + 1);
                const kind = rnd.uintLessThan(u8, 3);
                for (0..run) |k| text[i + k] = switch (kind) {
                    0 => '0' + rnd.uintLessThan(u8, 10),
                    1 => upper[rnd.uintLessThan(usize, upper.len)],
                    else => rnd.int(u8),
                };
                i += run;
            }
            const s = text[0..len];
            try encode(&m, s, .{ .ecc = ecc, .optimize_segments = true });
            try t.expectEqualSlices(u8, s, try decode(&m, &out));
            if (encode(&d, s, .{ .ecc = ecc })) |_| {
                try t.expect(m.version <= d.version);
            } else |_| {}
        }
    }
}

// ── whole-module mutation tests ─────────────────────────────────

fn sameMatrix(a: *const Matrix, b: *const Matrix) !void {
    const t = std.testing;
    try t.expectEqual(a.size, b.size);
    try t.expectEqual(a.version, b.version);
    try t.expectEqual(a.mask, b.mask);
    for (0..a.size) |y| for (0..a.size) |x| {
        if (a.isDark(@intCast(x), @intCast(y)) != b.isDark(@intCast(x), @intCast(y))) return error.MatrixMismatch;
    };
}

test "mutation: encodeSequence refuses a bad version and more than sixteen symbols" {
    const t = std.testing;
    const out = try t.allocator.alloc(Matrix, 20);
    defer t.allocator.free(out);
    try t.expectError(Error.BadVersion, encodeSequence(out, "abc", .{ .version = 0 }));
    try t.expectError(Error.BadVersion, encodeSequence(out, "abc", .{ .version = 41 }));
    try t.expectError(Error.BadVersion, encode(&out[0], "abc", .{ .version = 0 }));
    // 20 slots are offered but the standard counts to 16: a message that needs 17 symbols
    // even at version 40 is refused, searched or forced.
    const big = try t.allocator.alloc(u8, 17 * maxChunk(.byte, 40, .low, sequence_header_bits) - 16);
    defer t.allocator.free(big);
    @memset(big, 'x');
    try t.expectError(Error.TooLong, encodeSequence(out, big, .{ .ecc = .low }));
    try t.expectError(Error.TooLong, encodeSequence(out, big, .{ .ecc = .low, .version = 40 }));
}

test "mutation: a forced version holds exactly as many symbols as there are slots" {
    const t = std.testing;
    var out: [2]Matrix = undefined;
    const chunk = maxChunk(.byte, 5, .medium, sequence_header_bits);
    const text = try t.allocator.alloc(u8, 2 * chunk + 1);
    defer t.allocator.free(text);
    @memset(text, 'x');
    const two = try encodeSequence(&out, text[0 .. 2 * chunk], .{ .ecc = .medium, .version = 5 });
    try t.expectEqual(@as(usize, 2), two.len);
    try t.expectError(Error.TooLong, encodeSequence(&out, text, .{ .ecc = .medium, .version = 5 }));
}

test "mutation: the largest symbol is reachable, one-symbol sequences included" {
    const t = std.testing;
    const text = try t.allocator.alloc(u8, 2900);
    defer t.allocator.free(text);
    @memset(text, 'x');
    var m: Matrix = undefined;
    try encode(&m, text, .{ .ecc = .low });
    try t.expectEqual(@as(u6, 40), m.version);
    var out: [1]Matrix = undefined;
    const one = try encodeSequence(&out, text, .{ .ecc = .low });
    try t.expectEqual(@as(usize, 1), one.len);
    try t.expectEqual(@as(u6, 40), one[0].version);
}

test "mutation: every symbol of a sequence has the one chosen version and mode" {
    const t = std.testing;
    var text: [71]u8 = undefined;
    text[0] = 'k';
    for (text[1..], 0..) |*c, i| c.* = '0' + @as(u8, @intCast(i % 10));
    var out: [4]Matrix = undefined;
    const got = try encodeSequence(&out, &text, .{ .ecc = .low });
    try t.expect(got.len >= 2);
    const chunk = maxChunk(.byte, got[0].version, .low, sequence_header_bits);
    var exp: Matrix = undefined;
    for (got, 0..) |g, i| {
        const start = i * chunk;
        const end = @min(start + chunk, text.len);
        try encodeOne(&exp, text[start..end], .{ .ecc = .low, .version = got[0].version, .mode = .byte }, .{
            .index = @intCast(i),
            .total = @intCast(got.len),
            .parity = sequenceParity(&text),
        });
        try sameMatrix(&exp, &g);
    }
}

test "mutation: optimize_segments is ignored by encodeSequence, and by empty text" {
    const t = std.testing;
    var text: [90]u8 = undefined;
    for (&text, 0..) |*c, i| c.* = if (i % 9 < 5) '0' + @as(u8, @intCast(i % 10)) else 'a' + @as(u8, @intCast(i % 20));
    var a: [4]Matrix = undefined;
    var b: [4]Matrix = undefined;
    const x = try encodeSequence(&a, &text, .{ .ecc = .low });
    const y = try encodeSequence(&b, &text, .{ .ecc = .low, .optimize_segments = true });
    try t.expectEqual(x.len, y.len);
    for (x, y) |p, q| try sameMatrix(&p, &q);

    var e1: Matrix = undefined;
    var e2: Matrix = undefined;
    try encode(&e1, "", .{});
    try encode(&e2, "", .{ .optimize_segments = true });
    try sameMatrix(&e1, &e2);
}

test "mutation: the longest mixed text fits, one more does not; version 0 is refused" {
    const t = std.testing;
    const digits = try t.allocator.alloc(u8, max_mixed + 1);
    defer t.allocator.free(digits);
    @memset(digits, '7');
    var m: Matrix = undefined;
    try encode(&m, digits[0..max_mixed], .{ .ecc = .low, .optimize_segments = true });
    try t.expectEqual(@as(u6, 40), m.version);
    try t.expectError(Error.TooLong, encode(&m, digits, .{ .ecc = .low, .optimize_segments = true }));
    try t.expectError(Error.BadVersion, encode(&m, "1", .{ .optimize_segments = true, .version = 0 }));
}

test "mutation: an exact fit is accepted by every version selector" {
    const t = std.testing;
    const d27 = "012345678901234567890123456";
    try t.expectEqual(dataCapacityBits(1, .quartile), dataBits(.numeric, 27, 1));
    var m: Matrix = undefined;
    try encode(&m, d27, .{ .ecc = .quartile, .version = 1 });
    try encode(&m, d27, .{ .ecc = .quartile });
    try t.expectEqual(@as(u6, 1), m.version);
    try encode(&m, d27, .{ .ecc = .quartile, .version = 1, .optimize_segments = true });
    try encode(&m, d27, .{ .ecc = .quartile, .optimize_segments = true });
    try t.expectEqual(@as(u6, 1), m.version);
    var buf: [max_mixed]u8 = undefined;
    try t.expectEqual(@as(u6, 1), try pickMixedVersion(d27, .quartile, 1, &buf));
    try t.expectEqual(@as(?u6, 1), pickVersion(.numeric, 27, .quartile, 0));
    try t.expectEqual(@as(?u6, 2), pickVersion(.numeric, 28, .quartile, 0));
}

test "mutation: gf.inverse(0) is the documented 0" {
    try std.testing.expectEqual(@as(u8, 0), gf.inverse(0));
    try std.testing.expectEqual(@as(u8, 1), gf.mul(gf.inverse(2), 2));
}

test "mutation: a character-count field is never the binding limit (maxChunk)" {
    // If this fails, `maxChunk`'s count_max clamp becomes live.
    const t = std.testing;
    for (1..41) |vv| {
        const v: u6 = @intCast(vv);
        for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
            for ([_]Mode{ .numeric, .alphanumeric, .byte }) |mode| {
                const count_max = (@as(usize, 1) << countBits(mode, v)) - 1;
                try t.expect(dataBits(mode, count_max + 1, v) > dataCapacityBits(v, ecc));
            }
        }
    }
    // And a header of at most 48 bits always leaves room for a character: chunk >= 1.
    for ([_]Mode{ .numeric, .alphanumeric, .byte }) |mode| {
        try t.expect(maxChunk(mode, 1, .high, sequence_header_bits + 28) >= 1);
    }
}

/// Exact minimal bit count of `text` over every split into numeric / alphanumeric / byte
/// segments, the character-count widths of version `v`. `maxInt` if none exists.
fn oracleMixedBits(text: []const u8, v: u6) usize {
    const inf = std.math.maxInt(usize);
    var dp: [1300]usize = undefined;
    dp[0] = 0;
    for (1..text.len + 1) |i| {
        dp[i] = inf;
        var num_ok = true;
        var an_ok = true;
        var j: usize = i;
        while (j > 0) {
            j -= 1;
            num_ok = num_ok and text[j] >= '0' and text[j] <= '9';
            an_ok = an_ok and alnumValue(text[j]) != null;
            if (dp[j] == inf) continue;
            const len = i - j;
            const modes = [3]Mode{ .numeric, .alphanumeric, .byte };
            const ok = [3]bool{ num_ok, an_ok, true };
            for (modes, ok) |mode, allowed| {
                if (!allowed or len >= @as(usize, 1) << countBits(mode, v)) continue;
                dp[i] = @min(dp[i], dp[j] + dataBits(mode, len, v));
            }
        }
    }
    return dp[text.len];
}

fn oracleMixedVersion(text: []const u8, ecc: Ecc) ?u6 {
    const reps = [3]u6{ 1, 10, 27 }; // the count widths change at these versions only
    var bits: [3]usize = undefined;
    for (reps, 0..) |rv, i| bits[i] = oracleMixedBits(text, rv);
    var v: u6 = 1;
    while (v <= 40) : (v += 1) {
        const b = bits[if (v <= 9) 0 else if (v <= 26) 1 else 2];
        if (b != std.math.maxInt(usize) and b <= dataCapacityBits(v, ecc)) return v;
    }
    return null;
}

fn oracleText(buf: []u8, kind: u8, n: usize) []const u8 {
    for (buf[0..n], 0..) |*c, i| c.* = switch (kind) {
        0 => '0' + @as(u8, @intCast(i % 10)),
        1 => "ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:0123456789"[i % 44],
        2 => 'a' + @as(u8, @intCast(i % 26)),
        3 => if ((i / 7) % 3 == 0) '0' + @as(u8, @intCast(i % 10)) else if ((i / 7) % 3 == 1) 'A' + @as(u8, @intCast(i % 26)) else 'a' + @as(u8, @intCast(i % 26)),
        else => if ((i / 11) % 2 == 0) '5' else 'z',
    };
    return buf[0..n];
}

test "mutation: planSegments finds the exact minimum, pickMixedVersion the exact smallest version" {
    const t = std.testing;
    var text_buf: [1300]u8 = undefined;
    var plan: [max_mixed]u8 = undefined;
    var lens: [64]usize = undefined;
    var nl: usize = 0;
    for ([_]usize{ 1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 17, 22, 31, 40, 55, 70, 95, 130, 180 }) |n| {
        lens[nl] = n;
        nl += 1;
    }
    var n: usize = 262;
    while (n <= 276) : (n += 1) { // the 8-bit / 16-bit count boundary of the byte mode
        lens[nl] = n;
        nl += 1;
    }
    for ([_]usize{ 330, 1023, 1024 }) |nn| {
        lens[nl] = nn;
        nl += 1;
    }
    for (lens[0..nl]) |len| {
        for (0..5) |kind| {
            const text = oracleText(&text_buf, @intCast(kind), len);
            for ([_]u6{ 1, 9, 10, 26, 27 }) |rep| {
                const want = oracleMixedBits(text, rep);
                const got = planSegments(text, rep, &plan);
                // A run longer than the count field is not split by the planner, which is
                // harmless: such a text cannot fit the group's largest symbol anyway.
                const last: u6 = if (rep <= 9) 9 else if (rep <= 26) 26 else 40;
                if (want > dataCapacityBits(last, .low)) {
                    try t.expect(got == want or got == std.math.maxInt(usize));
                } else {
                    try t.expectEqual(want, got);
                }
            }
            for ([_]Ecc{ .low, .quartile }) |ecc| {
                const want = oracleMixedVersion(text, ecc);
                if (pickMixedVersion(text, ecc, null, &plan)) |got| {
                    try t.expectEqual(want.?, got);
                } else |_| {
                    try t.expectEqual(@as(?u6, null), want);
                }
            }
        }
    }
}

// ── penalty: differential test against a naive transcription of ISO/IEC 18004 §8.8.2 ──

fn refPenalty(m: *const Matrix) u32 {
    const side: usize = m.size;
    var score: u32 = 0;
    // N1: five or more in a row or column: 3 + (length - 5)
    for (0..2) |dir| {
        for (0..side) |a| {
            var b: usize = 0;
            while (b < side) {
                const first = if (dir == 0) m.isDark(@intCast(b), @intCast(a)) else m.isDark(@intCast(a), @intCast(b));
                var e = b + 1;
                while (e < side) : (e += 1) {
                    const v = if (dir == 0) m.isDark(@intCast(e), @intCast(a)) else m.isDark(@intCast(a), @intCast(e));
                    if (v != first) break;
                }
                if (e - b >= 5) score += @intCast(3 + (e - b - 5));
                b = e;
            }
        }
    }
    // N2: 2x2 blocks
    for (0..side - 1) |y| for (0..side - 1) |x| {
        const c = m.isDark(@intCast(x), @intCast(y));
        if (m.isDark(@intCast(x + 1), @intCast(y)) == c and m.isDark(@intCast(x), @intCast(y + 1)) == c and m.isDark(@intCast(x + 1), @intCast(y + 1)) == c) score += 3;
    };
    // N3: 1011101 with four light modules before or after, every window counted
    const dl = [_]u8{ 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0 };
    const ld = [_]u8{ 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1 };
    for (0..2) |dir| for (0..side) |a| {
        if (side < 11) continue;
        for (0..side - 10) |b| {
            for ([_][11]u8{ dl, ld }) |pat| {
                var hit = true;
                for (0..11) |k| {
                    const v = if (dir == 0) m.isDark(@intCast(b + k), @intCast(a)) else m.isDark(@intCast(a), @intCast(b + k));
                    if (@intFromBool(v) != pat[k]) hit = false;
                }
                if (hit) score += 40;
            }
        }
    };
    // N4: 10 per started... full 5% step of the exact deviation from 50%
    var dark: usize = 0;
    for (0..side) |y| for (0..side) |x| {
        if (m.isDark(@intCast(x), @intCast(y))) dark += 1;
    };
    const total = side * side;
    const twice = dark * 2;
    const dev = if (twice > total) twice - total else total - twice; // |2*dark - total|
    score += @intCast(dev * 10 / total * 10);
    return score;
}

test "mutation: penalty equals the ISO reference on random, striped and finder-like grids" {
    const t = std.testing;
    var prng = std.Random.DefaultPrng.init(0x51C0DE);
    const rnd = prng.random();
    var m: Matrix = undefined;
    for (0..400) |round| {
        const side: u16 = 21 + 4 * @as(u16, @intCast(round % 4));
        m = .{ .size = side };
        @memset(&m.bits, 0);
        const densities = [_]u8{ 50, 20, 80, 10, 92 };
        const density = densities[round % 5];
        for (0..side) |y| for (0..side) |x| m.setDark(@intCast(x), @intCast(y), rnd.uintLessThan(u8, 100) < density);
        if (round % 3 == 0) { // plant finder-like windows, both orientations and both layouts
            for (0..6) |_| {
                const a = rnd.uintLessThan(usize, side);
                const b0 = rnd.uintLessThan(usize, side - 10);
                const horiz = rnd.boolean();
                const flip = rnd.boolean();
                const pat = if (flip) [_]u8{ 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1 } else [_]u8{ 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0 };
                for (0..11) |k| {
                    if (horiz) m.setDark(@intCast(b0 + k), @intCast(a), pat[k] == 1) else m.setDark(@intCast(a), @intCast(b0 + k), pat[k] == 1);
                }
            }
        }
        if (round % 7 == 0) { // long runs and full blocks
            for (0..side) |x| m.setDark(@intCast(x), 3, round % 2 == 0);
            for (0..side) |y| m.setDark(5, @intCast(y), round % 2 == 1);
        }
        try t.expectEqual(refPenalty(&m), penalty(&m));
    }
}

test "mutation: the auto mask is the lowest-numbered of equal minimum penalties" {
    const t = std.testing;
    var ties: usize = 0;
    var text: [24]u8 = undefined;
    var k: usize = 0;
    while (k < 4000 and ties < 3) : (k += 1) {
        const s = std.fmt.bufPrint(&text, "{d}", .{k * 7919 + 13}) catch unreachable;
        var scores: [8]u32 = undefined;
        var m: Matrix = undefined;
        for (0..8) |p| {
            try encode(&m, s, .{ .mask = @intCast(p) });
            scores[p] = penalty(&m);
        }
        var best: usize = 0;
        var n_best: usize = 0;
        for (scores, 0..) |sc, p| {
            if (sc < scores[best]) best = p;
        }
        for (scores) |sc| n_best += @intFromBool(sc == scores[best]);
        try encode(&m, s, .{});
        try t.expectEqual(@as(u3, @intCast(best)), m.mask);
        if (n_best > 1) ties += 1;
    }
    try t.expect(ties >= 1);
}

// ── format information: each copy alone must be readable, and the BCH radius is exactly 3 ──

fn formatPos(side: u16, copy: u1, k: u16) [2]u16 {
    if (copy == 0) {
        const x: u16 = if (k <= 7) 8 else if (k == 8) 7 else 14 - k;
        const y: u16 = if (k <= 5) k else if (k == 6) 7 else if (k == 7) 8 else 8;
        return .{ x, y };
    }
    return if (k < 8) .{ side - 1 - k, 8 } else .{ 8, side - 15 + k };
}

fn flipFormat(m: *Matrix, copy: u1, bits: u16) void {
    for (0..15) |k| {
        if ((bits >> @intCast(k)) & 1 == 1) {
            const p = formatPos(m.size, copy, @intCast(k));
            m.setDark(p[0], p[1], !m.isDark(p[0], p[1]));
        }
    }
}

/// A weight-4 error pattern no codeword of the format code is nearer to than 4: the same for
/// every format value (the valid words are one coset of a linear code).
fn farPattern() u16 {
    const data: u32 = (@as(u32, Ecc.medium.formatBits()) << 3) | 5;
    const word = ((data << 10) | bch(data, 0x537, 10)) ^ 0x5412;
    var s: u16 = 0;
    while (s < 0x8000) : (s += 1) {
        if (@popCount(s) != 4) continue;
        var nearest: u32 = 16;
        for (0..32) |c| {
            const cw = ((@as(u32, @intCast(c)) << 10) | bch(@intCast(c), 0x537, 10)) ^ 0x5412;
            nearest = @min(nearest, @popCount(cw ^ word ^ s));
        }
        if (nearest == 4) return s;
    }
    unreachable;
}

test "mutation: format information is read from either copy alone, up to three errors each" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    var m: Matrix = undefined;
    const far = farPattern();
    for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
        for (0..8) |mask| {
            try encode(&m, "1", .{ .ecc = ecc, .mask = @intCast(mask), .version = 1 });
            // one copy unreadable (four errors), the other with three errors; both ways round
            var a = m;
            flipFormat(&a, 1, far);
            flipFormat(&a, 0, 0b000000000000111);
            try t.expectEqualStrings("1", try decode(&a, &out));
            var b = m;
            flipFormat(&b, 0, far);
            flipFormat(&b, 1, 0b000000100100001);
            try t.expectEqualStrings("1", try decode(&b, &out));
            // both copies with exactly three errors
            var c = m;
            flipFormat(&c, 0, 0b000000100100010);
            flipFormat(&c, 1, 0b100000001000100);
            try t.expectEqualStrings("1", try decode(&c, &out));
            // one copy unreadable, the other intact
            var d = m;
            flipFormat(&d, 0, far);
            try t.expectEqualStrings("1", try decode(&d, &out));
            var e = m;
            flipFormat(&e, 1, far);
            try t.expectEqualStrings("1", try decode(&e, &out));
        }
    }
}

test "mutation: four format errors in both copies are refused when no codeword is nearer than four" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    var m: Matrix = undefined;
    try encode(&m, "1", .{ .ecc = .medium, .mask = 5, .version = 1 });
    const far = farPattern();
    flipFormat(&m, 0, far);
    flipFormat(&m, 1, far);
    try t.expectError(DecodeError.BadFormat, decode(&m, &out));
}

test "mutation: the first long block's last codeword is read in its own place" {
    const t = std.testing;
    var text: [40]u8 = undefined;
    for (&text, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    var m: Matrix = undefined;
    try encode(&m, &text, .{ .version = 5, .ecc = .quartile, .mask = 2 });
    const spec = ecSpec(5, .quartile);
    const total = totalCodewords(5);
    const data_len = total - @as(usize, spec.ec_per_block) * spec.blocks;
    const short = data_len / spec.blocks;
    const long = data_len % spec.blocks;
    try t.expect(long > 0);
    // damage 9 (= the level's capability) data codewords of each long block, short of the long block's
    // extra last one: a reader that misplaces that one then has a tenth error and fails
    var scratch: Matrix = .{ .size = m.size, .version = 5 };
    @memset(&scratch.bits, 0);
    var reserved: [(max_size * max_size + 7) / 8]u8 = undefined;
    @memset(&reserved, 0);
    drawFunctionPatterns(&scratch, &reserved);
    var cw_of_bit: [max_codewords * 8][2]u16 = undefined;
    var w = Walk.init(m.size, &reserved);
    var nbits: usize = 0;
    while (w.next()) |p| : (nbits += 1) cw_of_bit[nbits] = p;
    for (spec.blocks - long..spec.blocks) |b| {
        var d = m;
        for (short - 9..short) |j| {
            var idx: usize = 0;
            for (0..j) |r| {
                for (0..spec.blocks) |bb| {
                    if (r < short + @as(usize, @intFromBool(bb >= spec.blocks - long))) idx += 1;
                }
            }
            for (0..b) |bb| {
                if (j < short + @as(usize, @intFromBool(bb >= spec.blocks - long))) idx += 1;
            }
            for (0..8) |bit| {
                const p = cw_of_bit[idx * 8 + bit];
                d.setDark(p[0], p[1], !d.isDark(p[0], p[1]));
            }
        }
        var out: [64]u8 = undefined;
        try t.expectEqualSlices(u8, &text, try decode(&d, &out));
    }
}

fn segDecode(bits: *const TestBits, out: []u8) DecodeError![]u8 {
    var seq: ?Sequence = null;
    var eci: ?u32 = null;
    return parseSegments(bits.bytes(), 1, out, &seq, &eci);
}

test "mutation: parseSegments guards, boundaries and exact-fit buffers" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    // a structured-append header is only legal as the first segment
    var b1: TestBits = .{};
    b1.put(0b0100, 4);
    b1.put(1, 8);
    b1.put('A', 8);
    b1.put(0b0011, 4);
    b1.put(0, 4);
    b1.put(0, 4);
    b1.put(0, 8);
    try t.expectError(DecodeError.BadData, segDecode(&b1, &out));
    // ECI designator 111xxxxx is reserved
    var b2: TestBits = .{};
    b2.put(0b0111, 4);
    b2.put(0xE0, 8);
    b2.put(0, 16);
    try t.expectError(DecodeError.BadData, segDecode(&b2, &out));
    // numeric: three digits, exact fit and one short
    var n3: TestBits = .{};
    n3.put(0b0001, 4);
    n3.put(3, 10);
    n3.put(123, 10);
    try t.expectEqualStrings("123", try segDecode(&n3, out[0..3]));
    try t.expectError(DecodeError.BufferTooSmall, segDecode(&n3, out[0..2]));
    // numeric: one trailing digit, then two trailing digits
    var n4: TestBits = .{};
    n4.put(0b0001, 4);
    n4.put(4, 10);
    n4.put(123, 10);
    n4.put(4, 4);
    try t.expectEqualStrings("1234", try segDecode(&n4, out[0..4]));
    try t.expectError(DecodeError.BufferTooSmall, segDecode(&n4, out[0..3]));
    var n5: TestBits = .{};
    n5.put(0b0001, 4);
    n5.put(5, 10);
    n5.put(123, 10);
    n5.put(45, 7);
    try t.expectEqualStrings("12345", try segDecode(&n5, out[0..5]));
    try t.expectError(DecodeError.BufferTooSmall, segDecode(&n5, out[0..4]));
    // numeric groups out of range: a single digit above 9, a pair above 99
    var s10: TestBits = .{};
    s10.put(0b0001, 4);
    s10.put(1, 10);
    s10.put(10, 4);
    try t.expectError(DecodeError.BadData, segDecode(&s10, &out));
    var p100: TestBits = .{};
    p100.put(0b0001, 4);
    p100.put(2, 10);
    p100.put(100, 7);
    try t.expectError(DecodeError.BadData, segDecode(&p100, &out));
    // alphanumeric: a pair and a single, exact fit; single index 45 and 63 are refused
    var a2: TestBits = .{};
    a2.put(0b0010, 4);
    a2.put(2, 9);
    a2.put(0, 11);
    try t.expectEqualStrings("00", try segDecode(&a2, out[0..2]));
    try t.expectError(DecodeError.BufferTooSmall, segDecode(&a2, out[0..1]));
    var a1: TestBits = .{};
    a1.put(0b0010, 4);
    a1.put(1, 9);
    a1.put(44, 6);
    try t.expectEqualStrings(":", try segDecode(&a1, out[0..1]));
    try t.expectError(DecodeError.BufferTooSmall, segDecode(&a1, out[0..0]));
    for ([_]u32{ 45, 63 }) |bad| {
        var a: TestBits = .{};
        a.put(0b0010, 4);
        a.put(1, 9);
        a.put(bad, 6);
        try t.expectError(DecodeError.BadData, segDecode(&a, &out));
    }
    // byte: exact fit
    var by: TestBits = .{};
    by.put(0b0100, 4);
    by.put(2, 8);
    by.put('a', 8);
    by.put('b', 8);
    try t.expectEqualStrings("ab", try segDecode(&by, out[0..2]));
    try t.expectError(DecodeError.BufferTooSmall, segDecode(&by, out[0..1]));
}

test "mutation: planSegments equals the exact optimum on random mixed texts" {
    const t = std.testing;
    var plan0: [max_mixed]u8 = undefined;
    // found by a 20000-text search: without rounding a segment end up to a whole bit, the
    // planner's sixth-of-a-bit costs pick a segmentation one bit longer than the optimum
    const hard = [_]struct { text: []const u8, bits: usize }{
        .{ .text = "/DR1149637643OSMhggj22dffcf1908779VR:9MLRNQ0ZL9223774OL8613", .bits = 390 },
        .{ .text = "PRI4hiO6%3700814052ETRZA0-6ZdehgeM$", .bits = 262 },
        .{ .text = "9029613833jdhG/ddgHO 7884627558CAFXH$HA67.VN8245fcjfjbbajcgg", .bits = 410 },
    };
    for (hard) |h| {
        try t.expectEqual(h.bits, oracleMixedBits(h.text, 1));
        try t.expectEqual(h.bits, planSegments(h.text, 1, &plan0));
    }
    var prng = std.Random.DefaultPrng.init(0xC057);
    const rnd = prng.random();
    var text: [120]u8 = undefined;
    var plan: [max_mixed]u8 = undefined;
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
    for (0..400) |_| {
        const len = rnd.uintLessThan(usize, 100) + 1;
        var i: usize = 0;
        while (i < len) {
            const run = @min(len - i, rnd.uintLessThan(usize, 12) + 1);
            const kind = rnd.uintLessThan(u8, 3);
            for (0..run) |k| text[i + k] = switch (kind) {
                0 => '0' + rnd.uintLessThan(u8, 10),
                1 => upper[rnd.uintLessThan(usize, upper.len)],
                else => 'a' + rnd.uintLessThan(u8, 26),
            };
            i += run;
        }
        for ([_]u6{ 1, 10, 27 }) |rep| {
            try t.expectEqual(oracleMixedBits(text[0..len], rep), planSegments(text[0..len], rep, &plan));
        }
    }
}

test "mutation: a forced version refuses text one bit over its capacity" {
    const t = std.testing;
    var m: Matrix = undefined;
    var hits: usize = 0;
    var buf: [300]u8 = undefined;
    for (1..6) |vv| {
        const v: u6 = @intCast(vv);
        for ([_]Ecc{ .low, .medium, .quartile, .high }) |ecc| {
            for (1..buf.len) |len| {
                const bits = dataBits(.alphanumeric, len, v);
                const cap = dataCapacityBits(v, ecc);
                if (bits != cap + 1 and bits != cap) continue;
                @memset(buf[0..len], 'A');
                if (bits == cap) {
                    try encode(&m, buf[0..len], .{ .version = v, .ecc = ecc, .mode = .alphanumeric });
                } else {
                    try t.expectError(Error.TooLong, encode(&m, buf[0..len], .{ .version = v, .ecc = ecc, .mode = .alphanumeric }));
                    hits += 1;
                }
            }
        }
    }
    try t.expect(hits >= 1);
}
