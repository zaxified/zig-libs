// SPDX-License-Identifier: MIT
//! Transcoding core: caller-buffer, allocation-free decode and encode with a
//! progress result — the shape of encoding_rs's `decode_to_utf8(src, dst,
//! last) -> (result, read, written)` and x/text's `Transform(dst, src,
//! atEOF)`. Every allocating entry point of the module is a loop over these.
//!
//! Hot paths skip ASCII 32 bytes at a time; a single-byte page decodes a
//! high byte through a precomputed UTF-8 table and encodes a code point
//! through a two-level reverse table, both built at compile time from the
//! page's 128-entry decode table.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");
const utf8_simd = @import("utf8_simd.zig");

/// Why a call returned.
pub const Status = enum {
    /// Every byte of `src` was consumed (a partial sequence at the end of a
    /// non-`last` call is consumed into the coder's state, never left).
    input_empty,
    /// `dst` has no room for the next output; call again with more room.
    output_full,
    /// Fatal mode only: an ill-formed sequence. `read`/`written` stop at it;
    /// what came before was written.
    malformed,
};

pub const Progress = struct {
    status: Status,
    read: usize,
    written: usize,
    /// A replacement (U+FFFD on decode, the unmappable substitute on
    /// encode) was written.
    replaced: bool = false,
};

/// A decode-table entry with no code point: the byte decodes to U+FFFD and
/// no code point encodes to it (WHATWG: a pointer missing from the index).
pub const unmapped: u16 = 0xFFFF;

const lanes = 32;
const V = @Vector(lanes, u8);

/// Length of the ASCII prefix of `s`.
pub fn asciiPrefix(s: []const u8) usize {
    var i: usize = 0;
    while (i + lanes <= s.len) : (i += lanes) {
        const v: V = s[i..][0..lanes].*;
        const bits: u32 = @bitCast(v >= @as(V, @splat(0x80)));
        if (bits != 0) return i + @ctz(bits);
    }
    while (i < s.len and s[i] < 0x80) i += 1;
    return i;
}

/// Copy the ASCII run at `src[r..]` into `dst[w..]` as far as both allow;
/// returns how many bytes were copied.
inline fn copyAscii(src: []const u8, r: usize, dst: []u8, w: usize) usize {
    // Sweep REV-EN-2: scan no further than `dst` can take, or a caller-buffer loop with a small
    // `dst` over a long ASCII `src` rescans the whole tail on every call (quadratic).
    const room = @min(src.len - r, dst.len - w);
    const n = asciiPrefix(src[r..][0..room]);
    @memcpy(dst[w..][0..n], src[r..][0..n]);
    return n;
}

fn utf8Encode(cp: u21, out: *[4]u8) u3 {
    return std.unicode.utf8Encode(cp, out) catch unreachable; // only scalar values reach here
}

/// The derived tables of one single-byte page.
pub fn SingleByte(comptime decode_table: [128]u16) type {
    return struct {
        pub const decode = decode_table;

        /// UTF-8 of each high byte: bytes in [0..3], length in [3]. An
        /// unmapped byte is U+FFFD.
        const utf8: [128][4]u8 = blk: {
            var t: [128][4]u8 = undefined;
            for (decode_table, 0..) |cp, i| {
                var b: [4]u8 = undefined;
                const n = utf8Encode(if (cp == unmapped) 0xFFFD else cp, &b);
                t[i] = .{ b[0], b[1], b[2], n };
            }
            const final = t;
            break :blk final;
        };

        /// Code point -> byte, two levels over the BMP: `hi[cp >> 8]` picks a
        /// 256-entry block (block 0 is all "none"), whose entry is the byte
        /// or 0. A page's high half covers a handful of blocks, so this is a
        /// few KiB per page instead of a linear search per character.
        const rev = blk: {
            @setEvalBranchQuota(200_000);
            var hi: [256]u8 = @splat(0);
            var n: usize = 0;
            for (decode_table) |cp| {
                if (cp == unmapped or cp < 0x80) continue;
                if (hi[cp >> 8] == 0) {
                    n += 1;
                    hi[cp >> 8] = n;
                }
            }
            var blocks: [n + 1][256]u8 = @splat(@splat(0));
            for (decode_table, 0..) |cp, i| {
                if (cp == unmapped or cp < 0x80) continue;
                // WHATWG: the encoder uses the FIRST pointer of a code point.
                const slot = &blocks[hi[cp >> 8]][cp & 0xFF];
                if (slot.* == 0) slot.* = 0x80 + i;
            }
            const Rev = struct { hi: [256]u8, blocks: [n + 1][256]u8 };
            const final: Rev = .{ .hi = hi, .blocks = blocks };
            break :blk final;
        };

        /// The page's byte for `cp`, or null.
        pub inline fn encodeCp(cp: u21) ?u8 {
            if (cp < 0x80) return @intCast(cp);
            if (cp > 0xFFFF) return null;
            const b = rev.blocks[rev.hi[cp >> 8]][cp & 0xFF];
            return if (b == 0) null else b;
        }

        /// Stateless decode of `src` into `dst`. `fatal`: stop with
        /// `.malformed` at a byte the page leaves undefined.
        pub fn decodeToUtf8(src: []const u8, dst: []u8, fatal: bool) Progress {
            var r: usize = 0;
            var w: usize = 0;
            var replaced = false;
            while (r < src.len) {
                const n = copyAscii(src, r, dst, w);
                r += n;
                w += n;
                if (r == src.len) break;
                if (src[r] < 0x80) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
                // A run of high bytes (dense in non-Latin text).
                while (r < src.len and src[r] >= 0x80) {
                    const e = &utf8[src[r] - 0x80];
                    const len = e[3];
                    if (dst.len - w < len) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
                    if (decode_table[src[r] - 0x80] == unmapped) {
                        if (fatal) return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
                        replaced = true;
                    }
                    @memcpy(dst[w..][0..len], e[0..len]);
                    r += 1;
                    w += len;
                }
            }
            return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
        }
    };
}

/// What a single-byte encoder writes for a code point the page lacks.
pub const Unmappable = enum {
    /// `?` — the module's long-standing default (Python `errors="replace"`).
    question_mark,
    /// Nothing (Python `errors="ignore"`).
    ignore,
    /// `&#NNNN;` — the WHATWG encoder's own error mode for HTML forms
    /// (encoding_rs's default `encode`).
    html_ncr,
    /// Stop with `EncodeStatus.unmappable` and the code point (Python
    /// `errors="strict"`, encoding_rs `encode_from_utf8_without_replacement`).
    fatal,
};

pub const EncodeStatus = enum { input_empty, output_full, unmappable };

pub const EncodeProgress = struct {
    status: EncodeStatus,
    read: usize,
    written: usize,
    replaced: bool = false,
    /// With `.unmappable`: the code point; `read` stops before it.
    code_point: u21 = 0,
};

/// One UTF-8 sequence at `s[i..]` as `encodeFromUtf8` has always read it
/// (`std.unicode` rules): a code point and its length, `.invalid` (the lead
/// byte is passed through verbatim and the scan moves one byte), or
/// `.incomplete` (the sequence runs past the end of `s`).
const Seq = union(enum) { cp: struct { cp: u21, len: u3 }, invalid, incomplete };

inline fn nextSeq(s: []const u8, i: usize) Seq {
    const b0 = s[i];
    const len: u3 = std.unicode.utf8ByteSequenceLength(b0) catch return .invalid;
    if (i + len > s.len) return .incomplete;
    const cp = std.unicode.utf8Decode(s[i..][0..len]) catch return .invalid;
    return .{ .cp = .{ .cp = cp, .len = len } };
}

/// The longest substitute an unmappable code point can need (`&#1114111;`).
pub const max_substitute = 10;

/// UTF-8 to a single-byte page. Invalid UTF-8 passes through byte by byte
/// (the module's lenient contract); a sequence cut by the end of `src` is
/// left unread unless `last` (then its lead byte passes through, as a
/// whole-buffer call always did).
pub fn encodeSingleByte(comptime Page: type, src: []const u8, dst: []u8, last: bool, mode: Unmappable) EncodeProgress {
    var r: usize = 0;
    var w: usize = 0;
    var replaced = false;
    while (r < src.len) {
        const n = copyAscii(src, r, dst, w);
        r += n;
        w += n;
        if (r == src.len) break;
        if (src[r] < 0x80) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        while (r < src.len and src[r] >= 0x80) {
            if (dst.len - w < max_substitute) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
            switch (nextSeq(src, r)) {
                .invalid => {
                    dst[w] = src[r];
                    w += 1;
                    r += 1;
                },
                .incomplete => {
                    if (!last) return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
                    dst[w] = src[r];
                    w += 1;
                    r += 1;
                },
                .cp => |c| {
                    if (Page.encodeCp(c.cp)) |b| {
                        dst[w] = b;
                        w += 1;
                    } else switch (mode) {
                        .question_mark => {
                            dst[w] = '?';
                            w += 1;
                            replaced = true;
                        },
                        .ignore => replaced = true,
                        .html_ncr => {
                            const out = std.fmt.bufPrint(dst[w..], "&#{d};", .{c.cp}) catch unreachable;
                            w += out.len;
                            replaced = true;
                        },
                        .fatal => return .{ .status = .unmappable, .read = r, .written = w, .replaced = replaced, .code_point = c.cp },
                    }
                    r += c.len;
                },
            }
        }
    }
    return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
}

// ── UTF-8 → UTF-8 with replacement (the WHATWG UTF-8 decoder) ─────────────

/// The WHATWG UTF-8 decoder's state between calls.
pub const Utf8State = struct {
    needed: u8 = 0,
    seen: u8 = 0,
    cp: u21 = 0,
    lower: u8 = 0x80,
    upper: u8 = 0xBF,

    pub fn pending(self: Utf8State) bool {
        return self.needed != 0;
    }
};

pub const replacement = "\u{FFFD}";

/// Length of a well-formed sequence starting at `s[i]` (lead byte >= 0x80)
/// that lies wholly in `s`, or 0 when it is ill-formed or cut by the end.
/// The WHATWG/Unicode well-formed ranges, so a 0 here sends the bytes to the
/// state machine, which then decides maximal subparts exactly.
inline fn wellFormedLen(s: []const u8, i: usize) usize {
    const b0 = s[i];
    const left = s.len - i;
    switch (b0) {
        0xC2...0xDF => {
            if (left >= 2 and s[i + 1] & 0xC0 == 0x80) return 2;
        },
        0xE0...0xEF => {
            if (left < 3) return 0;
            const b1 = s[i + 1];
            const lo: u8 = if (b0 == 0xE0) 0xA0 else 0x80;
            const hi: u8 = if (b0 == 0xED) 0x9F else 0xBF;
            if (b1 >= lo and b1 <= hi and s[i + 2] & 0xC0 == 0x80) return 3;
        },
        0xF0...0xF4 => {
            if (left < 4) return 0;
            const b1 = s[i + 1];
            const lo: u8 = if (b0 == 0xF0) 0x90 else 0x80;
            const hi: u8 = if (b0 == 0xF4) 0x8F else 0xBF;
            if (b1 >= lo and b1 <= hi and s[i + 2] & 0xC0 == 0x80 and s[i + 3] & 0xC0 == 0x80) return 4;
        },
        else => {},
    }
    return 0;
}

/// Is `s` well-formed UTF-8? (The fast path's own rule, so it agrees with
/// `decodeUtf8` by construction.)
pub fn validUtf8(s: []const u8) bool {
    var i: usize = utf8_simd.validPrefix(s);
    while (i < s.len) {
        i += asciiPrefix(s[i..]);
        while (i < s.len and s[i] >= 0x80) {
            const n = wellFormedLen(s, i);
            if (n == 0) return false;
            i += n;
        }
    }
    return true;
}

/// Length of the longest well-formed UTF-8 prefix of `s`: the index of the
/// first byte that cannot be part of well-formed UTF-8 (the start of an
/// ill-formed sequence, or of one cut by the end of `s`), or `s.len`. The same
/// rule as `validUtf8` and `decodeUtf8` (Rust's `Utf8Error::valid_up_to`).
pub fn utf8ValidUpTo(s: []const u8) usize {
    var i: usize = utf8_simd.validPrefix(s);
    while (i < s.len) {
        i += asciiPrefix(s[i..]);
        while (i < s.len and s[i] >= 0x80) {
            const n = wellFormedLen(s, i);
            if (n == 0) return i;
            i += n;
        }
    }
    return i;
}

/// Decode UTF-8 with replacement, one U+FFFD per maximal subpart. `last`:
/// the end of `src` is the end of the stream (a pending sequence becomes
/// U+FFFD). Needs room for 6 bytes before each non-ASCII step.
pub fn decodeUtf8(state: *Utf8State, src: []const u8, dst: []u8, last: bool, fatal: bool) Progress {
    var local = state.*;
    defer state.* = local;
    const st = &local;
    var r: usize = 0;
    var w: usize = 0;
    var replaced = false;
    // The vector validator runs again only this far past where it last
    // stopped short, so input dense with errors is not re-scanned per byte.
    var simd_from: usize = 0;
    while (r < src.len) {
        if (st.needed == 0 and r >= simd_from) {
            const lim = @min(src.len - r, dst.len - w);
            const v = utf8_simd.copyValidPrefix(src[r..][0..lim], dst[w..][0..lim]);
            r += v;
            w += v;
            if (r == src.len) break;
            simd_from = r + 64;
        }
        if (st.needed == 0) {
            const n = copyAscii(src, r, dst, w);
            r += n;
            w += n;
            if (r == src.len) break;
            if (src[r] < 0x80) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
            // Whole well-formed sequences are copied as they are.
            while (r < src.len and src[r] >= 0x80) {
                if (dst.len - w < 6) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
                const len = wellFormedLen(src, r);
                if (len == 0) break;
                @memcpy(dst[w..][0..len], src[r..][0..len]);
                r += len;
                w += len;
            }
            if (r == src.len or src[r] < 0x80) continue;
        }
        // The state machine: an ill-formed sequence, or one cut by the end
        // of `src` (possibly started in an earlier call).
        if (dst.len - w < 6) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        const b = src[r];
        // Through a copy: taking `w`'s own address kept it in memory for
        // the whole loop (a store-to-load round trip per step).
        var w2 = w;
        const rep = utf8Step(st, b, dst, &w2, fatal) catch return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
        w = w2;
        if (rep) replaced = true;
        r += 1;
    }
    if (last and st.needed != 0) {
        if (fatal) return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
        if (dst.len - w < 3) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        st.* = .{};
        @memcpy(dst[w..][0..3], replacement);
        w += 3;
        replaced = true;
    }
    return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
}

/// One byte through the WHATWG UTF-8 decoder; returns whether a U+FFFD was
/// written. Writes at most 6 bytes: U+FFFD for the cut sequence, then the
/// byte read again — itself ASCII (1) or invalid (another U+FFFD).
fn utf8Step(st: *Utf8State, b: u8, dst: []u8, w: *usize, fatal: bool) error{Malformed}!bool {
    if (st.needed == 0) {
        switch (b) {
            0x00...0x7F => {
                dst[w.*] = b;
                w.* += 1;
            },
            0xC2...0xDF => {
                st.needed = 1;
                st.cp = b & 0x1F;
            },
            0xE0...0xEF => {
                if (b == 0xE0) st.lower = 0xA0; // no overlongs
                if (b == 0xED) st.upper = 0x9F; // no surrogates
                st.needed = 2;
                st.cp = b & 0x0F;
            },
            0xF0...0xF4 => {
                if (b == 0xF0) st.lower = 0x90; // no overlongs
                if (b == 0xF4) st.upper = 0x8F; // nothing past U+10FFFF
                st.needed = 3;
                st.cp = b & 0x07;
            },
            else => {
                if (fatal) return error.Malformed;
                @memcpy(dst[w.*..][0..3], replacement);
                w.* += 3;
                return true;
            },
        }
        return false;
    }
    if (b < st.lower or b > st.upper) {
        // The maximal subpart so far is one error; `b` is read again.
        st.* = .{};
        if (fatal) return error.Malformed;
        @memcpy(dst[w.*..][0..3], replacement);
        w.* += 3;
        _ = try utf8Step(st, b, dst, w, fatal);
        return true;
    }
    st.lower = 0x80;
    st.upper = 0xBF;
    st.cp = (st.cp << 6) | (b & 0x3F);
    st.seen += 1;
    if (st.seen != st.needed) return false;
    var tmp: [4]u8 = undefined;
    const n = utf8Encode(st.cp, &tmp);
    @memcpy(dst[w.*..][0..n], tmp[0..n]);
    w.* += n;
    st.* = .{};
    return false;
}

// ── UTF-16 ──────────────────────────────────────────────────────────────────

pub const Endian = enum { le, be };

pub const Utf16State = struct {
    lead_byte: ?u8 = null,
    lead_surrogate: ?u16 = null,

    pub fn pending(self: Utf16State) bool {
        return self.lead_byte != null or self.lead_surrogate != null;
    }
};

/// Byte positions of the low (high) halves of 16 UTF-16 units in 32 bytes.
fn unitBytes(comptime e: Endian, comptime half: enum { low, high }) [16]i32 {
    var m: [16]i32 = undefined;
    const low_first = (e == .le) == (half == .low);
    for (0..16) |k| m[k] = @intCast(2 * k + @intFromBool(!low_first));
    return m;
}

inline fn unitAt(src: []const u8, i: usize, comptime e: Endian) u16 {
    return if (e == .le) @as(u16, src[i]) | (@as(u16, src[i + 1]) << 8) else (@as(u16, src[i]) << 8) | src[i + 1];
}

/// UTF-16 to UTF-8, WHATWG rules: an unpaired surrogate is U+FFFD, a lead
/// followed by a non-trail is U+FFFD and the unit read again, an odd final
/// byte (at `last`) is U+FFFD. Needs room for 7 bytes per step.
pub fn decodeUtf16(comptime e: Endian, state: *Utf16State, src: []const u8, dst: []u8, last: bool, fatal: bool) Progress {
    // A local copy: through the pointer every write to `dst` could alias
    // the state, and the compiler reloaded it per unit.
    var local = state.*;
    defer state.* = local;
    const st = &local;
    var r: usize = 0;
    var w: usize = 0;
    var replaced = false;
    if (st.lead_byte) |lb| {
        // The second byte of a unit started in an earlier call.
        if (r < src.len) {
            if (dst.len - w < 7) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
            st.lead_byte = null;
            const u: u16 = if (e == .le) lb | (@as(u16, src[r]) << 8) else (@as(u16, lb) << 8) | src[r];
            r += 1;
            var w2 = w; // a copy, so `w` itself stays in a register
            const rep = unit16(st, u, dst, &w2, fatal) catch return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
            w = w2;
            if (rep) replaced = true;
        }
    }
    while (r + 1 < src.len) {
        if (dst.len - w < 7) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        const u = unitAt(src, r, e);
        r += 2;
        if (st.lead_surrogate != null or u & 0xF800 == 0xD800) {
            var w2 = w; // a copy, so `w` itself stays in a register
            const rep = unit16(st, u, dst, &w2, fatal) catch return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
            w = w2;
            if (rep) replaced = true;
            continue;
        }
        // A BMP scalar: up to 3 bytes written without branching on the
        // length (the headroom check above covers all three).
        // Arithmetic, not selects: the compiler kept the ASCII/non-ASCII
        // select as a branch, and mixed-script text mispredicts it.
        const extra: u5 = @as(u5, @intFromBool(u >= 0x80)) + @intFromBool(u >= 0x800); // 0, 1, 2
        const lead: u32 = (@as(u32, 0xE0C000) >> (extra * 8)) & 0xFF; // 0x00, 0xC0, 0xE0
        const wide: u32 = u;
        dst[w] = @truncate(lead | (wide >> (extra * 6)));
        dst[w + 1] = @truncate(0x80 | ((wide >> ((extra >> 1) * 6)) & 0x3F));
        dst[w + 2] = @truncate(0x80 | (wide & 0x3F));
        w += 1 + @as(usize, extra);
    }
    if (r < src.len) {
        // One byte left: carried into the next call.
        st.lead_byte = src[r];
        r += 1;
    }
    if (last and st.pending()) {
        if (fatal) return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
        if (dst.len - w < 3) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        st.* = .{};
        @memcpy(dst[w..][0..3], replacement);
        w += 3;
        replaced = true;
    }
    return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
}

/// One UTF-16 unit through the surrogate state machine; at most 7 bytes out
/// (U+FFFD for an unpaired lead, then the unit itself).
fn unit16(st: *Utf16State, unit: u16, dst: []u8, w: *usize, fatal: bool) error{Malformed}!bool {
    var tmp: [4]u8 = undefined;
    if (st.lead_surrogate) |ls| {
        st.lead_surrogate = null;
        if (unit >= 0xDC00 and unit <= 0xDFFF) {
            const cp: u21 = 0x10000 + ((@as(u21, ls) - 0xD800) << 10) + (unit - 0xDC00);
            const n = utf8Encode(cp, &tmp);
            @memcpy(dst[w.*..][0..n], tmp[0..n]);
            w.* += n;
            return false;
        }
        // Unpaired lead: one error, then this unit on its own.
        if (fatal) return error.Malformed;
        @memcpy(dst[w.*..][0..3], replacement);
        w.* += 3;
        _ = try unit16(st, unit, dst, w, fatal);
        return true;
    }
    if (unit >= 0xD800 and unit <= 0xDBFF) {
        st.lead_surrogate = unit;
        return false;
    }
    if (unit >= 0xDC00 and unit <= 0xDFFF) {
        if (fatal) return error.Malformed;
        @memcpy(dst[w.*..][0..3], replacement);
        w.* += 3;
        return true;
    }
    const n = utf8Encode(unit, &tmp);
    @memcpy(dst[w.*..][0..n], tmp[0..n]);
    w.* += n;
    return false;
}

inline fn putUnit(comptime e: Endian, out: *[2]u8, u: u16) void {
    if (e == .le) {
        out[0] = @truncate(u);
        out[1] = @truncate(u >> 8);
    } else {
        out[0] = @truncate(u >> 8);
        out[1] = @truncate(u);
    }
}

/// UTF-8 with replacement (the same WHATWG decoder as `decodeUtf8`) to
/// UTF-16. Needs room for 8 bytes per step.
pub fn utf8ToUtf16(comptime e: Endian, st: *Utf8State, src: []const u8, dst: []u8, last: bool) Progress {
    var r: usize = 0;
    var w: usize = 0;
    var replaced = false;
    var simd_from: usize = 0;
    while (r < src.len) {
        if (st.needed == 0 and r >= simd_from) {
            // A validated stretch, converted without checks; it takes at
            // most two output bytes per input byte.
            const lim = @min(src.len - r, (dst.len - w) / 2);
            const v = utf8_simd.validPrefix(src[r..][0..lim]);
            const n = convertValid(e, src[r..][0..v], dst[w..]);
            r += v;
            w += n;
            if (r == src.len) break;
            simd_from = r + 64;
        }
        if (dst.len - w < 8) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        const b0 = src[r];
        if (st.needed == 0) {
            if (b0 < 0x80) {
                putUnit(e, dst[w..][0..2], b0);
                w += 2;
                r += 1;
                continue;
            }
            const len = wellFormedLen(src, r);
            if (len != 0) {
                const cp = std.unicode.utf8Decode(src[r..][0..len]) catch unreachable;
                w += putCp(e, dst[w..], cp);
                r += len;
                continue;
            }
        }
        // Ill-formed or cut: through the state machine into a scratch
        // buffer (at most U+FFFD plus one more code point), then re-encoded.
        var tmp: [8]u8 = undefined;
        var tw: usize = 0;
        if (utf8Step(st, b0, &tmp, &tw, false) catch unreachable) replaced = true;
        r += 1;
        w += putUtf8(e, dst[w..], tmp[0..tw]);
    }
    if (last and st.needed != 0) {
        if (dst.len - w < 2) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        st.* = .{};
        putUnit(e, dst[w..][0..2], 0xFFFD);
        w += 2;
        replaced = true;
    }
    return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
}

/// Well-formed UTF-8 to UTF-16, no checks: ASCII 16 bytes at a time.
fn convertValid(comptime e: Endian, s: []const u8, out: []u8) usize {
    var i: usize = 0;
    var w: usize = 0;
    const V16 = @Vector(16, u8);
    while (i < s.len) {
        while (i + 16 <= s.len) {
            const v: V16 = s[i..][0..16].*;
            if (@reduce(.Or, v & @as(V16, @splat(0x80))) != 0) break;
            const zero: V16 = @splat(0);
            const wide: V = if (e == .le) std.simd.interlace(.{ v, zero }) else std.simd.interlace(.{ zero, v });
            out[w..][0..32].* = wide;
            i += 16;
            w += 32;
        }
        if (i == s.len) break;
        const b0 = s[i];
        if (b0 < 0x80) {
            putUnit(e, out[w..][0..2], b0);
            i += 1;
            w += 2;
        } else if (b0 < 0xE0) {
            putUnit(e, out[w..][0..2], (@as(u16, b0 & 0x1F) << 6) | (s[i + 1] & 0x3F));
            i += 2;
            w += 2;
        } else if (b0 < 0xF0) {
            putUnit(e, out[w..][0..2], (@as(u16, b0 & 0x0F) << 12) | (@as(u16, s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F));
            i += 3;
            w += 2;
        } else {
            const cp: u21 = (@as(u21, b0 & 0x07) << 18) | (@as(u21, s[i + 1] & 0x3F) << 12) | (@as(u21, s[i + 2] & 0x3F) << 6) | (s[i + 3] & 0x3F);
            w += putCp(e, out[w..], cp);
            i += 4;
        }
    }
    return w;
}

inline fn putCp(comptime e: Endian, out: []u8, cp: u21) usize {
    if (cp >= 0x10000) {
        const v = cp - 0x10000;
        putUnit(e, out[0..2], @intCast(0xD800 + (v >> 10)));
        putUnit(e, out[2..4], @intCast(0xDC00 + (v & 0x3FF)));
        return 4;
    }
    putUnit(e, out[0..2], @intCast(cp));
    return 2;
}

/// Well-formed UTF-8 (a scratch buffer) as UTF-16.
fn putUtf8(comptime e: Endian, out: []u8, s: []const u8) usize {
    var w: usize = 0;
    var view = std.unicode.Utf8View.initUnchecked(s).iterator();
    while (view.nextCodepoint()) |cp| w += putCp(e, out[w..], cp);
    return w;
}

// ── UTF-32 ──────────────────────────────────────────────────────────────────

/// The bytes of a unit started in an earlier call (0..3 of them).
pub const Utf32State = struct {
    buf: [4]u8 = undefined,
    len: u8 = 0,

    pub fn pending(self: Utf32State) bool {
        return self.len != 0;
    }
};

inline fn unit32(src: *const [4]u8, comptime e: Endian) u32 {
    return std.mem.readInt(u32, src, if (e == .le) .little else .big);
}

/// A UTF-32 unit as UTF-8 at `dst[w..]`, or U+FFFD when it is no Unicode
/// scalar value (above U+10FFFF, or a surrogate): one U+FFFD per unit, as
/// Python's `errors="replace"` and the Unicode recommendation. Returns the
/// bytes written (at most 4), 0 for `fatal` and a bad unit.
inline fn putUnit32(u: u32, dst: []u8, w: usize) usize {
    if (u > 0x10FFFF or (u >= 0xD800 and u <= 0xDFFF)) {
        @memcpy(dst[w..][0..3], replacement);
        return 3;
    }
    var tmp: [4]u8 = undefined;
    const n = utf8Encode(@intCast(u), &tmp);
    @memcpy(dst[w..][0..n], tmp[0..n]);
    return n;
}

/// UTF-32 to UTF-8. A malformed unit (a value above U+10FFFF, a surrogate) is
/// one U+FFFD; so is a unit cut by the end of the stream (1 to 3 bytes left
/// at `last`, however many) — the same counts as CPython's `utf-32` decoder
/// with `errors="replace"`. Unlike UTF-16 there is no state beyond the cut
/// unit: a bad unit never swallows its successor. Needs room for 4 bytes per
/// step.
pub fn decodeUtf32(comptime e: Endian, state: *Utf32State, src: []const u8, dst: []u8, last: bool, fatal: bool) Progress {
    // A local copy, as in `decodeUtf16`.
    var local = state.*;
    defer state.* = local;
    const st = &local;
    var r: usize = 0;
    var w: usize = 0;
    var replaced = false;
    if (st.len != 0) {
        // Complete a unit started in an earlier call.
        while (st.len < 4 and r < src.len) {
            st.buf[st.len] = src[r];
            st.len += 1;
            r += 1;
        }
        if (st.len == 4) {
            if (dst.len - w < 4) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
            const u = unit32(st.buf[0..4], e);
            st.len = 0;
            if (u > 0x10FFFF or (u >= 0xD800 and u <= 0xDFFF)) {
                if (fatal) return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
                replaced = true;
            }
            w += putUnit32(u, dst, w);
        }
    }
    while (st.len == 0 and r + 4 <= src.len) {
        if (dst.len - w < 4) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        const u = unit32(src[r..][0..4], e);
        r += 4;
        if (u > 0x10FFFF or (u >= 0xD800 and u <= 0xDFFF)) {
            if (fatal) return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
            replaced = true;
        }
        w += putUnit32(u, dst, w);
    }
    if (st.len == 0 and r < src.len) {
        // Fewer than 4 bytes left: carried into the next call.
        while (r < src.len) : (r += 1) {
            st.buf[st.len] = src[r];
            st.len += 1;
        }
    }
    if (last and st.len != 0 and st.len < 4) {
        if (fatal) return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
        if (dst.len - w < 3) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        st.len = 0;
        @memcpy(dst[w..][0..3], replacement);
        w += 3;
        replaced = true;
    }
    return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
}

inline fn putU32(comptime e: Endian, out: *[4]u8, cp: u32) void {
    std.mem.writeInt(u32, out, cp, if (e == .le) .little else .big);
}

/// UTF-8 with replacement (the same WHATWG decoder as `decodeUtf8`) to
/// UTF-32. Needs room for 8 bytes per step.
pub fn utf8ToUtf32(comptime e: Endian, st: *Utf8State, src: []const u8, dst: []u8, last: bool) Progress {
    var r: usize = 0;
    var w: usize = 0;
    var replaced = false;
    while (r < src.len) {
        if (dst.len - w < 8) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        const b0 = src[r];
        if (st.needed == 0) {
            if (b0 < 0x80) {
                putU32(e, dst[w..][0..4], b0);
                w += 4;
                r += 1;
                continue;
            }
            const len = wellFormedLen(src, r);
            if (len != 0) {
                const cp = std.unicode.utf8Decode(src[r..][0..len]) catch unreachable;
                putU32(e, dst[w..][0..4], cp);
                w += 4;
                r += len;
                continue;
            }
        }
        // Ill-formed or cut: through the state machine into a scratch
        // buffer (at most U+FFFD plus one more code point), then re-encoded.
        var tmp: [8]u8 = undefined;
        var tw: usize = 0;
        if (utf8Step(st, b0, &tmp, &tw, false) catch unreachable) replaced = true;
        r += 1;
        var view = std.unicode.Utf8View.initUnchecked(tmp[0..tw]).iterator();
        while (view.nextCodepoint()) |cp| {
            putU32(e, dst[w..][0..4], cp);
            w += 4;
        }
    }
    if (last and st.needed != 0) {
        if (dst.len - w < 4) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
        st.* = .{};
        putU32(e, dst[w..][0..4], 0xFFFD);
        w += 4;
        replaced = true;
    }
    return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
}
