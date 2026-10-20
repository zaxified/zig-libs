// SPDX-License-Identifier: MIT
//! The WHATWG legacy multi-byte CJK encodings: Shift_JIS, EUC-JP,
//! ISO-2022-JP, EUC-KR, gb18030, GBK and Big5 (Encoding Standard sections
//! 10-13), as a separate API (`encoding.cjk`).
//!
//! ⚠ NOT members of `root.Encoding`. That enum promises that every member is
//! ASCII-compatible (a CSV framer may split cells on the raw bytes), and these
//! are not: Shift_JIS, Big5 and GBK use 0x40..0x7E as trail bytes (0x5C and
//! 0x7C included), and ISO-2022-JP is stateful (an escape sequence changes
//! what the following ASCII-range bytes mean). Treat their bytes as opaque;
//! decode before framing. The tables below are compiled only into a program
//! that references this file (`cjk_tables.zig` is ~290 KiB).
//!
//! The decoders and encoders are the Standard's state machines, step for
//! step, over bytes (decode) and scalar values (encode); the Standard's
//! "restore ... to ioQueue" is a small push-back queue inside the decoder,
//! so a decoder's output is the same at every split of its input.
//!
//! Decoding is lenient (an error is U+FFFD) unless `fatal`. Encoding input
//! is UTF-8 read as the Standard's UTF-8 decode would (one U+FFFD per maximal
//! subpart of an ill-formed sequence); a code point the encoding cannot
//! represent is handled per `core.Unmappable`: `.html_ncr` is the Standard's
//! own "html" error mode (`&#NNNN;`), `.fatal` its "fatal" mode.
//!
//! Provenance: the algorithms follow the Encoding Standard (CC-BY 4.0 / BSD-3,
//! see ../NOTICE); the code is original work of the zig-libs authors (MIT).

const std = @import("std");
const core = @import("core.zig");
const sb = @import("sb_tables.zig");
const t = @import("cjk_tables.zig");

pub const Progress = core.Progress;
pub const EncodeProgress = core.EncodeProgress;
pub const Unmappable = core.Unmappable;

/// The seven encodings of the Standard's CJK sections.
pub const Cjk = enum {
    shift_jis,
    euc_jp,
    iso_2022_jp,
    euc_kr,
    gb18030,
    gbk,
    big5,

    /// The Standard's name (`Shift_JIS`, `EUC-JP`, `ISO-2022-JP`, `EUC-KR`,
    /// `gb18030`, `GBK`, `Big5`).
    pub fn whatwgName(self: Cjk) []const u8 {
        return switch (self) {
            .shift_jis => "Shift_JIS",
            .euc_jp => "EUC-JP",
            .iso_2022_jp => "ISO-2022-JP",
            .euc_kr => "EUC-KR",
            .gb18030 => "gb18030",
            .gbk => "GBK",
            .big5 => "Big5",
        };
    }

    /// The WHATWG "get an encoding" lookup restricted to these seven (label
    /// trimmed of ASCII whitespace, ASCII case-insensitive); null for any
    /// other label, including every `root.Encoding` one.
    pub fn fromLabel(raw: []const u8) ?Cjk {
        const s = std.mem.trim(u8, raw, " \t\n\r\x0c");
        var buf: [64]u8 = undefined;
        if (s.len > buf.len) return null;
        const low = std.ascii.lowerString(&buf, s);
        const target = sb.lookupLabel(low) orelse return null;
        const name = switch (target) {
            .unsupported => |n| n,
            else => return null,
        };
        inline for (comptime std.enums.values(Cjk)) |c| {
            if (std.mem.eql(u8, name, c.whatwgName())) return c;
        }
        return null;
    }
};

// ── index access ────────────────────────────────────────────────────────────

const none: u16 = 0xFFFF;

inline fn denseCp(dec: []const u16, base: u32, ptr: u32) ?u21 {
    if (ptr < base) return null;
    const i = ptr - base;
    if (i >= dec.len) return null;
    const v = dec[i];
    return if (v == none) null else v;
}

inline fn j8Cp(ptr: u32) ?u21 {
    return denseCp(&t.jis0208_dec, 0, ptr);
}
inline fn j12Cp(ptr: u32) ?u21 {
    return denseCp(&t.jis0212_dec, t.jis0212_base, ptr);
}
inline fn ekCp(ptr: u32) ?u21 {
    return denseCp(&t.euckr_dec, 0, ptr);
}
inline fn gbCp(ptr: u32) ?u21 {
    return denseCp(&t.gb_dec, 0, ptr);
}
inline fn b5Cp(ptr: u32) ?u21 {
    if (ptr < t.big5_base) return null;
    const i = ptr - t.big5_base;
    if (i >= t.big5_dec.len) return null;
    const v = t.big5_dec[i];
    const sip: u21 = (t.big5_sip[i >> 3] >> @as(u3, @intCast(i & 7))) & 1;
    if (v == none and sip == 0) return null;
    return v | (sip << 17);
}

// The `*_enc` tables hold pointers sorted by the code point they decode to;
// every such pointer has an entry, so these never see a hole.
fn j8Of(ptr: u16) u21 {
    return j8Cp(ptr).?;
}
fn ekOf(ptr: u16) u21 {
    return ekCp(ptr).?;
}
fn gbOf(ptr: u16) u21 {
    return gbCp(ptr).?;
}
fn b5Of(ptr: u16) u21 {
    return b5Cp(ptr).?;
}

fn search(comptime cpOf: fn (u16) u21, tab: []const u16, cp: u21) ?u16 {
    var lo: usize = 0;
    var hi: usize = tab.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const c = cpOf(tab[mid]);
        if (c == cp) return tab[mid];
        if (c < cp) lo = mid + 1 else hi = mid;
    }
    return null;
}

/// index jis0208 pointer for `cp` (the first one).
fn j8Ptr(cp: u21) ?u16 {
    return search(j8Of, &t.jis0208_enc, cp);
}

/// "index Shift_JIS pointer": index jis0208 without pointers 8272..8835.
fn sjisPtr(cp: u21) ?u16 {
    const p = j8Ptr(cp) orelse return null;
    if (p < 8272 or p > 8835) return p;
    return search(j8Of, &t.jis0208_sjis_fix, cp);
}

/// "index gb18030 ranges code point" for a four-byte pointer.
fn gbRangesCp(ptr: u32) ?u21 {
    if ((ptr > 39419 and ptr < 189000) or ptr > 1237575) return null;
    if (ptr == 7457) return 0xE7C7;
    // The last range whose pointer is <= ptr.
    var lo: usize = 0;
    var hi: usize = t.gb_ranges_ptr.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (t.gb_ranges_ptr[mid] <= ptr) lo = mid + 1 else hi = mid;
    }
    const i = lo - 1;
    return @intCast(t.gb_ranges_cp[i] + ptr - t.gb_ranges_ptr[i]);
}

/// "index gb18030 ranges pointer" for a code point.
fn gbRangesPtr(cp: u21) u32 {
    if (cp == 0xE7C7) return 7457;
    var lo: usize = 0;
    var hi: usize = t.gb_ranges_cp.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (t.gb_ranges_cp[mid] <= cp) lo = mid + 1 else hi = mid;
    }
    const i = lo - 1;
    return t.gb_ranges_ptr[i] + cp - t.gb_ranges_cp[i];
}

/// The gb18030 encoder's side table (Standard 10.2.2): the GB18030-2022
/// private-use code points, kept two bytes long as in GB18030-2005.
const gb_side = [_]struct { cp: u21, b1: u8, b2: u8 }{
    .{ .cp = 0xE78D, .b1 = 0xA6, .b2 = 0xD9 }, .{ .cp = 0xE78E, .b1 = 0xA6, .b2 = 0xDA },
    .{ .cp = 0xE78F, .b1 = 0xA6, .b2 = 0xDB }, .{ .cp = 0xE790, .b1 = 0xA6, .b2 = 0xDC },
    .{ .cp = 0xE791, .b1 = 0xA6, .b2 = 0xDD }, .{ .cp = 0xE792, .b1 = 0xA6, .b2 = 0xDE },
    .{ .cp = 0xE793, .b1 = 0xA6, .b2 = 0xDF }, .{ .cp = 0xE794, .b1 = 0xA6, .b2 = 0xEC },
    .{ .cp = 0xE795, .b1 = 0xA6, .b2 = 0xED }, .{ .cp = 0xE796, .b1 = 0xA6, .b2 = 0xF3 },
    .{ .cp = 0xE81E, .b1 = 0xFE, .b2 = 0x59 }, .{ .cp = 0xE826, .b1 = 0xFE, .b2 = 0x61 },
    .{ .cp = 0xE82B, .b1 = 0xFE, .b2 = 0x66 }, .{ .cp = 0xE82C, .b1 = 0xFE, .b2 = 0x67 },
    .{ .cp = 0xE832, .b1 = 0xFE, .b2 = 0x6D }, .{ .cp = 0xE843, .b1 = 0xFE, .b2 = 0x7E },
    .{ .cp = 0xE854, .b1 = 0xFE, .b2 = 0x90 }, .{ .cp = 0xE864, .b1 = 0xFE, .b2 = 0xA0 },
};

// ── decoder ─────────────────────────────────────────────────────────────────

/// Output room a decoder needs before each step (one scalar value: up to 4
/// bytes). With less, `decodeInto` returns `.output_full` without progress.
pub const decoder_headroom = 4;

const IsoState = enum(u8) { ascii, roman, katakana, leading, trailing, escape_start, escape };

const Step = union(enum) {
    /// No output yet (a lead byte, an escape).
    cont,
    /// An error: U+FFFD, or `.malformed` in fatal mode.
    err,
    /// End of the stream.
    finished,
    cp: u21,
    /// Big5's four pointers that decode to two code points.
    cp2: [2]u21,
};

pub const Decoder = struct {
    enc: Cjk,
    fatal: bool,
    failed: bool = false,
    // The Standard's per-decoder state. `lead` is "first"/"leading" of every
    // decoder; `second` and `third` are gb18030's.
    lead: u8 = 0,
    second: u8 = 0,
    third: u8 = 0,
    jis0212: bool = false,
    iso_state: IsoState = .ascii,
    iso_out: IsoState = .ascii,
    iso_output: bool = false,
    /// The Standard's "restore": bytes to read again before the input.
    q: [4]u8 = undefined,
    qn: u8 = 0,

    pub const Options = struct {
        /// `.malformed` / `error.Malformed` instead of U+FFFD (WHATWG `fatal`).
        fatal: bool = false,
    };
    pub const Error = std.mem.Allocator.Error || error{Malformed};

    pub fn init(enc: Cjk, opts: Options) Decoder {
        return .{ .enc = enc, .fatal = opts.fatal };
    }

    /// An output size that always takes all of `n` input bytes (plus the
    /// state carried in) in one `decodeInto` call: every byte yields at most
    /// one U+FFFD (3 bytes), up to 3 more bytes are carried in the state, and
    /// the per-step headroom.
    pub fn maxUtf8Len(self: *const Decoder, n: usize) usize {
        _ = self;
        return (n +| 4) *| 3 +| decoder_headroom;
    }

    fn restore(self: *Decoder, bytes: []const u8) void {
        std.debug.assert(self.qn + bytes.len <= self.q.len);
        var i: usize = self.qn;
        while (i > 0) {
            i -= 1;
            self.q[i + bytes.len] = self.q[i];
        }
        @memcpy(self.q[0..bytes.len], bytes);
        self.qn += @intCast(bytes.len);
    }

    fn popq(self: *Decoder) u8 {
        const b = self.q[0];
        self.qn -= 1;
        var i: usize = 0;
        while (i < self.qn) : (i += 1) self.q[i] = self.q[i + 1];
        return b;
    }

    /// Decode `src` into `dst`. `last`: the end of `src` is the end of the
    /// stream (a pending sequence is flushed as U+FFFD, or `.malformed`).
    /// Bytes are "read" as soon as they enter the decoder's state, so
    /// `.input_empty` always has `read == src.len`. On `.output_full`, call
    /// again with `src[read..]` and more room (at least `decoder_headroom`).
    /// `.malformed` (fatal only): `read` includes the byte that completed the
    /// error and the decoder has failed. After a `last` call that returned
    /// `.input_empty` the decoder is reset for reuse.
    pub fn decodeInto(self: *Decoder, src: []const u8, dst: []u8, last: bool) Progress {
        if (self.failed) return .{ .status = .malformed, .read = 0, .written = 0 };
        var r: usize = 0;
        var w: usize = 0;
        var replaced = false;
        while (true) {
            if (self.qn == 0 and self.lead == 0 and self.enc != .iso_2022_jp) {
                // Clean state: ASCII passes through (Shift_JIS' 0x5C and 0x7E
                // included: the Standard maps them to themselves).
                const ascii_run = core.asciiPrefix(src[r..]);
                const n = @min(ascii_run, dst.len - w);
                @memcpy(dst[w..][0..n], src[r..][0..n]);
                r += n;
                w += n;
            }
            const have = self.qn > 0 or r < src.len;
            if (!have and !last) break;
            if (dst.len - w < decoder_headroom) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
            var res: Step = undefined;
            if (self.qn > 0) {
                res = self.stepByte(self.popq());
            } else if (r < src.len) {
                const b = src[r];
                r += 1;
                res = self.stepByte(b);
            } else {
                res = self.stepEnd();
            }
            switch (res) {
                .cont => {},
                .finished => break,
                .err => {
                    if (self.fatal) {
                        self.failed = true;
                        return .{ .status = .malformed, .read = r, .written = w, .replaced = replaced };
                    }
                    @memcpy(dst[w..][0..3], core.replacement);
                    w += 3;
                    replaced = true;
                },
                .cp => |c| w += putCp(dst[w..], c),
                .cp2 => |cs| {
                    w += putCp(dst[w..], cs[0]);
                    w += putCp(dst[w..], cs[1]);
                },
            }
        }
        if (last) self.* = .init(self.enc, .{ .fatal = self.fatal });
        return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
    }

    /// Decode `chunk`, appending UTF-8 to `out`.
    pub fn feed(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8) Error!void {
        return self.run(alloc, out, chunk, false);
    }

    /// End of stream: an unfinished sequence is one more U+FFFD (or
    /// `error.Malformed`). The decoder is reset and may be reused.
    pub fn finish(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        return self.run(alloc, out, "", true);
    }

    fn run(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8, last: bool) Error!void {
        var r: usize = 0;
        while (true) {
            try out.ensureUnusedCapacity(alloc, self.maxUtf8Len(chunk.len - r));
            const p = self.decodeInto(chunk[r..], out.unusedCapacitySlice(), last);
            out.items.len += p.written;
            r += p.read;
            switch (p.status) {
                .input_empty => return,
                .output_full => continue,
                .malformed => return error.Malformed,
            }
        }
    }

    fn stepByte(self: *Decoder, b: u8) Step {
        return switch (self.enc) {
            .shift_jis => self.stepSjis(b),
            .euc_jp => self.stepEucJp(b),
            .iso_2022_jp => self.stepIso(b),
            .euc_kr => self.stepEucKr(b),
            .gb18030, .gbk => self.stepGb(b), // GBK's decoder is gb18030's
            .big5 => self.stepBig5(b),
        };
    }

    /// The end-of-queue item.
    fn stepEnd(self: *Decoder) Step {
        switch (self.enc) {
            .iso_2022_jp => switch (self.iso_state) {
                .ascii, .roman, .katakana, .leading => return .finished,
                .trailing => {
                    self.iso_state = .leading;
                    return .err;
                },
                .escape_start => {
                    self.iso_output = false;
                    self.iso_state = self.iso_out;
                    return .err;
                },
                .escape => {
                    const leading = self.lead;
                    self.lead = 0;
                    self.restore(&.{leading});
                    self.iso_output = false;
                    self.iso_state = self.iso_out;
                    return .err;
                },
            },
            .gb18030, .gbk => {
                if (self.lead == 0 and self.second == 0 and self.third == 0) return .finished;
                self.lead = 0;
                self.second = 0;
                self.third = 0;
                return .err;
            },
            else => {
                if (self.lead == 0) return .finished;
                self.lead = 0;
                self.jis0212 = false;
                return .err;
            },
        }
    }

    fn stepGb(self: *Decoder, b: u8) Step {
        if (self.third != 0) {
            if (b < 0x30 or b > 0x39) {
                const second = self.second;
                const third = self.third;
                self.lead = 0;
                self.second = 0;
                self.third = 0;
                self.restore(&.{ second, third, b });
                return .err;
            }
            const ptr: u32 = (@as(u32, self.lead) - 0x81) * (10 * 126 * 10) +
                (@as(u32, self.second) - 0x30) * (10 * 126) +
                (@as(u32, self.third) - 0x81) * 10 + b - 0x30;
            self.lead = 0;
            self.second = 0;
            self.third = 0;
            const cp = gbRangesCp(ptr) orelse return .err;
            return .{ .cp = cp };
        }
        if (self.second != 0) {
            if (b >= 0x81 and b <= 0xFE) {
                self.third = b;
                return .cont;
            }
            const second = self.second;
            self.lead = 0;
            self.second = 0;
            self.restore(&.{ second, b });
            return .err;
        }
        if (self.lead != 0) {
            if (b >= 0x30 and b <= 0x39) {
                self.second = b;
                return .cont;
            }
            const leading = self.lead;
            self.lead = 0;
            const offset: u32 = if (b < 0x7F) 0x40 else 0x41;
            if ((b >= 0x40 and b <= 0x7E) or (b >= 0x80 and b <= 0xFE)) {
                if (gbCp((@as(u32, leading) - 0x81) * 190 + (b - offset))) |cp| return .{ .cp = cp };
            }
            if (b < 0x80) self.restore(&.{b});
            return .err;
        }
        if (b < 0x80) return .{ .cp = b };
        if (b == 0x80) return .{ .cp = 0x20AC };
        if (b >= 0x81 and b <= 0xFE) {
            self.lead = b;
            return .cont;
        }
        return .err;
    }

    fn stepBig5(self: *Decoder, b: u8) Step {
        if (self.lead != 0) {
            const leading = self.lead;
            self.lead = 0;
            const offset: u32 = if (b < 0x7F) 0x40 else 0x62;
            if ((b >= 0x40 and b <= 0x7E) or (b >= 0xA1 and b <= 0xFE)) {
                const ptr: u32 = (@as(u32, leading) - 0x81) * 157 + (b - offset);
                switch (ptr) {
                    1133 => return .{ .cp2 = .{ 0x00CA, 0x0304 } },
                    1135 => return .{ .cp2 = .{ 0x00CA, 0x030C } },
                    1164 => return .{ .cp2 = .{ 0x00EA, 0x0304 } },
                    1166 => return .{ .cp2 = .{ 0x00EA, 0x030C } },
                    else => {},
                }
                if (b5Cp(ptr)) |cp| return .{ .cp = cp };
            }
            if (b < 0x80) self.restore(&.{b});
            return .err;
        }
        if (b < 0x80) return .{ .cp = b };
        if (b >= 0x81 and b <= 0xFE) {
            self.lead = b;
            return .cont;
        }
        return .err;
    }

    fn stepEucKr(self: *Decoder, b: u8) Step {
        if (self.lead != 0) {
            const leading = self.lead;
            self.lead = 0;
            if (b >= 0x41 and b <= 0xFE) {
                if (ekCp((@as(u32, leading) - 0x81) * 190 + (b - 0x41))) |cp| return .{ .cp = cp };
            }
            if (b < 0x80) self.restore(&.{b});
            return .err;
        }
        if (b < 0x80) return .{ .cp = b };
        if (b >= 0x81 and b <= 0xFE) {
            self.lead = b;
            return .cont;
        }
        return .err;
    }

    fn stepEucJp(self: *Decoder, b: u8) Step {
        if (self.lead == 0x8E and b >= 0xA1 and b <= 0xDF) {
            self.lead = 0;
            return .{ .cp = 0xFF61 - 0xA1 + @as(u21, b) };
        }
        if (self.lead == 0x8F and b >= 0xA1 and b <= 0xFE) {
            self.jis0212 = true;
            self.lead = b;
            return .cont;
        }
        if (self.lead != 0) {
            const leading = self.lead;
            self.lead = 0;
            var cp: ?u21 = null;
            if (leading >= 0xA1 and leading <= 0xFE and b >= 0xA1 and b <= 0xFE) {
                const ptr: u32 = (@as(u32, leading) - 0xA1) * 94 + b - 0xA1;
                cp = if (self.jis0212) j12Cp(ptr) else j8Cp(ptr);
            }
            self.jis0212 = false;
            if (cp) |c| return .{ .cp = c };
            if (b < 0x80) self.restore(&.{b});
            return .err;
        }
        if (b < 0x80) return .{ .cp = b };
        if (b == 0x8E or b == 0x8F or (b >= 0xA1 and b <= 0xFE)) {
            self.lead = b;
            return .cont;
        }
        return .err;
    }

    fn stepSjis(self: *Decoder, b: u8) Step {
        if (self.lead != 0) {
            const leading = self.lead;
            self.lead = 0;
            var pointer: ?u32 = null;
            const offset: u32 = if (b < 0x7F) 0x40 else 0x41;
            const leading_offset: u32 = if (leading < 0xA0) 0x81 else 0xC1;
            if ((b >= 0x40 and b <= 0x7E) or (b >= 0x80 and b <= 0xFC)) {
                pointer = (@as(u32, leading) - leading_offset) * 188 + b - offset;
            }
            if (pointer) |p| {
                // EUDC, "interoperable legacy from Windows".
                if (p >= 8836 and p <= 10715) return .{ .cp = 0xE000 - 8836 + @as(u21, @intCast(p)) };
                if (j8Cp(p)) |cp| return .{ .cp = cp };
            }
            if (b < 0x80) self.restore(&.{b});
            return .err;
        }
        if (b < 0x80 or b == 0x80) return .{ .cp = b };
        if (b >= 0xA1 and b <= 0xDF) return .{ .cp = 0xFF61 - 0xA1 + @as(u21, b) };
        if ((b >= 0x81 and b <= 0x9F) or (b >= 0xE0 and b <= 0xFC)) {
            self.lead = b;
            return .cont;
        }
        return .err;
    }

    fn stepIso(self: *Decoder, b: u8) Step {
        switch (self.iso_state) {
            .ascii => {
                if (b == 0x1B) {
                    self.iso_state = .escape_start;
                    return .cont;
                }
                self.iso_output = false;
                if (b <= 0x7F and b != 0x0E and b != 0x0F) return .{ .cp = b };
                return .err;
            },
            .roman => {
                if (b == 0x1B) {
                    self.iso_state = .escape_start;
                    return .cont;
                }
                self.iso_output = false;
                if (b == 0x5C) return .{ .cp = 0x00A5 };
                if (b == 0x7E) return .{ .cp = 0x203E };
                if (b <= 0x7F and b != 0x0E and b != 0x0F) return .{ .cp = b };
                return .err;
            },
            .katakana => {
                if (b == 0x1B) {
                    self.iso_state = .escape_start;
                    return .cont;
                }
                self.iso_output = false;
                if (b >= 0x21 and b <= 0x5F) return .{ .cp = 0xFF61 - 0x21 + @as(u21, b) };
                return .err;
            },
            .leading => {
                if (b == 0x1B) {
                    self.iso_state = .escape_start;
                    return .cont;
                }
                self.iso_output = false;
                if (b >= 0x21 and b <= 0x7E) {
                    self.lead = b;
                    self.iso_state = .trailing;
                    return .cont;
                }
                return .err;
            },
            .trailing => {
                if (b == 0x1B) {
                    self.iso_state = .escape_start;
                    return .err;
                }
                self.iso_state = .leading;
                if (b >= 0x21 and b <= 0x7E) {
                    const ptr: u32 = (@as(u32, self.lead) - 0x21) * 94 + b - 0x21;
                    return if (j8Cp(ptr)) |cp| .{ .cp = cp } else .err;
                }
                return .err;
            },
            .escape_start => {
                if (b == 0x24 or b == 0x28) {
                    self.lead = b;
                    self.iso_state = .escape;
                    return .cont;
                }
                self.restore(&.{b});
                self.iso_output = false;
                self.iso_state = self.iso_out;
                return .err;
            },
            .escape => {
                const leading = self.lead;
                self.lead = 0;
                var state: ?IsoState = null;
                if (leading == 0x28 and b == 0x42) state = .ascii;
                if (leading == 0x28 and b == 0x4A) state = .roman;
                if (leading == 0x28 and b == 0x49) state = .katakana;
                if (leading == 0x24 and (b == 0x40 or b == 0x42)) state = .leading;
                if (state) |s| {
                    self.iso_state = s;
                    self.iso_out = s;
                    const output = self.iso_output;
                    self.iso_output = true;
                    return if (!output) .cont else .err;
                }
                self.restore(&.{ leading, b });
                self.iso_output = false;
                self.iso_state = self.iso_out;
                return .err;
            },
        }
    }
};

fn putCp(dst: []u8, cp: u21) usize {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch {
        // Unreachable for the Standard's indexes (no surrogate is mapped;
        // anchored in cjk_test.zig), but never write garbage.
        @memcpy(dst[0..3], core.replacement);
        return 3;
    };
    @memcpy(dst[0..n], buf[0..n]);
    return n;
}

// ── encoder ─────────────────────────────────────────────────────────────────

/// Output room an encoder needs before each code point: an escape sequence
/// (3), a two-byte character (2) and, in `.html_ncr` mode, an `&#1114111;`
/// (10) never exceed 16 together. With less, `encodeInto` returns
/// `.output_full` without progress.
pub const encoder_headroom = 16;

const IsoEncState = enum { ascii, roman, jis0208 };

pub const Encoder = struct {
    enc: Cjk,
    unmappable: Unmappable,
    /// The start of a UTF-8 sequence cut by the end of the previous chunk.
    pending: [3]u8 = undefined,
    pending_len: u8 = 0,
    /// ISO-2022-JP encoder state.
    iso: IsoEncState = .ascii,

    pub const Options = struct {
        unmappable: Unmappable = .question_mark,
    };
    pub const Error = std.mem.Allocator.Error || error{Unmappable};

    pub fn init(enc: Cjk, opts: Options) Encoder {
        return .{ .enc = enc, .unmappable = opts.unmappable };
    }

    /// An output size that always takes all of `n` input bytes in one
    /// `encodeInto` call (the carried bytes, a closing escape and the
    /// per-step headroom included).
    pub fn maxEncodedLen(self: *const Encoder, n: usize) usize {
        const per: usize = if (self.unmappable == .html_ncr) 13 else 5;
        return (n +| 3) *| per +| encoder_headroom;
    }

    /// Encode `src` (UTF-8) into `dst`. `last`: the end of `src` is the end
    /// of the stream (a cut sequence becomes U+FFFD; ISO-2022-JP returns to
    /// ASCII). On `.output_full`, call again with `src[read..]` and room (at
    /// least `encoder_headroom`).
    ///
    /// `.unmappable` (`.fatal` mode): `code_point` is the character, and —
    /// unlike `core.encodeSingleByte` — `read` is PAST it (its bytes may have
    /// been carried from an earlier call, so they cannot be given back); the
    /// caller continues with `src[read..]` after deciding what to write. An
    /// ISO-2022-JP encoder has already written its return-to-ASCII escape.
    /// After a `last` call that returned `.input_empty` the encoder is reset.
    pub fn encodeInto(self: *Encoder, src: []const u8, dst: []u8, last: bool) EncodeProgress {
        var r: usize = 0;
        var w: usize = 0;
        var replaced = false;
        while (true) {
            // ASCII that no state can change the meaning of.
            if (self.pending_len == 0) {
                while (r < src.len and w < dst.len and src[r] < 0x80 and self.asciiDirect(src[r])) {
                    dst[w] = src[r];
                    w += 1;
                    r += 1;
                }
            }
            if (self.pending_len == 0 and r == src.len) break;
            if (dst.len - w < encoder_headroom) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
            // The next scalar value.
            var cp: u21 = undefined;
            if (self.pending_len > 0) {
                const pl: usize = self.pending_len;
                var tmp: [6]u8 = undefined;
                @memcpy(tmp[0..pl], self.pending[0..pl]);
                const k = @min(src.len - r, 3);
                @memcpy(tmp[pl..][0..k], src[r..][0..k]);
                switch (nextScalar(tmp[0 .. pl + k], last and k == src.len - r)) {
                    .more => {
                        @memcpy(self.pending[0 .. pl + k], tmp[0 .. pl + k]);
                        self.pending_len = @intCast(pl + k);
                        r += k;
                        break;
                    },
                    .scalar => |s| {
                        // A sequence that began in `pending` consumes all of it.
                        std.debug.assert(s.len >= pl);
                        self.pending_len = 0;
                        r += s.len - pl;
                        cp = s.cp;
                    },
                }
            } else {
                switch (nextScalar(src[r..], last)) {
                    .more => {
                        const left = src.len - r;
                        @memcpy(self.pending[0..left], src[r..]);
                        self.pending_len = @intCast(left);
                        r = src.len;
                        break;
                    },
                    .scalar => |s| {
                        r += s.len;
                        cp = s.cp;
                    },
                }
            }
            switch (self.put(cp, dst[w..])) {
                .written => |n| w += n,
                .unmappable => |un| {
                    w += un.written;
                    switch (self.unmappable) {
                        .question_mark => {
                            dst[w] = '?';
                            w += 1;
                            replaced = true;
                        },
                        .ignore => replaced = true,
                        .html_ncr => {
                            const out = std.fmt.bufPrint(dst[w..], "&#{d};", .{un.cp}) catch unreachable;
                            w += out.len;
                            replaced = true;
                        },
                        .fatal => return .{ .status = .unmappable, .read = r, .written = w, .replaced = replaced, .code_point = un.cp },
                    }
                },
            }
        }
        if (last and self.pending_len == 0) {
            if (self.enc == .iso_2022_jp and self.iso != .ascii) {
                if (dst.len - w < 3) return .{ .status = .output_full, .read = r, .written = w, .replaced = replaced };
                @memcpy(dst[w..][0..3], "\x1b(B");
                w += 3;
            }
            self.* = .init(self.enc, .{ .unmappable = self.unmappable });
        }
        return .{ .status = .input_empty, .read = r, .written = w, .replaced = replaced };
    }

    /// Encode `chunk`, appending to `out`. `error.Unmappable` only in
    /// `.fatal` mode (the output so far is kept).
    pub fn feed(self: *Encoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8) Error!void {
        return self.run(alloc, out, chunk, false);
    }

    /// End of stream: a cut sequence becomes one more U+FFFD, ISO-2022-JP
    /// returns to ASCII. The encoder is reset and may be reused.
    pub fn finish(self: *Encoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        return self.run(alloc, out, "", true);
    }

    fn run(self: *Encoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8, last: bool) Error!void {
        var r: usize = 0;
        while (true) {
            try out.ensureUnusedCapacity(alloc, self.maxEncodedLen(chunk.len - r));
            const p = self.encodeInto(chunk[r..], out.unusedCapacitySlice(), last);
            out.items.len += p.written;
            r += p.read;
            switch (p.status) {
                .input_empty => return,
                .output_full => continue,
                .unmappable => return error.Unmappable,
            }
        }
    }

    /// Is `b` (ASCII) written as itself in the current state?
    inline fn asciiDirect(self: *const Encoder, b: u8) bool {
        if (self.enc != .iso_2022_jp) return true;
        return self.iso == .ascii and b != 0x0E and b != 0x0F and b != 0x1B;
    }

    const Put = union(enum) {
        written: usize,
        /// `written` bytes (an escape) went out before the error.
        unmappable: struct { cp: u21, written: usize },
    };

    fn put(self: *Encoder, cp: u21, dst: []u8) Put {
        switch (self.enc) {
            .shift_jis => return putSjis(cp, dst),
            .euc_jp => return putEucJp(cp, dst),
            .iso_2022_jp => return self.putIso(cp, dst),
            .euc_kr => {
                if (cp < 0x80) return ascii(cp, dst);
                const ptr = search(ekOf, &t.euckr_enc, cp) orelse return unmap(cp);
                dst[0] = @intCast(ptr / 190 + 0x81);
                dst[1] = @intCast(ptr % 190 + 0x41);
                return .{ .written = 2 };
            },
            .gb18030, .gbk => return putGb(cp, dst, self.enc == .gbk),
            .big5 => {
                if (cp < 0x80) return ascii(cp, dst);
                const ptr = search(b5Of, &t.big5_enc, cp) orelse return unmap(cp);
                dst[0] = @intCast(ptr / 157 + 0x81);
                const trailing = ptr % 157;
                dst[1] = @intCast(trailing + @as(u16, if (trailing < 0x3F) 0x40 else 0x62));
                return .{ .written = 2 };
            },
        }
    }

    fn putIso(self: *Encoder, cp0: u21, dst: []u8) Put {
        var cp = cp0;
        var w: usize = 0;
        while (true) {
            // "state is ASCII or Roman, and codePoint is U+000E, U+000F or
            // U+001B: error with U+FFFD" (never the code point itself). Checked
            // on every pass: a control code read again after the escape that
            // leaves the jis0208 state meets the ASCII state here.
            if (self.iso != .jis0208 and (cp == 0x0E or cp == 0x0F or cp == 0x1B)) {
                return .{ .unmappable = .{ .cp = 0xFFFD, .written = w } };
            }
            if (self.iso == .ascii and cp < 0x80) {
                dst[w] = @intCast(cp);
                return .{ .written = w + 1 };
            }
            if (self.iso == .roman and ((cp < 0x80 and cp != 0x5C and cp != 0x7E) or cp == 0x00A5 or cp == 0x203E)) {
                dst[w] = if (cp == 0x00A5) 0x5C else if (cp == 0x203E) 0x7E else @intCast(cp);
                return .{ .written = w + 1 };
            }
            if (cp < 0x80) {
                // Restore the code point, return to ASCII.
                @memcpy(dst[w..][0..3], "\x1b(B");
                w += 3;
                self.iso = .ascii;
                continue;
            }
            if ((cp == 0x00A5 or cp == 0x203E) and self.iso != .roman) {
                @memcpy(dst[w..][0..3], "\x1b(J");
                w += 3;
                self.iso = .roman;
                continue;
            }
            if (cp == 0x2212) cp = 0xFF0D;
            if (cp >= 0xFF61 and cp <= 0xFF9F) cp = t.katakana_dec[cp - 0xFF61];
            const ptr = j8Ptr(cp) orelse {
                if (self.iso == .jis0208) {
                    @memcpy(dst[w..][0..3], "\x1b(B");
                    w += 3;
                    self.iso = .ascii;
                }
                // The error names the original code point (the modified one
                // is only ever different when it is mappable).
                return .{ .unmappable = .{ .cp = cp0, .written = w } };
            };
            if (self.iso != .jis0208) {
                @memcpy(dst[w..][0..3], "\x1b$B");
                w += 3;
                self.iso = .jis0208;
            }
            dst[w] = @intCast(ptr / 94 + 0x21);
            dst[w + 1] = @intCast(ptr % 94 + 0x21);
            return .{ .written = w + 2 };
        }
    }
};

inline fn ascii(cp: u21, dst: []u8) Encoder.Put {
    dst[0] = @intCast(cp);
    return .{ .written = 1 };
}

inline fn unmap(cp: u21) Encoder.Put {
    return .{ .unmappable = .{ .cp = cp, .written = 0 } };
}

fn putSjis(cp0: u21, dst: []u8) Encoder.Put {
    var cp = cp0;
    if (cp < 0x81) return ascii(cp, dst); // ASCII or U+0080
    if (cp == 0x00A5) return ascii(0x5C, dst);
    if (cp == 0x203E) return ascii(0x7E, dst);
    if (cp >= 0xFF61 and cp <= 0xFF9F) return ascii(cp - 0xFF61 + 0xA1, dst);
    if (cp == 0x2212) cp = 0xFF0D;
    const ptr = sjisPtr(cp) orelse return unmap(cp0);
    const leading = ptr / 188;
    dst[0] = @intCast(leading + @as(u16, if (leading < 0x1F) 0x81 else 0xC1));
    const trailing = ptr % 188;
    dst[1] = @intCast(trailing + @as(u16, if (trailing < 0x3F) 0x40 else 0x41));
    return .{ .written = 2 };
}

fn putEucJp(cp0: u21, dst: []u8) Encoder.Put {
    var cp = cp0;
    if (cp < 0x80) return ascii(cp, dst);
    if (cp == 0x00A5) return ascii(0x5C, dst);
    if (cp == 0x203E) return ascii(0x7E, dst);
    if (cp >= 0xFF61 and cp <= 0xFF9F) {
        dst[0] = 0x8E;
        dst[1] = @intCast(cp - 0xFF61 + 0xA1);
        return .{ .written = 2 };
    }
    if (cp == 0x2212) cp = 0xFF0D;
    const ptr = j8Ptr(cp) orelse return unmap(cp0);
    dst[0] = @intCast(ptr / 94 + 0xA1);
    dst[1] = @intCast(ptr % 94 + 0xA1);
    return .{ .written = 2 };
}

fn putGb(cp: u21, dst: []u8, is_gbk: bool) Encoder.Put {
    if (cp < 0x80) return ascii(cp, dst);
    // 0xA3 0xA0 decodes to U+3000, so U+E5E5 cannot round-trip.
    if (cp == 0xE5E5) return unmap(cp);
    if (is_gbk and cp == 0x20AC) return ascii(0x80, dst);
    for (gb_side) |s| {
        if (s.cp == cp) {
            dst[0] = s.b1;
            dst[1] = s.b2;
            return .{ .written = 2 };
        }
    }
    if (search(gbOf, &t.gb_enc, cp)) |ptr| {
        dst[0] = @intCast(ptr / 190 + 0x81);
        const trailing = ptr % 190;
        dst[1] = @intCast(trailing + @as(u16, if (trailing < 0x3F) 0x40 else 0x41));
        return .{ .written = 2 };
    }
    if (is_gbk) return unmap(cp);
    var p = gbRangesPtr(cp);
    dst[0] = @intCast(p / (10 * 126 * 10) + 0x81);
    p %= 10 * 126 * 10;
    dst[1] = @intCast(p / (10 * 126) + 0x30);
    p %= 10 * 126;
    dst[2] = @intCast(p / 10 + 0x81);
    dst[3] = @intCast(p % 10 + 0x30);
    return .{ .written = 4 };
}

const Scalar = union(enum) {
    scalar: struct { cp: u21, len: usize },
    /// A well-formed prefix of a longer sequence; wait for more input.
    more,
};

/// The next scalar value of `s` as the Standard's UTF-8 decoder reads it: an
/// ill-formed sequence is one U+FFFD per maximal subpart. `last`: `s` ends
/// the stream, so a cut sequence is U+FFFD instead of `.more`.
fn nextScalar(s: []const u8, last: bool) Scalar {
    const b0 = s[0];
    if (b0 < 0x80) return .{ .scalar = .{ .cp = b0, .len = 1 } };
    var need: usize = undefined;
    var lo: u8 = 0x80;
    var hi: u8 = 0xBF;
    var cp: u21 = undefined;
    switch (b0) {
        0xC2...0xDF => {
            need = 1;
            cp = b0 & 0x1F;
        },
        0xE0...0xEF => {
            need = 2;
            cp = b0 & 0x0F;
            if (b0 == 0xE0) lo = 0xA0;
            if (b0 == 0xED) hi = 0x9F;
        },
        0xF0...0xF4 => {
            need = 3;
            cp = b0 & 0x07;
            if (b0 == 0xF0) lo = 0x90;
            if (b0 == 0xF4) hi = 0x8F;
        },
        else => return .{ .scalar = .{ .cp = 0xFFFD, .len = 1 } },
    }
    var i: usize = 1;
    while (i <= need) : (i += 1) {
        if (i >= s.len) {
            if (last) return .{ .scalar = .{ .cp = 0xFFFD, .len = i } };
            return .more;
        }
        const b = s[i];
        if (b < lo or b > hi) return .{ .scalar = .{ .cp = 0xFFFD, .len = i } };
        lo = 0x80;
        hi = 0xBF;
        cp = (cp << 6) | (b & 0x3F);
    }
    return .{ .scalar = .{ .cp = cp, .len = need + 1 } };
}

// ── whole-buffer API ────────────────────────────────────────────────────────

/// `bytes` in `enc` to UTF-8, U+FFFD for every error (the Standard's
/// "decode" with the replacement error mode).
pub fn decodeToUtf8(alloc: std.mem.Allocator, bytes: []const u8, enc: Cjk) ![]u8 {
    return decodeAll(alloc, bytes, enc, false) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => unreachable, // lenient
    };
}

/// As `decodeToUtf8`, but `error.Malformed` at the first error (WHATWG
/// `fatal`).
pub fn decodeFatal(alloc: std.mem.Allocator, bytes: []const u8, enc: Cjk) Decoder.Error![]u8 {
    return decodeAll(alloc, bytes, enc, true);
}

fn decodeAll(alloc: std.mem.Allocator, bytes: []const u8, enc: Cjk, fatal: bool) Decoder.Error![]u8 {
    var d: Decoder = .init(enc, .{ .fatal = fatal });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, bytes.len +| bytes.len / 2 +| 16);
    var r: usize = 0;
    while (true) {
        const p = d.decodeInto(bytes[r..], out.unusedCapacitySlice(), true);
        out.items.len += p.written;
        r += p.read;
        switch (p.status) {
            .input_empty => break,
            .output_full => try out.ensureUnusedCapacity(alloc, d.maxUtf8Len(bytes.len - r)),
            .malformed => return error.Malformed,
        }
    }
    return out.toOwnedSlice(alloc);
}

/// UTF-8 to `enc`; an unmappable code point per `opts.unmappable`
/// (`error.Unmappable` when `.fatal`). ISO-2022-JP output ends in ASCII.
pub fn encodeFromUtf8(alloc: std.mem.Allocator, utf8: []const u8, enc: Cjk, opts: Encoder.Options) Encoder.Error![]u8 {
    var e: Encoder = .init(enc, opts);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, utf8.len +| utf8.len / 2 +| 16);
    var r: usize = 0;
    while (true) {
        const p = e.encodeInto(utf8[r..], out.unusedCapacitySlice(), true);
        out.items.len += p.written;
        r += p.read;
        switch (p.status) {
            .input_empty => break,
            .output_full => try out.ensureUnusedCapacity(alloc, e.maxEncodedLen(utf8.len - r)),
            .unmappable => return error.Unmappable,
        }
    }
    return out.toOwnedSlice(alloc);
}
