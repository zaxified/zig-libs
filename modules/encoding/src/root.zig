// SPDX-License-Identifier: MIT
//! encoding — legacy single-byte code page ↔ UTF-8 conversion
//! (windows-1250/1252, iso-8859-1/2/15), plus UTF-16, BOM sniffing, a
//! streaming decoder and a fatal mode (2026-10-04). Lenient by default.
//!
//! The WHATWG "single-byte" decoder/encoder for the European code pages a
//! legacy broker / Excel export is realistically saved in. Internal currency
//! is always UTF-8; this module only runs at the read edge (decode → UTF-8)
//! and the write edge (encode ← UTF-8).
//!
//! Data-lenient: a byte / sequence that cannot be transcoded is emitted
//! verbatim (encode) or replaced with U+FFFD (decode) — never an error, never
//! a crash. Every code page's low half (0x00–0x7F) is ASCII and maps to
//! itself, so structural bytes (delimiters, quotes, CR, LF) survive
//! transcoding. ⚠ That is a claim about *delimiters*, not about *positions*:
//! earlier revisions of this line said "and raw byte offsets stay valid",
//! which is false as written for decode — 4 MiB of `0x80` decoded as
//! windows-1250 is 12 MiB, exactly 3x, so every offset after the first high
//! byte shifts. What holds is that a byte-oriented framer running on the RAW
//! bytes still finds its delimiters, which is the useful half.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Text decoding to and from UTF-8: 5 European single-byte code pages, UTF-8 and UTF-16 with BOM sniffing, streaming and fatal modes (WHATWG semantics).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "WHATWG Encoding Standard (single-byte subset)",
    .deps = .{},
};

/// Supported text encodings for input / output. `utf8` is the default and a
/// pure pass-through. The rest are the European single-byte code pages.
pub const Encoding = enum {
    utf8,
    windows_1250, // Central European (Czech, Polish, Hungarian, …)
    windows_1252, // Western European
    iso_8859_1, // Latin-1 (Western European)
    iso_8859_2, // Latin-2 (Central European)
    iso_8859_15, // Latin-9 (Latin-1 + €, Š, Ž, Œ, Ÿ)

    /// Parse a config string into an Encoding. Case-insensitive, and leading
    /// and trailing ASCII whitespace is stripped first (WHATWG "get an
    /// encoding" step 1 — a label read off a CRLF-terminated ini or CSV
    /// header line arrives with a `\r` on it, and used to return null).
    /// Returns null on no match so the caller can emit a did-you-mean style
    /// warning.
    ///
    /// The alias set is WHATWG's for these five pages, with **one deliberate
    /// departure**: WHATWG maps the labels `iso-8859-1`, `iso8859-1`,
    /// `latin1` and friends to the **windows-1252** encoding, because that is
    /// what the web actually contains. This module has a distinct
    /// `iso_8859_1` — the true ISO/IEC 8859-1 page, identity high half — and
    /// those labels select it. The consequence is real and worth knowing
    /// before you rely on either behaviour: `93 71 75 6f 74 65 64 94` decodes
    /// here to a C1 control, `“quoted”` in a browser. Choose `.windows_1252`
    /// explicitly for web-sourced data.
    pub fn parse(raw: []const u8) ?Encoding {
        const s = std.mem.trim(u8, raw, " \t\n\r\x0c");
        const eq = std.ascii.eqlIgnoreCase;
        if (eq(s, "utf-8") or eq(s, "utf8") or eq(s, "unicode-1-1-utf-8") or eq(s, "unicode11utf8") or eq(s, "unicode20utf8") or eq(s, "x-unicode20utf8")) return .utf8;
        if (eq(s, "windows-1250") or eq(s, "windows1250") or eq(s, "cp1250") or eq(s, "win1250") or eq(s, "x-cp1250")) return .windows_1250;
        if (eq(s, "windows-1252") or eq(s, "windows1252") or eq(s, "cp1252") or eq(s, "win1252") or eq(s, "x-cp1252") or
            eq(s, "ansi_x3.4-1968") or eq(s, "ascii") or eq(s, "us-ascii")) return .windows_1252;
        // `cp819`/`ibm819` are IANA's own aliases of ISO_8859-1:1987, so they
        // follow the departure with the rest of the family; until 2026-10-05
        // they alone stayed on windows-1252 (found by the Go oracle,
        // `go_oracle.zig`).
        if (eq(s, "iso-8859-1") or eq(s, "iso8859-1") or eq(s, "iso88591") or eq(s, "iso_8859-1") or
            eq(s, "iso_8859-1:1987") or eq(s, "iso-ir-100") or eq(s, "latin-1") or eq(s, "latin1") or
            eq(s, "l1") or eq(s, "csisolatin1") or eq(s, "cp819") or eq(s, "ibm819")) return .iso_8859_1;
        if (eq(s, "iso-8859-2") or eq(s, "iso8859-2") or eq(s, "iso88592") or eq(s, "iso_8859-2") or
            eq(s, "iso_8859-2:1987") or eq(s, "iso-ir-101") or eq(s, "latin-2") or eq(s, "latin2") or
            eq(s, "l2") or eq(s, "csisolatin2")) return .iso_8859_2;
        if (eq(s, "iso-8859-15") or eq(s, "iso8859-15") or eq(s, "iso885915") or eq(s, "iso_8859-15") or
            eq(s, "iso-ir-203") or eq(s, "latin-9") or eq(s, "latin9") or eq(s, "l9") or eq(s, "csisolatin9")) return .iso_8859_15;
        return null;
    }

    /// Canonical config string for this encoding.
    pub fn canonicalName(self: Encoding) []const u8 {
        return switch (self) {
            .utf8 => "utf-8",
            .windows_1250 => "windows-1250",
            .windows_1252 => "windows-1252",
            .iso_8859_1 => "iso-8859-1",
            .iso_8859_2 => "iso-8859-2",
            .iso_8859_15 => "iso-8859-15",
        };
    }
};

/// Copy `bytes`, replacing malformed UTF-8 with U+FFFD exactly as the WHATWG
/// Encoding Standard's UTF-8 decoder does: one U+FFFD per MAXIMAL SUBPART of an
/// ill-formed sequence (Unicode's recommended practice, also Python's
/// `errors="replace"`) — `e2 82` truncated is ONE U+FFFD, `f0 80 80` is three
/// (`80` cannot follow `f0`). Until 2026-10-04 this replaced byte by byte
/// (two for `e2 82`) while the doc said "WHATWG". Either way a byte that
/// cannot continue a sequence is re-read on its own, so an ASCII delimiter
/// after bad input is never swallowed.
fn sanitizeUtf8(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    // Overwhelmingly the input is already valid; pay one scan to find out.
    if (std.unicode.utf8ValidateSlice(bytes)) return alloc.dupe(u8, bytes);
    var d: Decoder = .init(.{ .encoding = .utf8 }, .{});
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, bytes.len);
    d.feed(alloc, &out, bytes) catch |e| return lenientOnly(e);
    d.finish(alloc, &out) catch |e| return lenientOnly(e);
    return out.toOwnedSlice(alloc);
}

/// A lenient decoder never reports `Malformed`; only allocation can fail.
fn lenientOnly(e: Decoder.Error) error{OutOfMemory} {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => unreachable,
    };
}

/// U+FFFD in UTF-8.
pub const replacement_char = "\u{FFFD}";

/// Decode `bytes` in `enc` into a freshly allocated **valid UTF-8** string.
/// ASCII bytes (< 0x80) always pass through unchanged. Caller owns the
/// returned slice.
///
/// For the five legacy pages the guarantee is structural: every one of the
/// 128 high bytes maps to a codepoint (pinned by `normative_test.zig`), so
/// the output cannot be anything but valid UTF-8. For `.utf8` it used to be
/// a verbatim dupe — and `.utf8` is the enum's first member, the one
/// `Encoding.parse` yields for an absent or unknown declaration, and the one
/// the README calls the default. So a function named `decodeToUtf8` handed
/// hostile bytes straight through on its most-taken path: a lone `0xFF`, a
/// truncated `e2 82`, a surrogate `ed a0 80` and an overlong `c0 af` all came
/// out unchanged, and a downstream `Utf8View` or JSON emitter met them
/// believing otherwise. Malformed input is now replaced with U+FFFD, which is
/// what the WHATWG Encoding Standard's own decode algorithm does — the
/// standard this module names as its model — so the guarantee is
/// unconditional. Well-formed UTF-8 is unchanged.
pub fn decodeToUtf8(alloc: std.mem.Allocator, bytes: []const u8, enc: Encoding) ![]u8 {
    if (enc == .utf8) return sanitizeUtf8(alloc, bytes);
    const table = highTable(enc);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    // Worst case is 1 byte → 3 UTF-8 bytes; the common case is ASCII (1:1).
    try out.ensureTotalCapacity(alloc, bytes.len);

    var enc_buf: [4]u8 = undefined;
    for (bytes) |b| {
        if (b < 0x80) {
            try out.append(alloc, b);
            continue;
        }
        const cp = table[b - 0x80];
        const n = std.unicode.utf8Encode(cp, &enc_buf) catch {
            try out.append(alloc, b); // unmappable codepoint → verbatim byte
            continue;
        };
        try out.appendSlice(alloc, enc_buf[0..n]);
    }
    return out.toOwnedSlice(alloc);
}

/// Encode a UTF-8 string into legacy `enc` bytes. For `.utf8` this is a
/// verbatim dupe. A codepoint with no representation in the target code page
/// becomes '?' (single byte); invalid UTF-8 bytes pass through verbatim.
/// Caller owns the returned slice.
pub fn encodeFromUtf8(alloc: std.mem.Allocator, utf8: []const u8, enc: Encoding) ![]u8 {
    if (enc == .utf8) return alloc.dupe(u8, utf8);
    const table = highTable(enc);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    // Output is always ≤ the UTF-8 length (multi-byte sequences shrink to one
    // byte), so the input length is a safe upper-bound reservation.
    try out.ensureTotalCapacity(alloc, utf8.len);

    var i: usize = 0;
    while (i < utf8.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(utf8[i]) catch {
            try out.append(alloc, utf8[i]); // invalid leading byte → verbatim
            i += 1;
            continue;
        };
        if (i + seq_len > utf8.len) {
            try out.append(alloc, utf8[i]); // truncated trailing sequence → verbatim
            i += 1;
            continue;
        }
        const cp = std.unicode.utf8Decode(utf8[i .. i + seq_len]) catch {
            try out.append(alloc, utf8[i]); // malformed continuation → verbatim
            i += 1;
            continue;
        };
        if (cp < 0x80) {
            try out.append(alloc, @intCast(cp));
        } else if (encodeHigh(table, cp)) |b| {
            try out.append(alloc, b);
        } else {
            try out.append(alloc, '?'); // not representable in the target code page
        }
        i += seq_len;
    }
    return out.toOwnedSlice(alloc);
}

// ── UTF-16, BOM sniffing, streaming and fatal decoding (2026-10-04) ─────────
//
// UTF-16 is deliberately NOT a member of `Encoding`. Every `Encoding` is
// ASCII-compatible: a byte below 0x80 is that ASCII character in every one,
// which is what lets a caller transcode a CSV cell by cell and write its
// delimiters as plain bytes (bxp does). UTF-16 breaks that — `,` is `2c 00` —
// so it gets its own entry points and cannot be picked by accident through
// `Encoding.parse` or an enum listing.

pub const Utf16Endian = enum { le, be };

/// What a byte-order mark at the start of a buffer says.
pub const Bom = enum {
    utf8, // ef bb bf
    utf16le, // ff fe
    utf16be, // fe ff

    pub fn len(self: Bom) usize {
        return if (self == .utf8) 3 else 2;
    }
};

/// The BOM `bytes` starts with, if any (WHATWG "BOM sniff"). Note that a
/// UTF-32LE BOM (`ff fe 00 00`) sniffs as UTF-16LE, as in the Standard.
pub fn sniffBom(bytes: []const u8) ?Bom {
    if (std.mem.startsWith(u8, bytes, "\xef\xbb\xbf")) return .utf8;
    if (std.mem.startsWith(u8, bytes, "\xff\xfe")) return .utf16le;
    if (std.mem.startsWith(u8, bytes, "\xfe\xff")) return .utf16be;
    return null;
}

pub const Decoded = struct {
    /// Valid UTF-8, without the BOM. Caller owns it.
    text: []u8,
    /// The BOM that decided the encoding, or null when `fallback` was used.
    bom: ?Bom,
};

/// The WHATWG "decode" algorithm: a BOM, when present, overrides `fallback`
/// and is removed; otherwise `bytes` are decoded as `fallback`. Lenient
/// (malformed input becomes U+FFFD). Use this for a file whose encoding is
/// declared somewhere but might carry a BOM — an Excel "Unicode Text" export
/// is UTF-16LE with `ff fe`, whatever the declaration says.
pub fn decode(alloc: std.mem.Allocator, bytes: []const u8, fallback: Encoding) !Decoded {
    if (sniffBom(bytes)) |b| {
        const rest = bytes[b.len()..];
        const text = switch (b) {
            .utf8 => try sanitizeUtf8(alloc, rest),
            .utf16le => try decodeUtf16(alloc, rest, .le),
            .utf16be => try decodeUtf16(alloc, rest, .be),
        };
        return .{ .text = text, .bom = b };
    }
    return .{ .text = try decodeToUtf8(alloc, bytes, fallback), .bom = null };
}

/// Decode UTF-16 (no BOM handling — see `decode`) into valid UTF-8, the WHATWG
/// way: an unpaired surrogate is one U+FFFD, a lead surrogate followed by a
/// non-trail unit is U+FFFD and the unit is read again, an odd final byte is
/// U+FFFD. Caller owns the result.
pub fn decodeUtf16(alloc: std.mem.Allocator, bytes: []const u8, endian: Utf16Endian) ![]u8 {
    var d: Decoder = .init(.{ .utf16 = endian }, .{});
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, bytes.len + bytes.len / 2);
    d.feed(alloc, &out, bytes) catch |e| return lenientOnly(e);
    d.finish(alloc, &out) catch |e| return lenientOnly(e);
    return out.toOwnedSlice(alloc);
}

/// Encode UTF-8 as UTF-16 (`bom`: prepend `ff fe` / `fe ff`). Malformed UTF-8
/// becomes U+FFFD (maximal subparts, as the decoder) — unlike the single-byte
/// encoders it cannot pass a stray byte through, UTF-16 has no byte to keep.
/// Caller owns the result.
pub fn encodeUtf16(alloc: std.mem.Allocator, utf8: []const u8, endian: Utf16Endian, bom: bool) ![]u8 {
    const valid = try sanitizeUtf8(alloc, utf8);
    defer alloc.free(valid);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, valid.len * 2 + 2);
    if (bom) try appendUnit(alloc, &out, 0xFEFF, endian);
    const view = std.unicode.Utf8View.initUnchecked(valid);
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp >= 0x10000) {
            const v = cp - 0x10000;
            try appendUnit(alloc, &out, @intCast(0xD800 + (v >> 10)), endian);
            try appendUnit(alloc, &out, @intCast(0xDC00 + (v & 0x3FF)), endian);
        } else try appendUnit(alloc, &out, @intCast(cp), endian);
    }
    return out.toOwnedSlice(alloc);
}

fn appendUnit(alloc: std.mem.Allocator, out: *std.ArrayList(u8), unit: u16, endian: Utf16Endian) !void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, unit, if (endian == .le) .little else .big);
    try out.appendSlice(alloc, &b);
}

/// Whole-buffer decode in FATAL mode (WHATWG `fatal`): `error.Malformed` at
/// the first ill-formed sequence instead of U+FFFD. Single-byte pages cannot
/// be malformed, so for them this equals `decodeToUtf8`.
pub fn decodeFatal(alloc: std.mem.Allocator, bytes: []const u8, kind: Decoder.Kind) Decoder.Error![]u8 {
    var d: Decoder = .init(kind, .{ .fatal = true });
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, bytes.len);
    try d.feed(alloc, &out, bytes);
    try d.finish(alloc, &out);
    return out.toOwnedSlice(alloc);
}

/// Streaming decoder: feed input in chunks of any size — a multi-byte UTF-8
/// sequence or a UTF-16 unit / surrogate pair split across chunks is carried
/// over — and call `finish` at the end of the stream. The output is the same
/// as decoding the concatenation in one call (tested at every split point).
/// State is a few bytes; no allocation beyond `out`.
pub const Decoder = struct {
    kind: Kind,
    fatal: bool,
    // UTF-8 (WHATWG "UTF-8 decoder" state).
    needed: u8 = 0,
    seen: u8 = 0,
    cp: u21 = 0,
    lower: u8 = 0x80,
    upper: u8 = 0xBF,
    // UTF-16.
    lead_byte: ?u8 = null,
    lead_surrogate: ?u16 = null,
    /// Set once `fatal` reported an error; the decoder refuses further input.
    failed: bool = false,

    pub const Kind = union(enum) {
        /// Any `Encoding` (UTF-8 or a single-byte page).
        encoding: Encoding,
        utf16: Utf16Endian,
    };
    pub const Options = struct {
        /// `error.Malformed` instead of U+FFFD (WHATWG `fatal`).
        fatal: bool = false,
    };
    pub const Error = std.mem.Allocator.Error || error{Malformed};

    pub fn init(kind: Kind, opts: Options) Decoder {
        return .{ .kind = kind, .fatal = opts.fatal };
    }

    fn bad(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        if (self.fatal) {
            self.failed = true;
            return error.Malformed;
        }
        try out.appendSlice(alloc, replacement_char);
    }

    fn emit(alloc: std.mem.Allocator, out: *std.ArrayList(u8), cp: u21) !void {
        var b: [4]u8 = undefined;
        // Only scalar values reach here (surrogates are filtered by both
        // state machines), so this cannot fail.
        const n = std.unicode.utf8Encode(cp, &b) catch unreachable;
        try out.appendSlice(alloc, b[0..n]);
    }

    /// Decode `chunk`, appending UTF-8 to `out`.
    pub fn feed(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8) Error!void {
        if (self.failed) return error.Malformed;
        switch (self.kind) {
            .encoding => |enc| if (enc == .utf8) {
                for (chunk) |b| try self.utf8Byte(alloc, out, b);
            } else {
                const table = highTable(enc);
                for (chunk) |b| {
                    if (b < 0x80) try out.append(alloc, b) else try emit(alloc, out, table[b - 0x80]);
                }
            },
            .utf16 => |endian| for (chunk) |b| try self.utf16Byte(alloc, out, b, endian),
        }
    }

    /// End of stream: an unfinished sequence is one more U+FFFD (or
    /// `error.Malformed`). The decoder is reset and may be reused.
    pub fn finish(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) Error!void {
        if (self.failed) return error.Malformed;
        const pending = self.needed != 0 or self.lead_byte != null or self.lead_surrogate != null;
        self.* = .init(self.kind, .{ .fatal = self.fatal });
        if (pending) try self.bad(alloc, out);
    }

    fn utf8Byte(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), b: u8) Error!void {
        if (self.needed == 0) {
            switch (b) {
                0x00...0x7F => try out.append(alloc, b),
                0xC2...0xDF => {
                    self.needed = 1;
                    self.cp = b & 0x1F;
                },
                0xE0...0xEF => {
                    if (b == 0xE0) self.lower = 0xA0; // no overlongs
                    if (b == 0xED) self.upper = 0x9F; // no surrogates
                    self.needed = 2;
                    self.cp = b & 0x0F;
                },
                0xF0...0xF4 => {
                    if (b == 0xF0) self.lower = 0x90; // no overlongs
                    if (b == 0xF4) self.upper = 0x8F; // nothing past U+10FFFF
                    self.needed = 3;
                    self.cp = b & 0x07;
                },
                else => try self.bad(alloc, out),
            }
            return;
        }
        if (b < self.lower or b > self.upper) {
            // The maximal subpart so far is one error; `b` is read again.
            self.needed = 0;
            self.seen = 0;
            self.cp = 0;
            self.lower = 0x80;
            self.upper = 0xBF;
            try self.bad(alloc, out);
            return self.utf8Byte(alloc, out, b);
        }
        self.lower = 0x80;
        self.upper = 0xBF;
        self.cp = (self.cp << 6) | (b & 0x3F);
        self.seen += 1;
        if (self.seen != self.needed) return;
        const cp = self.cp;
        self.needed = 0;
        self.seen = 0;
        self.cp = 0;
        try emit(alloc, out, cp);
    }

    fn utf16Byte(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), b: u8, endian: Utf16Endian) Error!void {
        const lead = self.lead_byte orelse {
            self.lead_byte = b;
            return;
        };
        self.lead_byte = null;
        const unit: u16 = if (endian == .le) (@as(u16, b) << 8) | lead else (@as(u16, lead) << 8) | b;
        try self.utf16Unit(alloc, out, unit);
    }

    fn utf16Unit(self: *Decoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), unit: u16) Error!void {
        if (self.lead_surrogate) |ls| {
            self.lead_surrogate = null;
            if (unit >= 0xDC00 and unit <= 0xDFFF) {
                const cp: u21 = 0x10000 + ((@as(u21, ls) - 0xD800) << 10) + (unit - 0xDC00);
                return emit(alloc, out, cp);
            }
            // Unpaired lead: one error, then this unit on its own.
            try self.bad(alloc, out);
            return self.utf16Unit(alloc, out, unit);
        }
        if (unit >= 0xD800 and unit <= 0xDBFF) {
            self.lead_surrogate = unit;
            return;
        }
        if (unit >= 0xDC00 and unit <= 0xDFFF) return self.bad(alloc, out);
        try emit(alloc, out, unit);
    }
};

/// Reverse lookup: find the high byte (0x80–0xFF) that maps to `cp` in `table`.
/// Linear scan — the table is 128 entries and the encode path is a rare,
/// non-hot legacy-output feature.
fn encodeHigh(table: *const [128]u21, cp: u21) ?u8 {
    for (table, 0..) |t, i| {
        if (t == cp) return @intCast(0x80 + i);
    }
    return null;
}

// ── 0x80–0xFF code page tables ──────────────────────────────────────────────
//
// Each table maps the 128 high bytes (index 0 = byte 0x80) to a Unicode
// codepoint. Built from an identity base (byte value == codepoint, which is
// exactly Latin-1 and the C1 region) plus the per-code-page overrides where
// the mapping differs. Bytes 0x00–0x7F are ASCII and handled directly by the
// decode loop, never via these tables.

const Ovr = struct { b: u8, cp: u21 };

fn build(comptime ovrs: []const Ovr) [128]u21 {
    var t: [128]u21 = undefined;
    for (&t, 0..) |*e, i| e.* = @intCast(0x80 + i); // identity base (Latin-1 / C1)
    for (ovrs) |o| t[o.b - 0x80] = o.cp;
    return t;
}

fn highTable(enc: Encoding) *const [128]u21 {
    return switch (enc) {
        .utf8 => unreachable, // callers short-circuit utf8 before reaching here
        .windows_1250 => &windows_1250_high,
        .windows_1252 => &windows_1252_high,
        .iso_8859_1 => &iso_8859_1_high,
        .iso_8859_2 => &iso_8859_2_high,
        .iso_8859_15 => &iso_8859_15_high,
    };
}

// ISO-8859-1 (Latin-1): the high half is pure identity (byte == codepoint).
const iso_8859_1_high = build(&.{});

// ISO-8859-15 (Latin-9): Latin-1 with eight substitutions.
const iso_8859_15_high = build(&.{
    .{ .b = 0xA4, .cp = 0x20AC }, // €
    .{ .b = 0xA6, .cp = 0x0160 }, // Š
    .{ .b = 0xA8, .cp = 0x0161 }, // š
    .{ .b = 0xB4, .cp = 0x017D }, // Ž
    .{ .b = 0xB8, .cp = 0x017E }, // ž
    .{ .b = 0xBC, .cp = 0x0152 }, // Œ
    .{ .b = 0xBD, .cp = 0x0153 }, // œ
    .{ .b = 0xBE, .cp = 0x0178 }, // Ÿ
});

// Windows-1252 (Western European): Latin-1 plus the 0x80–0x9F "C1" specials
// (smart quotes, €, dashes, …). The five undefined slots (0x81 0x8D 0x8F 0x90
// 0x9D) keep the identity mapping, matching the WHATWG decoder.
const windows_1252_high = build(&.{
    .{ .b = 0x80, .cp = 0x20AC }, .{ .b = 0x82, .cp = 0x201A }, .{ .b = 0x83, .cp = 0x0192 },
    .{ .b = 0x84, .cp = 0x201E }, .{ .b = 0x85, .cp = 0x2026 }, .{ .b = 0x86, .cp = 0x2020 },
    .{ .b = 0x87, .cp = 0x2021 }, .{ .b = 0x88, .cp = 0x02C6 }, .{ .b = 0x89, .cp = 0x2030 },
    .{ .b = 0x8A, .cp = 0x0160 }, .{ .b = 0x8B, .cp = 0x2039 }, .{ .b = 0x8C, .cp = 0x0152 },
    .{ .b = 0x8E, .cp = 0x017D }, .{ .b = 0x91, .cp = 0x2018 }, .{ .b = 0x92, .cp = 0x2019 },
    .{ .b = 0x93, .cp = 0x201C }, .{ .b = 0x94, .cp = 0x201D }, .{ .b = 0x95, .cp = 0x2022 },
    .{ .b = 0x96, .cp = 0x2013 }, .{ .b = 0x97, .cp = 0x2014 }, .{ .b = 0x98, .cp = 0x02DC },
    .{ .b = 0x99, .cp = 0x2122 }, .{ .b = 0x9A, .cp = 0x0161 }, .{ .b = 0x9B, .cp = 0x203A },
    .{ .b = 0x9C, .cp = 0x0153 }, .{ .b = 0x9E, .cp = 0x017E }, .{ .b = 0x9F, .cp = 0x0178 },
});

// Windows-1250 (Central European). Identity base covers the Latin-1-coincident
// slots; the overrides below are every byte whose codepoint differs (the C1
// specials in 0x80–0x9F and the Central-European letters in 0xA0–0xFF).
const windows_1250_high = build(&.{
    .{ .b = 0x80, .cp = 0x20AC }, .{ .b = 0x82, .cp = 0x201A }, .{ .b = 0x84, .cp = 0x201E },
    .{ .b = 0x85, .cp = 0x2026 }, .{ .b = 0x86, .cp = 0x2020 }, .{ .b = 0x87, .cp = 0x2021 },
    .{ .b = 0x89, .cp = 0x2030 }, .{ .b = 0x8A, .cp = 0x0160 }, .{ .b = 0x8B, .cp = 0x2039 },
    .{ .b = 0x8C, .cp = 0x015A }, .{ .b = 0x8D, .cp = 0x0164 }, .{ .b = 0x8E, .cp = 0x017D },
    .{ .b = 0x8F, .cp = 0x0179 }, .{ .b = 0x91, .cp = 0x2018 }, .{ .b = 0x92, .cp = 0x2019 },
    .{ .b = 0x93, .cp = 0x201C }, .{ .b = 0x94, .cp = 0x201D }, .{ .b = 0x95, .cp = 0x2022 },
    .{ .b = 0x96, .cp = 0x2013 }, .{ .b = 0x97, .cp = 0x2014 }, .{ .b = 0x99, .cp = 0x2122 },
    .{ .b = 0x9A, .cp = 0x0161 }, .{ .b = 0x9B, .cp = 0x203A }, .{ .b = 0x9C, .cp = 0x015B },
    .{ .b = 0x9D, .cp = 0x0165 }, .{ .b = 0x9E, .cp = 0x017E }, .{ .b = 0x9F, .cp = 0x017A },
    .{ .b = 0xA1, .cp = 0x02C7 }, .{ .b = 0xA2, .cp = 0x02D8 }, .{ .b = 0xA3, .cp = 0x0141 },
    .{ .b = 0xA5, .cp = 0x0104 }, .{ .b = 0xAA, .cp = 0x015E }, .{ .b = 0xAF, .cp = 0x017B },
    .{ .b = 0xB2, .cp = 0x02DB }, .{ .b = 0xB3, .cp = 0x0142 }, .{ .b = 0xB9, .cp = 0x0105 },
    .{ .b = 0xBA, .cp = 0x015F }, .{ .b = 0xBC, .cp = 0x013D }, .{ .b = 0xBD, .cp = 0x02DD },
    .{ .b = 0xBE, .cp = 0x013E }, .{ .b = 0xBF, .cp = 0x017C }, .{ .b = 0xC0, .cp = 0x0154 },
    .{ .b = 0xC3, .cp = 0x0102 }, .{ .b = 0xC5, .cp = 0x0139 }, .{ .b = 0xC6, .cp = 0x0106 },
    .{ .b = 0xC8, .cp = 0x010C }, .{ .b = 0xCA, .cp = 0x0118 }, .{ .b = 0xCC, .cp = 0x011A },
    .{ .b = 0xCF, .cp = 0x010E }, .{ .b = 0xD0, .cp = 0x0110 }, .{ .b = 0xD1, .cp = 0x0143 },
    .{ .b = 0xD2, .cp = 0x0147 }, .{ .b = 0xD5, .cp = 0x0150 }, .{ .b = 0xD8, .cp = 0x0158 },
    .{ .b = 0xD9, .cp = 0x016E }, .{ .b = 0xDB, .cp = 0x0170 }, .{ .b = 0xDE, .cp = 0x0162 },
    .{ .b = 0xE0, .cp = 0x0155 }, .{ .b = 0xE3, .cp = 0x0103 }, .{ .b = 0xE5, .cp = 0x013A },
    .{ .b = 0xE6, .cp = 0x0107 }, .{ .b = 0xE8, .cp = 0x010D }, .{ .b = 0xEA, .cp = 0x0119 },
    .{ .b = 0xEC, .cp = 0x011B }, .{ .b = 0xEF, .cp = 0x010F }, .{ .b = 0xF0, .cp = 0x0111 },
    .{ .b = 0xF1, .cp = 0x0144 }, .{ .b = 0xF2, .cp = 0x0148 }, .{ .b = 0xF5, .cp = 0x0151 },
    .{ .b = 0xF8, .cp = 0x0159 }, .{ .b = 0xF9, .cp = 0x016F }, .{ .b = 0xFB, .cp = 0x0171 },
    .{ .b = 0xFE, .cp = 0x0163 }, .{ .b = 0xFF, .cp = 0x02D9 },
});

// ISO-8859-2 (Latin-2). 0x80–0x9F are the C1 controls (identity); 0xA0–0xFF
// are the Central-European letters. Overrides list every 0xA0+ byte whose
// codepoint differs from the identity (Latin-1-coincident) value.
const iso_8859_2_high = build(&.{
    .{ .b = 0xA1, .cp = 0x0104 }, .{ .b = 0xA2, .cp = 0x02D8 }, .{ .b = 0xA3, .cp = 0x0141 },
    .{ .b = 0xA5, .cp = 0x013D }, .{ .b = 0xA6, .cp = 0x015A }, .{ .b = 0xA9, .cp = 0x0160 },
    .{ .b = 0xAA, .cp = 0x015E }, .{ .b = 0xAB, .cp = 0x0164 }, .{ .b = 0xAC, .cp = 0x0179 },
    .{ .b = 0xAE, .cp = 0x017D }, .{ .b = 0xAF, .cp = 0x017B }, .{ .b = 0xB1, .cp = 0x0105 },
    .{ .b = 0xB2, .cp = 0x02DB }, .{ .b = 0xB3, .cp = 0x0142 }, .{ .b = 0xB5, .cp = 0x013E },
    .{ .b = 0xB6, .cp = 0x015B }, .{ .b = 0xB7, .cp = 0x02C7 }, .{ .b = 0xB9, .cp = 0x0161 },
    .{ .b = 0xBA, .cp = 0x015F }, .{ .b = 0xBB, .cp = 0x0165 }, .{ .b = 0xBC, .cp = 0x017A },
    .{ .b = 0xBD, .cp = 0x02DD }, .{ .b = 0xBE, .cp = 0x017E }, .{ .b = 0xBF, .cp = 0x017C },
    .{ .b = 0xC0, .cp = 0x0154 }, .{ .b = 0xC3, .cp = 0x0102 }, .{ .b = 0xC5, .cp = 0x0139 },
    .{ .b = 0xC6, .cp = 0x0106 }, .{ .b = 0xC8, .cp = 0x010C }, .{ .b = 0xCA, .cp = 0x0118 },
    .{ .b = 0xCC, .cp = 0x011A }, .{ .b = 0xCF, .cp = 0x010E }, .{ .b = 0xD0, .cp = 0x0110 },
    .{ .b = 0xD1, .cp = 0x0143 }, .{ .b = 0xD2, .cp = 0x0147 }, .{ .b = 0xD5, .cp = 0x0150 },
    .{ .b = 0xD8, .cp = 0x0158 }, .{ .b = 0xD9, .cp = 0x016E }, .{ .b = 0xDB, .cp = 0x0170 },
    .{ .b = 0xDE, .cp = 0x0162 }, .{ .b = 0xE0, .cp = 0x0155 }, .{ .b = 0xE3, .cp = 0x0103 },
    .{ .b = 0xE5, .cp = 0x013A }, .{ .b = 0xE6, .cp = 0x0107 }, .{ .b = 0xE8, .cp = 0x010D },
    .{ .b = 0xEA, .cp = 0x0119 }, .{ .b = 0xEC, .cp = 0x011B }, .{ .b = 0xEF, .cp = 0x010F },
    .{ .b = 0xF0, .cp = 0x0111 }, .{ .b = 0xF1, .cp = 0x0144 }, .{ .b = 0xF2, .cp = 0x0148 },
    .{ .b = 0xF5, .cp = 0x0151 }, .{ .b = 0xF8, .cp = 0x0159 }, .{ .b = 0xF9, .cp = 0x016F },
    .{ .b = 0xFB, .cp = 0x0171 }, .{ .b = 0xFE, .cp = 0x0163 }, .{ .b = 0xFF, .cp = 0x02D9 },
});

// ── tests ────────────────────────────────────────────────────────────────
const testing = std.testing;

fn expectDecode(enc: Encoding, bytes: []const u8, want: []const u8) !void {
    const got = try decodeToUtf8(testing.allocator, bytes, enc);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

fn expectEncode(enc: Encoding, utf8: []const u8, want: []const u8) !void {
    const got = try encodeFromUtf8(testing.allocator, utf8, enc);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

test "parse: canonical names and aliases" {
    try testing.expectEqual(Encoding.utf8, Encoding.parse("UTF-8").?);
    try testing.expectEqual(Encoding.windows_1250, Encoding.parse("windows-1250").?);
    try testing.expectEqual(Encoding.windows_1250, Encoding.parse("cp1250").?);
    try testing.expectEqual(Encoding.windows_1252, Encoding.parse("Windows-1252").?);
    try testing.expectEqual(Encoding.iso_8859_1, Encoding.parse("latin1").?);
    try testing.expectEqual(Encoding.iso_8859_2, Encoding.parse("ISO-8859-2").?);
    try testing.expectEqual(Encoding.iso_8859_15, Encoding.parse("latin-9").?);
    try testing.expectEqual(@as(?Encoding, null), Encoding.parse("shift-jis"));
}

test "decode: ASCII passes through in every encoding" {
    for ([_]Encoding{ .utf8, .windows_1250, .windows_1252, .iso_8859_1, .iso_8859_2, .iso_8859_15 }) |enc| {
        try expectDecode(enc, "AAPL,123.45\n", "AAPL,123.45\n");
    }
}

test "decode: Latin-1 high bytes are identity codepoints" {
    try expectDecode(.iso_8859_1, "caf\xe9", "café"); // 0xE9 → é
    try expectDecode(.iso_8859_1, "\xff", "ÿ"); // 0xFF → ÿ
}

test "decode: Windows-1252 smart quotes and euro" {
    try expectDecode(.windows_1252, "\x93Hi\x94", "“Hi”"); // 0x93/0x94 curly quotes
    try expectDecode(.windows_1252, "\x80", "€"); // 0x80 → €
    try expectDecode(.windows_1252, "na\xefve", "naïve"); // 0xEF → ï (Latin-1 region)
}

test "decode: Windows-1250 Czech letters" {
    // "Příliš" — ř=0xF8, í=0xED, š=0x9A in CP1250
    try expectDecode(.windows_1250, "P\xf8\xedli\x9a", "Příliš");
    try expectDecode(.windows_1250, "\xe8", "č"); // 0xE8 → č
    try expectDecode(.windows_1250, "\xb9", "ą"); // 0xB9 → ą (differs from Latin-1 ¹)
}

test "decode: ISO-8859-2 Czech letters" {
    try expectDecode(.iso_8859_2, "\xe8", "č"); // 0xE8 → č
    try expectDecode(.iso_8859_2, "\xf8", "ř"); // 0xF8 → ř
    try expectDecode(.iso_8859_2, "\xb9", "š"); // 0xB9 → š
}

test "decode: ISO-8859-15 euro and Latin-1 divergence" {
    try expectDecode(.iso_8859_15, "\xa4", "€"); // 0xA4 → € (¤ in Latin-1)
    try expectDecode(.iso_8859_15, "\xe9", "é"); // unchanged from Latin-1
}

test "encode: round-trips for representable codepoints" {
    try expectEncode(.iso_8859_1, "café", "caf\xe9");
    try expectEncode(.windows_1250, "Příliš", "P\xf8\xedli\x9a");
    try expectEncode(.iso_8859_2, "č", "\xe8");
    try expectEncode(.windows_1252, "€", "\x80");
    try expectEncode(.iso_8859_15, "€", "\xa4");
}

test "encode: ASCII and utf8 pass-through" {
    try expectEncode(.windows_1250, "AAPL,1.5\n", "AAPL,1.5\n");
    try expectEncode(.utf8, "Příliš", "Příliš");
    try expectDecode(.utf8, "Příliš", "Příliš");
}

test "encode: unrepresentable codepoint becomes '?'" {
    // A CJK character cannot be expressed in any single-byte European code page.
    try expectEncode(.windows_1250, "A日B", "A?B");
    try expectEncode(.iso_8859_1, "€", "?"); // € is not in Latin-1
}

test "decode/encode: empty string" {
    try expectDecode(.windows_1250, "", "");
    try expectEncode(.windows_1250, "", "");
}

test "encode: invalid UTF-8 passes through verbatim" {
    try expectEncode(.iso_8859_1, "ab\xffcd", "ab\xffcd");
}

test "encode: a malformed CONTINUATION resyncs by ONE byte, so the next ASCII byte survives (re-audit F1)" {
    // The whole point of this codec's error handling: structural bytes —
    // delimiters, quotes, CR, LF — survive transcoding, which is what lets a
    // CSV/log framer keep working across it. Byte-at-a-time resynchronisation
    // on a malformed sequence is what delivers that, and only two of the
    // three `catch` arms had a test. Skipping `seq_len` instead of 1 here
    // silently eats the bytes that follow a bad lead — `e2 22 2c` losing the
    // `"` and the `,` is field-boundary desync, the same shape as the
    // csvstream finding — and the suite stayed green.
    try expectEncode(.windows_1250, "\xe2\x22\x2c", "\xe2\x22\x2c");
    try expectEncode(.iso_8859_1, "\xe2\x22\x2c", "\xe2\x22\x2c");
    try expectEncode(.iso_8859_1, "\xf0\x3c\x73\x3e", "\xf0\x3c\x73\x3e");
    // A 3-byte lead followed by ONE valid continuation and then a delimiter:
    // the delimiter is two bytes past the lead, so `seq_len` would swallow it.
    try expectEncode(.iso_8859_1, "a\xe2\x82,b", "a\xe2\x82,b");
    // The other two arms, kept beside it so the three read as one set.
    try expectEncode(.iso_8859_1, "ab\xffcd", "ab\xffcd"); // invalid lead
    try expectEncode(.iso_8859_1, "ab\xe2", "ab\xe2"); // truncated at end
}

test "decode: `.utf8` produces valid UTF-8, not the bytes it was handed (re-audit F2)" {
    // `.utf8` is the enum's first member, what `Encoding.parse` yields for an
    // absent or unknown declaration, and what the README calls the default —
    // and on that path `decodeToUtf8` was a verbatim dupe, so hostile bytes
    // passed straight through a function whose name is a promise. A
    // downstream `Utf8View` or JSON emitter then met them believing
    // otherwise.
    const cases = [_][]const u8{
        "\xff", // lone continuation-less byte
        "\xe2\x82", // truncated 3-byte sequence
        "\xed\xa0\x80", // surrogate
        "\xc0\xaf", // overlong
        "a,\xff,b", // ...and the delimiters around it still survive
    };
    for (cases) |c| {
        const got = try decodeToUtf8(testing.allocator, c, .utf8);
        defer testing.allocator.free(got);
        try testing.expect(std.unicode.utf8ValidateSlice(got));
        try testing.expect(std.mem.indexOf(u8, got, replacement_char) != null);
    }
    // Valid input is untouched, byte for byte.
    for ([_][]const u8{ "", "plain ascii", "p\u{159}\u{ed}li\u{161} \u{17e}lu\u{165}ou\u{10d}k\u{fd}", "\u{1F600}" }) |c| {
        const got = try decodeToUtf8(testing.allocator, c, .utf8);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(c, got);
    }
    // The commas either side of a bad byte are still commas.
    const framed = try decodeToUtf8(testing.allocator, "a,\xff,b", .utf8);
    defer testing.allocator.free(framed);
    try testing.expectEqualStrings("a," ++ replacement_char ++ ",b", framed);
    // And every legacy page's decode was, and remains, unconditionally valid.
    inline for (.{ .windows_1250, .windows_1252, .iso_8859_1, .iso_8859_2, .iso_8859_15 }) |enc| {
        var all: [256]u8 = undefined;
        for (&all, 0..) |*b, i| b.* = @intCast(i);
        const got = try decodeToUtf8(testing.allocator, &all, enc);
        defer testing.allocator.free(got);
        try testing.expect(std.unicode.utf8ValidateSlice(got));
    }
}

test "parse: WHATWG labels and whitespace (re-audit F3)" {
    // 23 of the 35 WHATWG labels selecting these five pages were rejected
    // outright, so a caller fell back to its default on labels that really
    // occur in the wild; and a label read off a CRLF line kept its `\r`.
    for ([_][]const u8{ "iso88592", "iso_8859-2", "l2", "csisolatin2", "iso-ir-101" }) |l| {
        try testing.expectEqual(Encoding.iso_8859_2, Encoding.parse(l).?);
    }
    for ([_][]const u8{ "iso885915", "l9", "iso_8859-15", "csisolatin9" }) |l| {
        try testing.expectEqual(Encoding.iso_8859_15, Encoding.parse(l).?);
    }
    for ([_][]const u8{ "x-cp1250", "cp1250" }) |l| {
        try testing.expectEqual(Encoding.windows_1250, Encoding.parse(l).?);
    }
    for ([_][]const u8{ "x-cp1252", "ascii", "us-ascii", "ansi_x3.4-1968" }) |l| {
        try testing.expectEqual(Encoding.windows_1252, Encoding.parse(l).?);
    }
    for ([_][]const u8{ "l1", "csisolatin1", "iso88591", "iso_8859-1:1987" }) |l| {
        try testing.expectEqual(Encoding.iso_8859_1, Encoding.parse(l).?);
    }
    // Whitespace, including the CR a CRLF header line leaves behind.
    for ([_][]const u8{ "cp1250\r", " cp1250", "cp1250 ", "\t cp1250 \r\n" }) |l| {
        try testing.expectEqual(Encoding.windows_1250, Encoding.parse(l).?);
    }
    // Still null for a genuine non-match, so a caller can still warn.
    try testing.expect(Encoding.parse("shift_jis") == null);
    try testing.expect(Encoding.parse("") == null);
    // The documented departure from WHATWG, pinned so it cannot drift
    // silently in either direction: these labels select the TRUE ISO-8859-1
    // page here, windows-1252 in a browser.
    try testing.expectEqual(Encoding.iso_8859_1, Encoding.parse("latin1").?);
    const bytes = "\x93quoted\x94";
    const here = try decodeToUtf8(testing.allocator, bytes, Encoding.parse("iso-8859-1").?);
    defer testing.allocator.free(here);
    const web = try decodeToUtf8(testing.allocator, bytes, .windows_1252);
    defer testing.allocator.free(web);
    try testing.expect(!std.mem.eql(u8, here, web));
    try testing.expectEqualStrings("\u{201C}quoted\u{201D}", web);
}

test "canonicalName: round-trips through parse for every Encoding (audit F2)" {
    // canonicalName() had zero test coverage — a wrong string for one arm
    // (e.g. windows_1250 mislabeled as "windows-1252") stayed green.
    inline for (@typeInfo(Encoding).@"enum".fields) |f| {
        const e: Encoding = @enumFromInt(f.value);
        try testing.expectEqual(e, Encoding.parse(e.canonicalName()).?);
    }
    try testing.expectEqualStrings("windows-1250", Encoding.windows_1250.canonicalName());
}

test "encode: cp U+0080 boundary — ASCII cutoff is strictly '< 0x80' (audit F3)" {
    // 0x80 is the first non-ASCII codepoint. windows_1252 overrides byte 0x80's
    // identity mapping (to €), so no byte maps back to raw cp U+0080 there —
    // it must fall to '?', not be truncated into the ASCII branch.
    try expectEncode(.iso_8859_1, "\u{80}", "\x80"); // identity: still round-trips
    try expectEncode(.windows_1252, "\u{80}", "?"); // 0x80 is remapped to €; no byte left for raw U+0080
}

test "encode: a valid multi-byte lead truncated at buffer end passes through, no OOB (audit F1)" {
    // The invalid-leading-byte case above (0xFF) is caught by utf8ByteSequenceLength;
    // the SEPARATE truncated-trailing-sequence bounds check (a valid lead byte with
    // too few continuation bytes left in the buffer) was load-bearing but untested —
    // disabling it OOB-read past the buffer. These exercise that path directly.
    try expectEncode(.iso_8859_1, "ab\xc2", "ab\xc2"); // 2-byte lead (0xC2), 0 continuation
    try expectEncode(.iso_8859_1, "ab\xe2\x82", "ab\xe2\x82"); // 3-byte lead (0xE2), only 1 continuation
}

test {
    _ = @import("fuzz_test.zig");
    // Exhaustive cross-check of all five high-tables against vendored
    // normative sources (WHATWG index-*.txt / Unicode.org 8859-1.TXT) — see
    // normative_test.zig and ../NOTICE.
    _ = @import("normative_vectors.zig");
    _ = @import("normative_test.zig");
    _ = @import("go_oracle.zig");
}

// ── fuzz: decode/encode never panic, OOB or leak on arbitrary bytes ────────
//
// `decodeToUtf8` is the module's decode entry point — legacy code-page bytes
// off the read edge (a broker/Excel export saved in an unknown encoding).
// It is data-lenient by design (never errors on malformed input, an
// unmappable codepoint is emitted verbatim), so unlike a rejecting parser
// there is no structure to bias toward: every byte value takes the same
// bounded per-byte path (ASCII passthrough, table lookup, or the
// `utf8Encode` fallback), so plain arbitrary bytes already reach all of it.
// `encodeFromUtf8` (the write edge) is fuzzed alongside it — the more
// branchy of the two (invalid leading byte / truncated trailing sequence /
// malformed continuation, each with its own audit-found edge case above) —
// over the SAME bytes, since malformed UTF-8 is exactly what a lenient
// encoder must also tolerate. Both allocate, so this runs under
// `std.testing.allocator` with the result freed on every path — a leak here
// is a real finding, not a lenient no-op.
//
// ⚠ This harness opened with `smith.bytes(&buf)` followed by
// `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` copies `min(buf.len,
// in.len)` octets and the ranged draw then reads EIGHT more as a little-endian
// u64, returning the range minimum when fewer remain — so the length was 0 on
// every input a corpus can carry and both codecs were handed an empty slice
// while the bytes sat unread in `buf`. And `enc` was drawn AFTER that, from an
// exhausted input, so `smith.index` returned 0: **every run used `.utf8` and
// no table-driven encoding was ever selected at all**. It had no corpus either,
// so outside `--fuzz` the target ran exactly one input for ever — the empty one
// through the passthrough encoding, which is the single least interesting cell
// of a 6 × N matrix.

/// The encodings the harness sweeps. Swept rather than drawn: the fuzzer still
/// drives the bytes, and every seed now visits all six — including the five
/// table-driven ones the drawn index could never reach.
const fuzz_encodings = [_]Encoding{ .utf8, .windows_1250, .windows_1252, .iso_8859_1, .iso_8859_2, .iso_8859_15 };

/// `testkit.fuzz.seed`, aliased so the corpus reads as the byte strings it is.
/// A corpus entry is not the input: `Smith.slice` reads a little-endian `u32`
/// length first, so a raw string would arrive minus its own first four octets.
const seed = @import("testkit").fuzz.seed;

/// Byte strings, in the format the length draw reads. The same bytes go through
/// BOTH directions, so each seed has to be interesting as a code-page byte
/// string AND as (possibly malformed) UTF-8 — which is why the malformed-UTF-8
/// edges the audit found are here verbatim: a bare lead byte at the very end of
/// the buffer, a lead with too few continuations, and a lone continuation.
const codec_seeds = [_][]const u8{
    seed("plain ASCII, identical in every table"), // the passthrough path
    seed("\x80\x81\x82\x9a\x9c\x9e\xa1\xa5\xb1\xb9"), // the 0x80..0xBF band, where the five tables disagree
    seed("\xc0\xc1\xc2\xd0\xdd\xe0\xea\xf3\xfc\xff"), // the high band: accented letters in every table
    seed("P\xf8\xed li\xb9 \xbelu\xbbou\xe8k\xfd k\xf9\xf2"), // Czech in windows-1250 — every byte the table remaps
    seed("\xa4\xa6\xa8\xb4\xb8\xbc\xbd\xbe"), // the eight positions where iso-8859-15 differs from -1
    seed("P\xc5\x99\xc3\xad li\xc5\xa1"), // well-formed multi-byte UTF-8, for the encode direction
    seed("ab\xc2"), // a 2-byte lead with 0 continuations, at the very end (audit edge)
    seed("ab\xe2\x82"), // a 3-byte lead with only 1 continuation (audit edge)
    seed("\x80\x80\x80"), // continuation bytes with no lead at all
    seed("\xf0\x9f\x92\xa9"), // a 4-byte sequence: unmappable in every 8-bit table
    seed("\x00\x01\x7f"), // NUL and the C0/DEL controls
    seed("\xed\xa0\x80"), // a surrogate encoded as UTF-8, which is not valid UTF-8
};

test "fuzz: decodeToUtf8 / encodeFromUtf8 never panic, OOB or leak on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzCodecNeverLeaks, .{ .corpus = &codec_seeds });
}

fn fuzzCodecNeverLeaks(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    var src: fz.ScriptSource = .{ .cur = .{ .bytes = buf[0..len] } };
    try fz.codecHarness(fz.ScriptSource, &src, std.testing.allocator);
}

const fz = @import("fuzz_test.zig");

test "corpus: every seed reaches both codecs, and the octets produced are pinned" {
    // ⭐ Octets produced is the second number, and it has to be: neither codec
    // ever errors — they are lenient by design, an unmappable byte is emitted
    // verbatim — so there is no acceptance to count and "it did not leak" was
    // already true on a harness handed nothing. Decoded and encoded octets are
    // pinned separately, and `.utf8` separately from the five table encodings,
    // because `.utf8` is the only one the drawn `enc` ever selected: if the
    // sweep ever collapses back to index 0 the table totals fall to match the
    // passthrough one, which a single number would hide.
    const a = std.testing.allocator;
    var nonempty: usize = 0;
    var utf8_decoded: usize = 0;
    var table_decoded: usize = 0;
    var table_encoded: usize = 0;
    for (codec_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        for (fuzz_encodings) |enc| {
            const decoded = try decodeToUtf8(a, buf[0..len], enc);
            defer a.free(decoded);
            const encoded = try encodeFromUtf8(a, buf[0..len], enc);
            defer a.free(encoded);
            if (enc == .utf8) {
                utf8_decoded += decoded.len;
            } else {
                table_decoded += decoded.len;
                table_encoded += encoded.len;
            }
        }
    }
    try std.testing.expectEqual(codec_seeds.len, nonempty);
    // Measured 2026-09-07: with the collapsing draw and the collapsing index,
    // 0 seeds arrived non-empty and every run was `.utf8` over an empty slice —
    // 0 / 0 / 0. After: 12 seeds, 208 / 879 / 550. 2026-10-04: 205 — the
    // `ab e2 82` seed now decodes to ONE U+FFFD (maximal subpart, WHATWG),
    // not two, which is 3 octets fewer.
    try std.testing.expectEqual(@as(usize, 205), utf8_decoded);
    try std.testing.expectEqual(@as(usize, 879), table_decoded);
    try std.testing.expectEqual(@as(usize, 550), table_encoded);
}

// ── UTF-8 / UTF-16 against CPython, streaming, fatal, BOM (2026-10-04) ─────

fn hexAlloc(alloc: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn decodeKind(alloc: std.mem.Allocator, kind: Decoder.Kind, bytes: []const u8) ![]u8 {
    return switch (kind) {
        .encoding => |e| decodeToUtf8(alloc, bytes, e),
        .utf16 => |e| decodeUtf16(alloc, bytes, e),
    };
}

/// Decode through the streaming decoder with `bytes` cut at `cut` (and
/// byte by byte when `cut` is null).
fn decodeSplit(alloc: std.mem.Allocator, kind: Decoder.Kind, bytes: []const u8, cut: ?usize) ![]u8 {
    var d: Decoder = .init(kind, .{});
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    if (cut) |c| {
        try d.feed(alloc, &out, bytes[0..c]);
        try d.feed(alloc, &out, bytes[c..]);
    } else for (bytes) |b| try d.feed(alloc, &out, &.{b});
    try d.finish(alloc, &out);
    return out.toOwnedSlice(alloc);
}

test "UTF-8 / UTF-16 decode and UTF-16 encode agree with CPython's codecs on every golden case" {
    // `tools/codec-oracle.py` wrote these from CPython (errors="replace",
    // maximal subparts — the WHATWG rule): valid sequences of every length,
    // truncations, overlongs, encoded surrogates, lone/swapped surrogates, odd
    // lengths and random bytes. Each case is also decoded through the
    // streaming decoder at every split point and byte by byte, and in fatal
    // mode, which must fail exactly when CPython's strict decode does.
    const a = testing.allocator;
    var lines = std.mem.splitScalar(u8, @embedFile("testdata/codec_golden.txt"), '\n');
    var n_dec: usize = 0;
    var n_bad: usize = 0;
    var n_enc: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var f = std.mem.splitScalar(u8, line, '\t');
        const codec = f.next().?;
        const input = try hexAlloc(a, f.next().?);
        defer a.free(input);
        const want = try hexAlloc(a, f.next().?);
        defer a.free(want);
        const strict = std.mem.eql(u8, f.next().?, "1");

        if (std.mem.startsWith(u8, codec, "enc-")) {
            const e: Utf16Endian = if (std.mem.endsWith(u8, codec, "le")) .le else .be;
            const got = try encodeUtf16(a, input, e, false);
            defer a.free(got);
            try testing.expectEqualSlices(u8, want, got);
            n_enc += 1;
            continue;
        }
        const kind: Decoder.Kind = if (std.mem.eql(u8, codec, "utf-8"))
            .{ .encoding = .utf8 }
        else if (std.mem.eql(u8, codec, "utf-16le")) .{ .utf16 = .le } else .{ .utf16 = .be };

        const got = try decodeKind(a, kind, input);
        defer a.free(got);
        try testing.expectEqualSlices(u8, want, got);
        for (0..input.len + 1) |cut| {
            const s = try decodeSplit(a, kind, input, cut);
            defer a.free(s);
            try testing.expectEqualSlices(u8, want, s);
        }
        const bb = try decodeSplit(a, kind, input, null);
        defer a.free(bb);
        try testing.expectEqualSlices(u8, want, bb);

        if (decodeFatal(a, input, kind)) |ok| {
            defer a.free(ok);
            try testing.expect(strict);
            try testing.expectEqualSlices(u8, want, ok);
        } else |err| {
            try testing.expectEqual(error.Malformed, err);
            try testing.expect(!strict);
            n_bad += 1;
        }
        n_dec += 1;
    }
    // Both outcomes in bulk, for all three codecs, or the file is not what it was.
    try testing.expect(n_dec > 4500);
    try testing.expect(n_bad > 3500);
    try testing.expect(n_enc > 1000);
}

test "UTF-8 replacement is per maximal subpart (WHATWG), and delimiters survive" {
    // Hand-checked against the Standard's UTF-8 decoder: `e2 82` is one
    // unfinished sequence; `f0 80`: 80 is outside f0's 90..bf, so f0 alone is
    // an error and both 80s are lone continuations; `ed a0`: a0 is outside
    // ed's 80..9f (it would encode a surrogate).
    try expectDecode(.utf8, "a\xe2\x82,b", "a\u{FFFD},b");
    try expectDecode(.utf8, "\xf0\x80\x80", "\u{FFFD}\u{FFFD}\u{FFFD}");
    try expectDecode(.utf8, "\xed\xa0\x80", "\u{FFFD}\u{FFFD}\u{FFFD}");
    try expectDecode(.utf8, "\xf0\x9f\x98", "\u{FFFD}");
    try expectDecode(.utf8, "\xf4\x90\x80\x80", "\u{FFFD}" ** 4);
    try expectDecode(.utf8, "\xe2\x82\xac\xe2\x82", "\u{20AC}\u{FFFD}");
}

test "UTF-16: surrogate handling by hand" {
    const a = testing.allocator;
    const Case = struct { []const u8, Utf16Endian, []const u8 };
    for ([_]Case{
        .{ "A\x00", .le, "A" },
        .{ "\x00A", .be, "A" },
        .{ "\x3d\xd8\x00\xde", .le, "\u{1F600}" }, // D83D DE00
        .{ "\x00\xd8A\x00", .le, "\u{FFFD}A" }, // lead + non-trail: error, unit re-read
        .{ "\x00\xd8\x00\xd8\x00\xdc", .le, "\u{FFFD}\u{10000}" },
        .{ "\x00\xdc", .le, "\u{FFFD}" }, // lone trail
        .{ "A\x00B", .le, "A\u{FFFD}" }, // odd final byte
        .{ "\x00\xd8", .le, "\u{FFFD}" }, // lead at end
        .{ "\x00\xd8A", .le, "\u{FFFD}" }, // lead + odd byte at end: one error (Standard: both pending, one error)
    }) |c| {
        const got = try decodeUtf16(a, c[0], c[1]);
        defer a.free(got);
        try testing.expectEqualStrings(c[2], got);
    }
}

test "BOM: sniffed, removed, and it overrides the fallback" {
    const a = testing.allocator;
    try testing.expectEqual(@as(?Bom, .utf8), sniffBom("\xef\xbb\xbfx"));
    try testing.expectEqual(@as(?Bom, .utf16le), sniffBom("\xff\xfex\x00"));
    try testing.expectEqual(@as(?Bom, .utf16be), sniffBom("\xfe\xff\x00x"));
    try testing.expectEqual(@as(?Bom, null), sniffBom("\xef\xbb"));
    try testing.expectEqual(@as(?Bom, null), sniffBom(""));

    // An Excel "Unicode Text" export: UTF-16LE with BOM, declared windows-1250.
    const xl = "\xff\xfe" ++ "P\x00\x59\x01\xed\x00,\x00\n\x00";
    const d = try decode(a, xl, .windows_1250);
    defer a.free(d.text);
    try testing.expectEqual(@as(?Bom, .utf16le), d.bom);
    try testing.expectEqualStrings("P\u{159}\u{ed},\n", d.text);
    // UTF-8 BOM removed.
    const d8 = try decode(a, "\xef\xbb\xbfa,b", .windows_1250);
    defer a.free(d8.text);
    try testing.expectEqualStrings("a,b", d8.text);
    // No BOM: the fallback decides (0xF8 is ř in windows-1250).
    const dl = try decode(a, "\xf8", .windows_1250);
    defer a.free(dl.text);
    try testing.expectEqual(@as(?Bom, null), dl.bom);
    try testing.expectEqualStrings("\u{159}", dl.text);
}

test "encodeUtf16: BOM, surrogate pairs, round trip" {
    const a = testing.allocator;
    const le = try encodeUtf16(a, "A\u{1F600}", .le, true);
    defer a.free(le);
    try testing.expectEqualSlices(u8, "\xff\xfeA\x00\x3d\xd8\x00\xde", le);
    const be = try encodeUtf16(a, "A\u{1F600}", .be, false);
    defer a.free(be);
    try testing.expectEqualSlices(u8, "\x00A\xd8\x3d\xde\x00", be);
    // U+10000 is the first codepoint that needs a pair: D800 DC00 (mutation
    // 2026-10-04: `cp > 0x10000` survived — nothing encoded the boundary).
    const first_pair = try encodeUtf16(a, "\u{10000}\u{FFFF}", .le, false);
    defer a.free(first_pair);
    try testing.expectEqualSlices(u8, "\x00\xd8\x00\xdc\xff\xff", first_pair);
    const back = try decode(a, le, .utf8);
    defer a.free(back.text);
    try testing.expectEqualStrings("A\u{1F600}", back.text);
}

test "Decoder: fatal stops at the first error and stays failed; lenient is reusable after finish" {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(a);
    var d: Decoder = .init(.{ .encoding = .utf8 }, .{ .fatal = true });
    try d.feed(a, &out, "ok");
    try testing.expectError(error.Malformed, d.feed(a, &out, "\xff"));
    try testing.expectError(error.Malformed, d.feed(a, &out, "more"));
    try testing.expectError(error.Malformed, d.finish(a, &out));
    try testing.expectEqualStrings("ok", out.items);
    // A truncated sequence is only an error at finish.
    out.clearRetainingCapacity();
    var t: Decoder = .init(.{ .encoding = .utf8 }, .{ .fatal = true });
    try t.feed(a, &out, "\xe2\x82");
    try testing.expectError(error.Malformed, t.finish(a, &out));
    // Lenient: finish flushes the pending sequence and resets.
    out.clearRetainingCapacity();
    var l: Decoder = .init(.{ .utf16 = .le }, .{});
    try l.feed(a, &out, "A");
    try l.finish(a, &out);
    try l.feed(a, &out, "B\x00");
    try l.finish(a, &out);
    try testing.expectEqualStrings("\u{FFFD}B", out.items);
    // Single-byte pages cannot be malformed: fatal == lenient.
    const all = comptime blk: {
        var b: [256]u8 = undefined;
        for (&b, 0..) |*x, i| x.* = i;
        break :blk b;
    };
    const f = try decodeFatal(a, &all, .{ .encoding = .windows_1250 });
    defer a.free(f);
    const g = try decodeToUtf8(a, &all, .windows_1250);
    defer a.free(g);
    try testing.expectEqualStrings(g, f);
}

test "Encoding stays ASCII-compatible: UTF-16 is not one of its members" {
    // bxp transcodes CSV cell by cell and writes delimiters as raw bytes, which
    // is only sound because every `Encoding` maps bytes < 0x80 to ASCII.
    inline for (@typeInfo(Encoding).@"enum".fields) |f| {
        const e: Encoding = @enumFromInt(f.value);
        const got = try decodeToUtf8(testing.allocator, ",;\"\r\n", e);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(",;\"\r\n", got);
    }
    try testing.expect(Encoding.parse("utf-16le") == null);
    try testing.expect(Encoding.parse("utf-16") == null);
}
