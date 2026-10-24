// SPDX-License-Identifier: MIT
//! encoding — legacy single-byte code page ↔ UTF-8 conversion (every
//! WHATWG single-byte encoding since 2026-10-20, plus `x-user-defined` and the
//! DOS pages CP437/CP850/CP852), plus UTF-16 and UTF-32, BOM sniffing,
//! streaming decoder and encoder over a caller-buffer core (`core.zig`), a
//! fatal mode, `mem`-style helpers and a public custom-page constructor
//! (`Custom`). Lenient by default.
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
const core = @import("core.zig");
const sb = @import("sb_tables.zig");

/// The WHATWG CJK encodings (Shift_JIS, EUC-JP, ISO-2022-JP, EUC-KR,
/// gb18030, GBK, Big5) — a separate API, compiled only when referenced, so
/// a program that never uses them carries none of their ~300 KB of tables.
pub const cjk = @import("cjk.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Text decoding to and from UTF-8: every WHATWG single-byte code page plus DOS CP437/850/852 and custom pages, UTF-8, UTF-16 and UTF-32 with BOM sniffing, streaming decoder and encoder, caller-buffer API, unmappable modes, fatal mode (WHATWG semantics).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{ .linux64, .windows },
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "WHATWG Encoding Standard / encoding_rs (single-byte, UTF-8, UTF-16)",
    .deps = .{},
};

/// Supported text encodings for input / output. `utf8` is the default and a
/// pure pass-through. The rest are single-byte code pages: the first five in
/// the order they were added (their tags are stable), then, since
/// 2026-10-20, every other single-byte encoding of the WHATWG Encoding
/// Standard, then `x-user-defined` and three DOS pages (2026-10-20, R11/R12).
/// Every member is ASCII-compatible.
pub const Encoding = enum {
    utf8,
    windows_1250, // Central European (Czech, Polish, Hungarian, …)
    windows_1252, // Western European
    iso_8859_1, // Latin-1 (Western European) — this module's own, see `parse`
    iso_8859_2, // Latin-2 (Central European)
    iso_8859_15, // Latin-9 (Latin-1 + €, Š, Ž, Œ, Ÿ)
    ibm866,
    iso_8859_3,
    iso_8859_4,
    iso_8859_5,
    iso_8859_6,
    iso_8859_7,
    iso_8859_8,
    iso_8859_8_i,
    iso_8859_10,
    iso_8859_13,
    iso_8859_14,
    iso_8859_16,
    koi8_r,
    koi8_u,
    macintosh,
    windows_874,
    windows_1251,
    windows_1253,
    windows_1254,
    windows_1255,
    windows_1256,
    windows_1257,
    windows_1258,
    x_mac_cyrillic,
    /// WHATWG `x-user-defined` (legacy XHR binary hack): byte 0x80..0xFF is
    /// U+F780..U+F7FF, a private-use range, so every byte round-trips.
    x_user_defined,
    /// IBM PC / MS-DOS code pages, not WHATWG encodings (labels: IANA's).
    /// Named by their IANA names (`IBM437`, …); the high half is Unicode.org's
    /// MICSFT/PC mapping (all 128 bytes defined, the low half is ASCII).
    cp437, // DOS Latin US (legacy ZIP names)
    cp850, // DOS Latin 1 (Western European)
    cp852, // DOS Latin 2 (Czech, Polish, Hungarian, …)

    /// Parse a config string into an Encoding. Case-insensitive, and leading
    /// and trailing ASCII whitespace is stripped first (WHATWG "get an
    /// encoding" step 1 — a label read off a CRLF-terminated ini or CSV
    /// header line arrives with a `\r` on it, and used to return null).
    /// Every WHATWG label of an encoding this enum has is accepted, plus a
    /// few common spellings WHATWG lacks (`win1250`, `latin-2`, …). Returns
    /// null on no match so the caller can emit a did-you-mean style warning;
    /// `lookupLabel` says whether an unknown label names an encoding this
    /// module does not have (UTF-16, CJK, `replacement`).
    ///
    /// **One deliberate departure** from WHATWG: WHATWG maps the labels
    /// `iso-8859-1`, `iso8859-1`, `latin1` and friends to the
    /// **windows-1252** encoding, because that is what the web actually
    /// contains. This module has a distinct `iso_8859_1` — the true ISO/IEC
    /// 8859-1 page, identity high half — and those labels select it. The
    /// consequence is real and worth knowing before you rely on either
    /// behaviour: `93 71 75 6f 74 65 64 94` decodes here to a C1 control,
    /// `“quoted”` in a browser. Choose `.windows_1252` explicitly for
    /// web-sourced data.
    pub fn parse(raw: []const u8) ?Encoding {
        return switch (lookupLabel(raw) orelse return null) {
            .encoding => |e| e,
            else => null,
        };
    }

    /// Canonical config string for this encoding: the WHATWG name in lower
    /// case (`windows-1250`, `iso-8859-8-i`, `utf-8`) — what this function
    /// has always returned for the first six members.
    pub fn canonicalName(self: Encoding) []const u8 {
        return switch (self) {
            inline else => |e| comptime blk: {
                @setEvalBranchQuota(10_000);
                const name = whatwgNameOf(e);
                var buf: [name.len]u8 = undefined;
                _ = std.ascii.lowerString(&buf, name);
                const final = buf;
                break :blk &final;
            },
        };
    }

    /// The WHATWG name with the Standard's capitalisation (`UTF-8`,
    /// `ISO-8859-2`, `windows-1250`, `KOI8-R`) — encoding_rs `name()`.
    /// `iso_8859_1` is not a WHATWG encoding; it answers `ISO-8859-1`.
    pub fn whatwgName(self: Encoding) []const u8 {
        return switch (self) {
            inline else => |e| comptime whatwgNameOf(e),
        };
    }

    /// One byte per character (everything but UTF-8).
    pub fn isSingleByte(self: Encoding) bool {
        return self != .utf8;
    }

    /// Every member is: bytes below 0x80 are ASCII in all of them.
    pub fn isAsciiCompatible(self: Encoding) bool {
        _ = self;
        return true;
    }

    /// Can every Unicode scalar value be encoded (only UTF-8)?
    pub fn canEncodeEverything(self: Encoding) bool {
        return self == .utf8;
    }

    /// The single-byte page, for any member but `utf8`.
    fn page(comptime self: Encoding) type {
        return core.SingleByte(@field(sb, @tagName(self) ++ "_decode"));
    }
};

fn whatwgNameOf(comptime e: Encoding) []const u8 {
    if (e == .utf8) return "UTF-8";
    if (e == .iso_8859_1) return "ISO-8859-1";
    return @field(sb, @tagName(e) ++ "_canonical_name");
}

/// What a label names, per the WHATWG "get an encoding" table.
pub const LabelTarget = union(enum) {
    /// A member of `Encoding`.
    encoding: Encoding,
    /// UTF-16 — a real encoding, deliberately outside `Encoding` (not
    /// ASCII-compatible): use `decodeUtf16`/`encodeUtf16` or a `Decoder`.
    utf16: Utf16Endian,
    /// The WHATWG `replacement` encoding (ISO-2022-KR, HZ-GB-2312, …): a
    /// security measure, it decodes any non-empty input to one U+FFFD — see
    /// `decodeReplacement`.
    replacement,
    /// A CJK multi-byte encoding: not ASCII-compatible (trail bytes in
    /// 0x40–0x7E), so outside `Encoding` — use `encoding.cjk`.
    cjk: cjk.Cjk,
};

/// Common spellings WHATWG lacks, kept from this module's original label
/// set so a config written against it still parses.
const extra_labels = [_]struct { []const u8, Encoding }{
    .{ "windows1250", .windows_1250 },
    .{ "win1250", .windows_1250 },
    .{ "windows1252", .windows_1252 },
    .{ "win1252", .windows_1252 },
    .{ "latin-1", .iso_8859_1 },
    .{ "latin-2", .iso_8859_2 },
    .{ "iso-ir-203", .iso_8859_15 },
    .{ "latin-9", .iso_8859_15 },
    .{ "latin9", .iso_8859_15 },
};

/// The WHATWG "get an encoding" lookup: trim ASCII whitespace, compare
/// case-insensitively against every label of the Standard (plus the
/// module's extra spellings and the IANA labels of the DOS pages — `cp437`,
/// `ibm437`, `437`, `cspc8codepage437`, `cp850`, `ibm850`, `850`,
/// `cspc850multilingual`, `cp852`, `ibm852`, `852`, `cspcp852` — which the
/// Standard does not have). Null for a label nobody knows.
pub fn lookupLabel(raw: []const u8) ?LabelTarget {
    const s = std.mem.trim(u8, raw, " \t\n\r\x0c");
    var buf: [64]u8 = undefined;
    if (s.len > buf.len) return null;
    const low = std.ascii.lowerString(&buf, s);
    if (sb.lookupLabel(low)) |t| return switch (t) {
        .page => |p| .{ .encoding = switch (p) {
            inline else => |tag| @field(Encoding, @tagName(tag)),
        } },
        .utf8 => .{ .encoding = .utf8 },
        .utf16le => .{ .utf16 = .le },
        .utf16be => .{ .utf16 = .be },
        .replacement => .replacement,
        .unsupported => |name| blk: {
            inline for (comptime std.enums.values(cjk.Cjk)) |c| {
                if (std.mem.eql(u8, name, c.whatwgName())) break :blk .{ .cjk = c };
            }
            unreachable; // the generator names only the seven CJK encodings
        },
    };
    for (extra_labels) |x| if (std.mem.eql(u8, x[0], low)) return .{ .encoding = x[1] };
    return null;
}

/// The WHATWG `replacement` decoder: empty input decodes to nothing, any
/// other input to exactly one U+FFFD (so content in a label-smuggled
/// encoding can never be read as text). Caller owns the result.
pub fn decodeReplacement(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return alloc.dupe(u8, if (bytes.len == 0) "" else replacement_char);
}

/// U+FFFD in UTF-8.
pub const replacement_char = "\u{FFFD}";

/// What a single-byte encoder writes for a character the page lacks
/// (`?` by default; `&#NNNN;`, nothing, or a refusal).
pub const Unmappable = core.Unmappable;

/// Why a caller-buffer call returned, and how far it got.
pub const Progress = core.Progress;
pub const Status = core.Status;
pub const EncodeProgress = core.EncodeProgress;
pub const EncodeStatus = core.EncodeStatus;

/// Copy `bytes`, replacing malformed UTF-8 with U+FFFD exactly as the WHATWG
/// Encoding Standard's UTF-8 decoder does: one U+FFFD per MAXIMAL SUBPART of an
/// ill-formed sequence (Unicode's recommended practice, also Python's
/// `errors="replace"`) — `e2 82` truncated is ONE U+FFFD, `f0 80 80` is three
/// (`80` cannot follow `f0`). Until 2026-10-04 this replaced byte by byte
/// (two for `e2 82`) while the doc said "WHATWG". Either way a byte that
/// cannot continue a sequence is re-read on its own, so an ASCII delimiter
/// after bad input is never swallowed.
fn sanitizeUtf8(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var d: Decoder = .init(.{ .encoding = .utf8 }, .{});
    return d.decodeAll(alloc, bytes) catch |e| lenientOnly(e);
}

/// A lenient decoder never reports `Malformed`; only allocation can fail.
fn lenientOnly(e: Decoder.Error) error{OutOfMemory} {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Malformed => unreachable,
    };
}

/// Decode `bytes` in `enc` into a freshly allocated **valid UTF-8** string.
/// ASCII bytes (< 0x80) always pass through unchanged. Caller owns the
/// returned slice.
///
/// A single-byte page's byte that the Standard leaves undefined (windows-1253
/// has a few, ISO-8859-8 many) decodes to U+FFFD; every other byte maps to a
/// code point (pinned against the vendored WHATWG indexes by
/// `sb_tables_test.zig`), so the output is valid UTF-8 for every encoding.
/// For `.utf8` it used to be a verbatim dupe — and `.utf8` is the enum's
/// first member, the one `Encoding.parse` yields for an absent or unknown
/// declaration, and the one the README calls the default. So a function
/// named `decodeToUtf8` handed hostile bytes straight through on its
/// most-taken path: a lone `0xFF`, a truncated `e2 82`, a surrogate `ed a0
/// 80` and an overlong `c0 af` all came out unchanged, and a downstream
/// `Utf8View` or JSON emitter met them believing otherwise. Malformed input
/// is now replaced with U+FFFD, which is what the WHATWG Encoding Standard's
/// own decode algorithm does — the standard this module names as its model —
/// so the guarantee is unconditional. Well-formed UTF-8 is unchanged.
pub fn decodeToUtf8(alloc: std.mem.Allocator, bytes: []const u8, enc: Encoding) ![]u8 {
    var d: Decoder = .init(.{ .encoding = enc }, .{});
    return d.decodeAll(alloc, bytes) catch |e| lenientOnly(e);
}

/// Encode a UTF-8 string into legacy `enc` bytes. For `.utf8` this is a
/// verbatim dupe. A codepoint with no representation in the target code page
/// becomes '?' (single byte); invalid UTF-8 bytes pass through verbatim.
/// Caller owns the returned slice. `encodeFromUtf8Opts` chooses the
/// substitute (or a refusal).
pub fn encodeFromUtf8(alloc: std.mem.Allocator, utf8: []const u8, enc: Encoding) ![]u8 {
    return encodeFromUtf8Opts(alloc, utf8, enc, .{}) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Unmappable => unreachable, // only with `.fatal`
    };
}

/// `encodeFromUtf8` with the unmappable-character mode: `.question_mark`
/// (the default), `.ignore`, `.html_ncr` (`&#NNNN;`) or `.fatal`
/// (`error.Unmappable`; `Encoder.encodeInto` reports the code point).
pub fn encodeFromUtf8Opts(alloc: std.mem.Allocator, utf8: []const u8, enc: Encoding, opts: Encoder.Options) Encoder.Error![]u8 {
    var e: Encoder = .init(.{ .encoding = enc }, opts);
    return e.encodeAll(alloc, utf8);
}

// ── UTF-16, BOM sniffing, streaming and fatal decoding (2026-10-04) ─────────
//
// UTF-16 is deliberately NOT a member of `Encoding`. Every `Encoding` is
// ASCII-compatible: a byte below 0x80 is that ASCII character in every one,
// which is what lets a caller transcode a CSV cell by cell and write its
// delimiters as plain bytes (bxp does). UTF-16 breaks that — `,` is `2c 00` —
// so it gets its own entry points and cannot be picked by accident through
// `Encoding.parse` or an enum listing.

pub const Utf16Endian = core.Endian;
/// Byte order of UTF-32 (the same type as `Utf16Endian`). UTF-32 is outside
/// `Encoding` for the same reason UTF-16 is, and is not WHATWG at all.
pub const Utf32Endian = core.Endian;

/// What a byte-order mark at the start of a buffer says.
pub const Bom = enum {
    utf8, // ef bb bf
    utf16le, // ff fe
    utf16be, // fe ff
    /// Only `sniffBom32` returns these two.
    utf32le, // ff fe 00 00
    utf32be, // 00 00 fe ff

    pub fn len(self: Bom) usize {
        return switch (self) {
            .utf8 => 3,
            .utf16le, .utf16be => 2,
            .utf32le, .utf32be => 4,
        };
    }
};

/// The BOM `bytes` starts with, if any (WHATWG "BOM sniff"): UTF-8 or UTF-16
/// only. Note that a UTF-32LE BOM (`ff fe 00 00`) sniffs as UTF-16LE, as in
/// the Standard; `sniffBom32` is the variant that knows UTF-32.
pub fn sniffBom(bytes: []const u8) ?Bom {
    if (std.mem.startsWith(u8, bytes, "\xef\xbb\xbf")) return .utf8;
    if (std.mem.startsWith(u8, bytes, "\xff\xfe")) return .utf16le;
    if (std.mem.startsWith(u8, bytes, "\xfe\xff")) return .utf16be;
    return null;
}

/// `sniffBom` that also recognises the UTF-32 BOMs (Python's `utf-32`, x/text's
/// `utf32`): `ff fe 00 00` is UTF-32LE and `00 00 fe ff` UTF-32BE, tested
/// BEFORE UTF-16 — so UTF-16LE text that starts with U+0000 right after its BOM
/// (`ff fe 00 00`) is read as UTF-32LE here, the unavoidable ambiguity the
/// Standard avoids by not having UTF-32. Use it only when UTF-32 input is
/// possible; `sniffBom`/`decode` keep the WHATWG answer.
pub fn sniffBom32(bytes: []const u8) ?Bom {
    if (std.mem.startsWith(u8, bytes, "\xff\xfe\x00\x00")) return .utf32le;
    if (std.mem.startsWith(u8, bytes, "\x00\x00\xfe\xff")) return .utf32be;
    return sniffBom(bytes);
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
    return decodeBom(alloc, bytes, fallback, sniffBom(bytes));
}

/// `decode` that also honours a UTF-32 BOM (`sniffBom32`): Python `utf-32`
/// semantics layered on the WHATWG algorithm. Without a BOM `fallback` decides.
pub fn decode32(alloc: std.mem.Allocator, bytes: []const u8, fallback: Encoding) !Decoded {
    return decodeBom(alloc, bytes, fallback, sniffBom32(bytes));
}

fn decodeBom(alloc: std.mem.Allocator, bytes: []const u8, fallback: Encoding, bom: ?Bom) !Decoded {
    if (bom) |b| {
        const rest = bytes[b.len()..];
        const text = switch (b) {
            .utf8 => try sanitizeUtf8(alloc, rest),
            .utf16le => try decodeUtf16(alloc, rest, .le),
            .utf16be => try decodeUtf16(alloc, rest, .be),
            .utf32le => try decodeUtf32(alloc, rest, .le),
            .utf32be => try decodeUtf32(alloc, rest, .be),
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
    return d.decodeAll(alloc, bytes) catch |e| lenientOnly(e);
}

/// Encode UTF-8 as UTF-16 (`bom`: prepend `ff fe` / `fe ff`). Malformed UTF-8
/// becomes U+FFFD (maximal subparts, as the decoder) — unlike the single-byte
/// encoders it cannot pass a stray byte through, UTF-16 has no byte to keep.
/// Caller owns the result.
pub fn encodeUtf16(alloc: std.mem.Allocator, utf8: []const u8, endian: Utf16Endian, bom: bool) ![]u8 {
    var e: Encoder = .init(.{ .utf16 = endian }, .{ .bom = bom });
    return e.encodeAll(alloc, utf8) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Unmappable => unreachable, // UTF-16 encodes everything
    };
}

/// Decode UTF-32 (no BOM handling — see `decode32`) into valid UTF-8: a value
/// above U+10FFFF or a surrogate is one U+FFFD, and so are the 1 to 3 bytes of a
/// unit cut by the end — one per unit, exactly CPython's `utf-32` decoder with
/// `errors="replace"` (checked against CPython 3 in `extra_test.zig`'s golden
/// cases). Caller owns the result.
pub fn decodeUtf32(alloc: std.mem.Allocator, bytes: []const u8, endian: Utf32Endian) ![]u8 {
    var d: Decoder = .init(.{ .utf32 = endian }, .{});
    return d.decodeAll(alloc, bytes) catch |e| lenientOnly(e);
}

/// Encode UTF-8 as UTF-32 (`bom`: prepend `ff fe 00 00` / `00 00 fe ff`).
/// Malformed UTF-8 becomes U+FFFD (maximal subparts, as the decoder).
/// Caller owns the result.
pub fn encodeUtf32(alloc: std.mem.Allocator, utf8: []const u8, endian: Utf32Endian, bom: bool) ![]u8 {
    var e: Encoder = .init(.{ .utf32 = endian }, .{ .bom = bom });
    return e.encodeAll(alloc, utf8) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Unmappable => unreachable, // UTF-32 encodes everything
    };
}

/// Whole-buffer decode in FATAL mode (WHATWG `fatal`): `error.Malformed` at
/// the first ill-formed sequence instead of U+FFFD — for a single-byte page,
/// at a byte the Standard leaves undefined.
pub fn decodeFatal(alloc: std.mem.Allocator, bytes: []const u8, kind: Decoder.Kind) Decoder.Error![]u8 {
    var d: Decoder = .init(kind, .{ .fatal = true });
    return d.decodeAll(alloc, bytes);
}

/// Streaming decoder: feed input in chunks of any size — a multi-byte UTF-8
/// sequence or a UTF-16 unit / surrogate pair split across chunks is carried
/// over — and call `finish` at the end of the stream. The output is the same
/// as decoding the concatenation in one call (tested at every split point).
/// State is a few bytes; no allocation beyond `out`. `decodeInto` is the
/// caller-buffer form (encoding_rs `decode_to_utf8`), which allocates nothing.
pub const Decoder = struct {
    kind: Kind,
    fatal: bool,
    utf8: core.Utf8State = .{},
    utf16: core.Utf16State = .{},
    utf32: core.Utf32State = .{},
    /// Set once `fatal` reported an error; the decoder refuses further input.
    failed: bool = false,

    pub const Kind = union(enum) {
        /// Any `Encoding` (UTF-8 or a single-byte page).
        encoding: Encoding,
        utf16: Utf16Endian,
        utf32: Utf32Endian,
    };
    pub const Options = struct {
        /// `error.Malformed` instead of U+FFFD (WHATWG `fatal`).
        fatal: bool = false,
    };
    pub const Error = std.mem.Allocator.Error || error{Malformed};

    pub fn init(kind: Kind, opts: Options) Decoder {
        return .{ .kind = kind, .fatal = opts.fatal };
    }

    /// An output size that always takes all of `n` input bytes (plus the
    /// state carried in) in one `decodeInto` call: 3 bytes per input byte
    /// (a high byte or an invalid one becomes up to 3) and room for the
    /// pending sequence and the per-step headroom.
    pub fn maxUtf8Len(self: *const Decoder, n: usize) usize {
        _ = self;
        return n *| 3 +| 8;
    }

    /// Decode `src` into `dst`. `last`: the end of `src` is the end of the
    /// stream. On `.output_full`, call again with `src[read..]` and room;
    /// on `.malformed` (fatal only) the decoder has failed. After a `last`
    /// call that consumed everything the decoder is reset for reuse.
    pub fn decodeInto(self: *Decoder, src: []const u8, dst: []u8, last: bool) Progress {
        if (self.failed) return .{ .status = .malformed, .read = 0, .written = 0 };
        const p: Progress = switch (self.kind) {
            .encoding => |enc| switch (enc) {
                .utf8 => core.decodeUtf8(&self.utf8, src, dst, last, self.fatal),
                inline else => |e| Encoding.page(e).decodeToUtf8(src, dst, self.fatal),
            },
            .utf16 => |endian| switch (endian) {
                inline else => |e| core.decodeUtf16(e, &self.utf16, src, dst, last, self.fatal),
            },
            .utf32 => |endian| switch (endian) {
                inline else => |e| core.decodeUtf32(e, &self.utf32, src, dst, last, self.fatal),
            },
        };
        if (p.status == .malformed) self.failed = true;
        if (last and p.status == .input_empty) self.* = .init(self.kind, .{ .fatal = self.fatal });
        return p;
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

    /// The whole of `bytes` decoded into one allocation sized close to the
    /// result (grown only if the text is denser than the first guess).
    fn decodeAll(self: *Decoder, alloc: std.mem.Allocator, bytes: []const u8) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        // Valid UTF-8 decodes to itself, so its first guess is exact; a
        // single-byte page or UTF-16 grows, so it gets a margin.
        const first = switch (self.kind) {
            .encoding => |e| if (e == .utf8) bytes.len +| 8 else bytes.len +| bytes.len / 4 +| 16,
            .utf16 => bytes.len +| bytes.len / 2 +| 16,
            .utf32 => bytes.len +| 16,
        };
        try out.ensureTotalCapacity(alloc, first);
        var r: usize = 0;
        while (true) {
            const p = self.decodeInto(bytes[r..], out.unusedCapacitySlice(), true);
            out.items.len += p.written;
            r += p.read;
            switch (p.status) {
                .input_empty => break,
                .output_full => try out.ensureUnusedCapacity(alloc, self.maxUtf8Len(bytes.len - r)),
                .malformed => return error.Malformed,
            }
        }
        return out.toOwnedSlice(alloc);
    }
};

/// Streaming encoder from UTF-8 (encoding_rs `Encoder`): into any `Encoding`
/// (a single-byte page, or UTF-8 as a verbatim copy), UTF-16 or UTF-32. A UTF-8
/// sequence split across chunks is carried over; `encodeInto` is the
/// caller-buffer form, which allocates nothing — reuse one output buffer
/// across cells instead of allocating per cell.
pub const Encoder = struct {
    kind: Kind,
    unmappable: Unmappable,
    bom: bool,
    /// The start of a UTF-8 sequence cut by the end of the previous chunk.
    pending: [4]u8 = undefined,
    pending_len: u8 = 0,
    /// UTF-16/32 target: the UTF-8 decoder's state (malformed input becomes
    /// U+FFFD) and whether the BOM is still to be written.
    utf8: core.Utf8State = .{},
    bom_due: bool = false,

    pub const Kind = Decoder.Kind;
    pub const Options = struct {
        unmappable: Unmappable = .question_mark,
        /// UTF-16/32 target only: start the output with a byte-order mark.
        bom: bool = false,
    };
    pub const Error = std.mem.Allocator.Error || error{Unmappable};

    pub fn init(kind: Kind, opts: Options) Encoder {
        return .{ .kind = kind, .unmappable = opts.unmappable, .bom = opts.bom, .bom_due = opts.bom and kind != .encoding };
    }

    /// An output size that always takes all of `n` input bytes in one
    /// `encodeInto` call.
    pub fn maxEncodedLen(self: *const Encoder, n: usize) usize {
        const per: usize = switch (self.kind) {
            .utf16 => 2, // 1 byte -> 1 unit; 4 bytes -> 2 units
            .utf32 => 4, // 1 byte -> 1 unit
            .encoding => |e| if (e == .utf8) 1 else if (self.unmappable == .html_ncr) core.max_substitute else 1,
        };
        return n *| per +| core.max_substitute +| 8;
    }

    /// Encode `src` into `dst`. `last`: the end of `src` is the end of the
    /// stream (a cut sequence's bytes then pass through, or become U+FFFD
    /// for UTF-16). On `.output_full`, call again with `src[read..]`; on
    /// `.unmappable` (fatal mode), `code_point` is the character and `read`
    /// stops before it.
    pub fn encodeInto(self: *Encoder, src: []const u8, dst: []u8, last: bool) EncodeProgress {
        var r: usize = 0;
        var w: usize = 0;
        var replaced = false;
        if (self.bom_due) {
            switch (self.kind) {
                .utf16 => |e| {
                    if (dst.len < 2) return .{ .status = .output_full, .read = 0, .written = 0 };
                    const bom: u16 = 0xFEFF;
                    dst[0] = if (e == .le) @truncate(bom) else @truncate(bom >> 8);
                    dst[1] = if (e == .le) @truncate(bom >> 8) else @truncate(bom);
                    w = 2;
                },
                .utf32 => |e| {
                    if (dst.len < 4) return .{ .status = .output_full, .read = 0, .written = 0 };
                    dst[0..4].* = if (e == .le) .{ 0xFF, 0xFE, 0, 0 } else .{ 0, 0, 0xFE, 0xFF };
                    w = 4;
                },
                .encoding => unreachable, // `bom` only applies to UTF-16/32 targets
            }
            self.bom_due = false;
        }
        // Complete a sequence cut by the end of the previous call. Only a
        // single-byte target leaves one (the UTF-16 target carries it in
        // its decoder state); its first byte is a valid lead byte.
        if (self.pending_len != 0) {
            const pl: usize = self.pending_len;
            var tmp: [4]u8 = undefined;
            @memcpy(tmp[0..pl], self.pending[0..pl]);
            const need = (std.unicode.utf8ByteSequenceLength(tmp[0]) catch unreachable) - pl;
            const take = @min(src.len, need);
            @memcpy(tmp[pl..][0..take], src[0..take]);
            const tlast = last and take == src.len;
            if (take < need and !tlast) {
                @memcpy(self.pending[pl..][0..take], src[0..take]);
                self.pending_len += @intCast(take);
                return .{ .status = .input_empty, .read = take, .written = w };
            }
            const p = self.step(tmp[0 .. pl + take], dst[w..], tlast);
            w += p.written;
            replaced = p.replaced;
            if (p.read < pl) {
                // Stopped inside the carried bytes: keep the rest of them.
                std.mem.copyForwards(u8, self.pending[0..], self.pending[p.read..pl]);
                self.pending_len = @intCast(pl - p.read);
                if (p.status == .input_empty) {
                    // A new sequence starting inside them is cut again; the
                    // bytes taken from `src` go with it.
                    @memcpy(self.pending[self.pending_len..][0..take], src[0..take]);
                    self.pending_len += @intCast(take);
                    return .{ .status = .input_empty, .read = take, .written = w, .replaced = replaced };
                }
                return .{ .status = p.status, .read = 0, .written = w, .replaced = replaced, .code_point = p.code_point };
            }
            self.pending_len = 0;
            // Whatever of `tmp` was not read came from `src`: read it again there.
            r = p.read - pl;
            if (p.status != .input_empty) return .{ .status = p.status, .read = r, .written = w, .replaced = replaced, .code_point = p.code_point };
        }
        const p = self.step(src[r..], dst[w..], last);
        r += p.read;
        w += p.written;
        replaced = replaced or p.replaced;
        if (p.status == .input_empty and r < src.len) {
            // A sequence cut by the end of `src`: keep it for the next call.
            const left = src.len - r;
            @memcpy(self.pending[0..left], src[r..]);
            self.pending_len = @intCast(left);
            r = src.len;
        }
        if (last and p.status == .input_empty) self.* = .init(self.kind, .{ .unmappable = self.unmappable, .bom = self.bom });
        return .{ .status = p.status, .read = r, .written = w, .replaced = replaced, .code_point = p.code_point };
    }

    fn step(self: *Encoder, src: []const u8, dst: []u8, last: bool) EncodeProgress {
        switch (self.kind) {
            .encoding => |enc| switch (enc) {
                .utf8 => {
                    const n = @min(src.len, dst.len);
                    @memcpy(dst[0..n], src[0..n]);
                    return .{ .status = if (n < src.len) .output_full else .input_empty, .read = n, .written = n };
                },
                inline else => |e| return core.encodeSingleByte(Encoding.page(e), src, dst, last, self.unmappable),
            },
            .utf16 => |endian| switch (endian) {
                inline else => |e| {
                    const p = core.utf8ToUtf16(e, &self.utf8, src, dst, last);
                    return .{ .status = if (p.status == .output_full) .output_full else .input_empty, .read = p.read, .written = p.written, .replaced = p.replaced };
                },
            },
            .utf32 => |endian| switch (endian) {
                inline else => |e| {
                    const p = core.utf8ToUtf32(e, &self.utf8, src, dst, last);
                    return .{ .status = if (p.status == .output_full) .output_full else .input_empty, .read = p.read, .written = p.written, .replaced = p.replaced };
                },
            },
        }
    }

    /// Encode `chunk`, appending to `out`. `error.Unmappable` only in
    /// `.fatal` mode.
    pub fn feed(self: *Encoder, alloc: std.mem.Allocator, out: *std.ArrayList(u8), chunk: []const u8) Error!void {
        return self.run(alloc, out, chunk, false);
    }

    /// End of stream: a cut sequence is flushed (verbatim bytes, or U+FFFD
    /// for UTF-16). The encoder is reset and may be reused.
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

    fn encodeAll(self: *Encoder, alloc: std.mem.Allocator, utf8: []const u8) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        const first = switch (self.kind) {
            .utf16 => utf8.len *| 2 +| 4,
            .utf32 => utf8.len *| 4 +| 8,
            .encoding => utf8.len +| 16,
        };
        try out.ensureTotalCapacity(alloc, first);
        var r: usize = 0;
        while (true) {
            const p = self.encodeInto(utf8[r..], out.unusedCapacitySlice(), true);
            out.items.len += p.written;
            r += p.read;
            switch (p.status) {
                .input_empty => break,
                .output_full => try out.ensureUnusedCapacity(alloc, self.maxEncodedLen(utf8.len - r)),
                .unmappable => return error.Unmappable,
            }
        }
        return out.toOwnedSlice(alloc);
    }
};

// ── `mem`-style helpers (encoding_rs `mem`, 2026-10-20) ─────────────────────

/// Length of the longest well-formed UTF-8 prefix of `s`: the index of the
/// first byte that is not part of well-formed UTF-8 (the start of an
/// ill-formed sequence, or of one cut by the end of `s`), or `s.len`. So
/// `utf8ValidUpTo(s) == s.len` iff `s` is valid. Vector fast path.
pub fn utf8ValidUpTo(s: []const u8) usize {
    return core.utf8ValidUpTo(s);
}

/// Is every byte of `s` below 0x80? (Vector.)
pub fn isAscii(s: []const u8) bool {
    return core.asciiPrefix(s) == s.len;
}

/// Length of the ASCII prefix of `s` (the index of the first byte >= 0x80, or
/// `s.len`). Vector.
pub fn asciiValidUpTo(s: []const u8) usize {
    return core.asciiPrefix(s);
}

/// ISO-8859-1 bytes to UTF-8: byte N is U+00N. This is the **identity**
/// high-half page (`Encoding.iso_8859_1`), NOT windows-1252: 0x80..0x9F are the
/// C1 controls, not `€` and curly quotes (encoding_rs `convert_latin1_to_utf8`).
/// Caller owns the result.
pub fn latin1ToUtf8(alloc: std.mem.Allocator, bytes: []const u8) ![]u8 {
    return decodeToUtf8(alloc, bytes, .iso_8859_1);
}

/// UTF-8 to ISO-8859-1 (the identity high-half page, not windows-1252), lossy:
/// a code point above U+00FF becomes `?` — NOT truncated to its low byte as
/// encoding_rs `convert_utf8_to_latin1_lossy` does — and invalid UTF-8 bytes
/// pass through verbatim (this module's encoder contract). Use
/// `encodeFromUtf8Opts` for `&#NNNN;`, dropping, or a refusal. Caller owns the
/// result.
pub fn utf8ToLatin1Lossy(alloc: std.mem.Allocator, utf8: []const u8) ![]u8 {
    return encodeFromUtf8(alloc, utf8, .iso_8859_1);
}

// ── custom single-byte pages (x/text `charmap.Charmap`, Python `charmap_build`) ──

/// A single-byte page of your own: `decode_table[i]` is the code point of byte
/// `0x80 + i`, or `0xFFFF` for a byte with no character (decodes to U+FFFD, and
/// `fatal` refuses it). Bytes below 0x80 are ASCII, as in every page of this
/// module. The result is what `Encoding.page` is for the built-in pages
/// (a `core.SingleByte`): `decodeToUtf8` / `encodeCp` / `encodeInto` are the
/// caller-buffer forms, `decodeCustom` / `encodeCustom` the allocating ones.
/// Entries below U+0080 decode but never encode (ASCII always encodes to
/// itself); when two bytes decode to one code point the FIRST one encodes it
/// (WHATWG's rule).
pub fn Custom(comptime decode_table: [128]u16) type {
    return struct {
        const Core = core.SingleByte(decode_table);

        /// The table this page was built from.
        pub const decode = decode_table;
        /// A decode-table entry with no character.
        pub const unmapped = core.unmapped;

        /// The code point of `byte`, or null when the page has none.
        pub fn decodeByte(byte: u8) ?u21 {
            if (byte < 0x80) return byte;
            const cp = decode_table[byte - 0x80];
            return if (cp == core.unmapped) null else cp;
        }

        /// The byte of `cp`, or null when the page lacks it.
        pub fn encodeCp(cp: u21) ?u8 {
            return Core.encodeCp(cp);
        }

        /// Caller-buffer decode to UTF-8; stateless (see `Decoder.decodeInto`
        /// for the contract of `Progress`). `fatal`: stop at an unmapped byte.
        pub fn decodeToUtf8(src: []const u8, dst: []u8, fatal: bool) Progress {
            return Core.decodeToUtf8(src, dst, fatal);
        }

        /// Caller-buffer encode from UTF-8 (see `Encoder.encodeInto`; `dst`
        /// needs `core.max_substitute` bytes of room per non-ASCII step).
        pub fn encodeInto(src: []const u8, dst: []u8, last: bool, mode: Unmappable) EncodeProgress {
            return core.encodeSingleByte(Core, src, dst, last, mode);
        }
    };
}

/// Decode `bytes` in the custom page `Page` (a `Custom(...)`) into valid UTF-8.
/// Lenient: an unmapped byte is U+FFFD. Caller owns the result.
pub fn decodeCustom(alloc: std.mem.Allocator, bytes: []const u8, comptime Page: type) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, bytes.len +| bytes.len / 4 +| 16);
    var r: usize = 0;
    while (true) {
        const p = Page.decodeToUtf8(bytes[r..], out.unusedCapacitySlice(), false);
        out.items.len += p.written;
        r += p.read;
        switch (p.status) {
            .input_empty => break,
            .output_full => try out.ensureUnusedCapacity(alloc, (bytes.len - r) *| 3 +| 8),
            .malformed => unreachable, // only with `fatal`
        }
    }
    return out.toOwnedSlice(alloc);
}

/// Encode UTF-8 into the custom page `Page`; `mode` as in `encodeFromUtf8Opts`
/// (`error.Unmappable` only for `.fatal`). Caller owns the result.
pub fn encodeCustom(alloc: std.mem.Allocator, utf8: []const u8, comptime Page: type, mode: Unmappable) Encoder.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.ensureTotalCapacity(alloc, utf8.len +| 16);
    var r: usize = 0;
    const per: usize = if (mode == .html_ncr) core.max_substitute else 1;
    while (true) {
        const p = Page.encodeInto(utf8[r..], out.unusedCapacitySlice(), true, mode);
        out.items.len += p.written;
        r += p.read;
        switch (p.status) {
            .input_empty => break,
            .output_full => try out.ensureUnusedCapacity(alloc, (utf8.len - r) *| per +| core.max_substitute +| 8),
            .unmappable => return error.Unmappable,
        }
    }
    return out.toOwnedSlice(alloc);
}

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
        try testing.expect(std.mem.find(u8, got, replacement_char) != null);
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
    inline for (@typeInfo(Encoding).@"enum".field_values) |fv| {
        const e: Encoding = @fromBackingInt(@intCast(fv));
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
    _ = @import("sb_tables_test.zig");
    _ = @import("core.zig");
    _ = @import("api_test.zig");
    _ = @import("utf8_simd.zig");
    _ = @import("extra_test.zig");
    _ = @import("cjk.zig");
    _ = @import("cjk_test.zig");
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

test "fuzz: the CJK codecs never panic and agree across chunking" {
    try std.testing.fuzz({}, fuzzCjk, .{});
}

fn fuzzCjk(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    const len = smith.slice(&buf);
    var src: fz.ScriptSource = .{ .cur = .{ .bytes = buf[0..len] } };
    try fz.cjkHarness(fz.ScriptSource, &src, std.testing.allocator);
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
        .utf32 => |e| decodeUtf32(alloc, bytes, e),
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
    try expectDecode(.utf8, "\xf4\x90\x80\x80", strRepeat("\u{FFFD}", 4));
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
    inline for (@typeInfo(Encoding).@"enum".field_values) |fv| {
        const e: Encoding = @fromBackingInt(@intCast(fv));
        const got = try decodeToUtf8(testing.allocator, ",;\"\r\n", e);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(",;\"\r\n", got);
    }
    try testing.expect(Encoding.parse("utf-16le") == null);
    try testing.expect(Encoding.parse("utf-16") == null);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
