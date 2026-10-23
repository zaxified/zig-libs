// SPDX-License-Identifier: MIT

//! Content sniffing: the media type of a body whose sender did not name one —
//! Go's `http.DetectContentType`. The algorithm is the WHATWG MIME Sniffing
//! standard's "rules for identifying an unknown MIME type" (§7.1) with the
//! scriptable-HTML branch on and the signature tables of §6 (images, audio and
//! video, fonts, archives), in the subset and with the result strings Go 1.26
//! returns; `go_oracle.zig` (area sniff) holds every row of the table to Go's
//! answer. Clean-room from the WHATWG text; Go is the oracle, not a source.
//!
//! Only the first `sniff_len` bytes are looked at. The answer is always one of
//! a fixed set of static strings, never a slice of the input, and nothing
//! allocates.

const std = @import("std");

/// How many leading bytes `detectContentType` considers (WHATWG §5.2's
/// resource header buffer size, and Go's).
pub const sniff_len = 512;

/// The answer when nothing matches and the bytes look binary.
pub const octet_stream = "application/octet-stream";
/// The answer when nothing matches and no binary byte occurs (also for an
/// empty body).
pub const text_plain = "text/plain; charset=utf-8";

/// The media type `data` most likely carries, as a `Content-Type` value:
/// HTML and XML (after leading whitespace), PDF, PostScript, a text byte-order
/// mark, the common image, audio, video, font and archive signatures, then
/// plain text unless a binary byte occurs, else `application/octet-stream`.
/// Never fails; a match on a prefix is a guess, not validation of the format.
pub fn detectContentType(data: []const u8) []const u8 {
    const d = data[0..@min(data.len, sniff_len)];
    const first_non_ws = std.mem.findNone(u8, d, ws) orelse d.len;
    for (signatures) |sig| {
        if (sig.matches(d, first_non_ws)) return sig.content_type;
    }
    return if (looksBinary(d)) octet_stream else text_plain;
}

/// WHATWG whitespace bytes (§3: HTAB, LF, FF, CR, SP).
const ws = "\t\n\x0c\r ";

/// WHATWG binary data bytes (§3): every C0 control except HTAB, LF, FF, CR and
/// ESC.
fn isBinaryByte(b: u8) bool {
    return b <= 0x08 or b == 0x0b or (b >= 0x0e and b <= 0x1a) or (b >= 0x1c and b <= 0x1f);
}

fn looksBinary(d: []const u8) bool {
    for (d) |b| if (isBinaryByte(b)) return true;
    return false;
}

const Signature = struct {
    content_type: []const u8,
    kind: union(enum) {
        /// The bytes at offset 0 equal `pat`.
        exact: []const u8,
        /// `byte & mask == pat` for each position; `skip_ws` starts after the
        /// leading whitespace.
        masked: struct { pat: []const u8, mask: []const u8, skip_ws: bool = false },
        /// After leading whitespace, an HTML tag (letters compared ASCII
        /// case-insensitively) followed by a tag-terminating byte (SP or `>`).
        html: []const u8,
        /// The MP4 `ftyp` box with an `mp4` brand (WHATWG §6.2.1).
        mp4,
    },

    fn matches(sig: Signature, d: []const u8, first_non_ws: usize) bool {
        switch (sig.kind) {
            .exact => |pat| return std.mem.startsWith(u8, d, pat),
            .masked => |m| {
                const s = if (m.skip_ws) d[first_non_ws..] else d;
                if (s.len < m.pat.len) return false;
                for (m.pat, m.mask, s[0..m.pat.len]) |p, k, b| if (b & k != p) return false;
                return true;
            },
            .html => |tag| {
                const s = d[first_non_ws..];
                if (s.len < tag.len + 1) return false;
                for (tag, s[0..tag.len]) |t, b| {
                    const folded = if (t >= 'A' and t <= 'Z') b & 0xdf else b;
                    if (folded != t) return false;
                }
                const tt = s[tag.len];
                return tt == ' ' or tt == '>';
            },
            .mp4 => return isMp4(d),
        }
    }
};

/// WHATWG §6.2.1 "matches the signature for MP4": a big-endian box size that
/// fits the buffer and is a multiple of 4, `ftyp`, and an `mp4` brand as the
/// major brand or a compatible brand (the minor version at offset 12 skipped).
fn isMp4(d: []const u8) bool {
    if (d.len < 12) return false;
    const box_size = std.mem.readInt(u32, d[0..4], .big);
    if (d.len < box_size or box_size % 4 != 0) return false;
    if (!std.mem.eql(u8, d[4..8], "ftyp")) return false;
    var st: usize = 8;
    while (st < box_size) : (st += 4) {
        if (st == 12) continue;
        if (std.mem.eql(u8, d[st .. st + 3], "mp4")) return true;
    }
    return false;
}

fn html(tag: []const u8) Signature {
    return .{ .content_type = "text/html; charset=utf-8", .kind = .{ .html = tag } };
}

fn exact(pat: []const u8, ct: []const u8) Signature {
    return .{ .content_type = ct, .kind = .{ .exact = pat } };
}

fn masked(pat: []const u8, mask: []const u8, ct: []const u8) Signature {
    return .{ .content_type = ct, .kind = .{ .masked = .{ .pat = pat, .mask = mask } } };
}

/// In WHATWG order: §7.1's scriptable and non-scriptable tables, then §6's
/// image (§6.1), audio/video (§6.2), font (§6.3) and archive (§6.4) tables.
/// Go adds WebAssembly at the end; so does this table.
const signatures = [_]Signature{
    html("<!DOCTYPE HTML"),
    html("<HTML"),
    html("<HEAD"),
    html("<SCRIPT"),
    html("<IFRAME"),
    html("<H1"),
    html("<DIV"),
    html("<FONT"),
    html("<TABLE"),
    html("<A"),
    html("<STYLE"),
    html("<TITLE"),
    html("<B"),
    html("<BODY"),
    html("<BR"),
    html("<P"),
    html("<!--"),
    .{ .content_type = "text/xml; charset=utf-8", .kind = .{ .masked = .{ .pat = "<?xml", .mask = "\xff\xff\xff\xff\xff", .skip_ws = true } } },
    exact("%PDF-", "application/pdf"),
    exact("%!PS-Adobe-", "application/postscript"),

    // Byte-order marks (§7.1 step 4).
    masked("\xfe\xff\x00\x00", "\xff\xff\x00\x00", "text/plain; charset=utf-16be"),
    masked("\xff\xfe\x00\x00", "\xff\xff\x00\x00", "text/plain; charset=utf-16le"),
    masked("\xef\xbb\xbf\x00", "\xff\xff\xff\x00", "text/plain; charset=utf-8"),

    // §6.1 images.
    exact("\x00\x00\x01\x00", "image/x-icon"),
    exact("\x00\x00\x02\x00", "image/x-icon"),
    exact("BM", "image/bmp"),
    exact("GIF87a", "image/gif"),
    exact("GIF89a", "image/gif"),
    masked("RIFF\x00\x00\x00\x00WEBPVP", "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff", "image/webp"),
    exact("\x89PNG\x0d\x0a\x1a\x0a", "image/png"),
    exact("\xff\xd8\xff", "image/jpeg"),

    // §6.2 audio and video.
    masked("FORM\x00\x00\x00\x00AIFF", "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff", "audio/aiff"),
    exact("ID3", "audio/mpeg"),
    exact("OggS\x00", "application/ogg"),
    exact("MThd\x00\x00\x00\x06", "audio/midi"),
    masked("RIFF\x00\x00\x00\x00AVI ", "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff", "video/avi"),
    masked("RIFF\x00\x00\x00\x00WAVE", "\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff", "audio/wave"),
    .{ .content_type = "video/mp4", .kind = .mp4 },
    exact("\x1a\x45\xdf\xa3", "video/webm"),

    // §6.3 fonts. Embedded OpenType: "LP" at offset 34.
    masked((strRepeat("\x00", 34)) ++ "LP", (strRepeat("\x00", 34)) ++ "\xff\xff", "application/vnd.ms-fontobject"),
    exact("\x00\x01\x00\x00", "font/ttf"),
    exact("OTTO", "font/otf"),
    exact("ttcf", "font/collection"),
    exact("wOFF", "font/woff"),
    exact("wOF2", "font/woff2"),

    // §6.4 archives.
    exact("\x1f\x8b\x08", "application/x-gzip"),
    exact("PK\x03\x04", "application/zip"),
    exact("Rar!\x1a\x07\x00", "application/x-rar-compressed"),
    exact("Rar!\x1a\x07\x01\x00", "application/x-rar-compressed"),

    exact("\x00asm", "application/wasm"),
};

const testing = std.testing;

test "detectContentType: one row of every table" {
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "", text_plain },
        .{ "hello", text_plain },
        .{ "\x00\x01", octet_stream },
        .{ "  \n<!doctype html><p>", "text/html; charset=utf-8" },
        .{ "<HtMl>", "text/html; charset=utf-8" },
        .{ "<html", text_plain }, // no tag-terminating byte
        .{ "<htmlx>", text_plain },
        .{ "<!-- x -->", "text/html; charset=utf-8" },
        .{ "\t<?xml version=\"1.0\"?>", "text/xml; charset=utf-8" },
        .{ "<?XML", text_plain }, // XML's signature is case-sensitive
        .{ "%PDF-1.7", "application/pdf" },
        .{ "\xef\xbb\xbfhi", "text/plain; charset=utf-8" },
        .{ "\xfe\xff\x00h", "text/plain; charset=utf-16be" },
        .{ "GIF89a", "image/gif" },
        .{ "\x89PNG\r\n\x1a\nrest", "image/png" },
        .{ "RIFF\x10\x00\x00\x00WEBPVP8 ", "image/webp" },
        .{ "RIFF\x10\x00\x00\x00WAVEfmt ", "audio/wave" },
        .{ "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp41isom", "video/mp4" },
        .{ "\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2", octet_stream },
        .{ "\x1f\x8b\x08\x00", "application/x-gzip" },
        .{ "\x00asm\x01\x00\x00\x00", "application/wasm" },
        .{ (strRepeat("\x00", 34)) ++ "LP", "application/vnd.ms-fontobject" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], detectContentType(c[0]));
}

test "detectContentType: only the first 512 bytes count" {
    var buf: [sniff_len + 1]u8 = @splat('a');
    buf[sniff_len] = 0x00; // a binary byte past the window
    try testing.expectEqualStrings(text_plain, detectContentType(&buf));
    buf[sniff_len - 1] = 0x00;
    try testing.expectEqualStrings(octet_stream, detectContentType(&buf));
}

test "detectContentType: an mp4 box larger than the window does not match" {
    var buf: [sniff_len + 64]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], sniff_len + 64, .big);
    @memcpy(buf[4..11], "ftypmp4");
    try testing.expectEqualStrings(octet_stream, detectContentType(&buf));
    std.mem.writeInt(u32, buf[0..4], 16, .big);
    try testing.expectEqualStrings("video/mp4", detectContentType(&buf));
}

// ── fuzz: the answer is always a table entry, and the window bounds the input ──

const fz = @import("fuzz_test.zig");
const seed = @import("testkit").fuzz.seed;

const sniff_seeds = [_][]const u8{
    seed("<html>"),
    seed(" \t<!--x"),
    seed("<?xml"),
    seed("\x00\x00\x00\x14ftypmp4"),
    seed("RIFF\x00\x00\x00\x00WEBPVP"),
    seed("\xfe\xff\x00\x00"),
    seed("plain text"),
    seed("\x1b\x00"),
};

const SniffMark = fz.Marker(enum { html, other_signature, text, binary });

test "fuzz: detectContentType answers from its table and never past the window" {
    try testing.fuzz({}, fuzzSniffSmith, .{ .corpus = &sniff_seeds });
}

test "fuzz driver: HTTP_FUZZ (sniff)" {
    try fz.fuzz_driver.run(fuzzSniff, .{ .prefix = "HTTP_FUZZ", .name = "http-sniff" });
}

test "fuzz harness: sniff, 300 seeds, reaches every outcome" {
    try SniffMark.reach(fuzzSniff, "http-sniff", 300);
}

fn fuzzSniffSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzSniff, smith, script[0..n]);
}

fn fuzzSniff(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [sniff_len + 8]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, &sniff_seeds);
    const in = buf[0..len];
    const ct = detectContentType(in);

    // A static table string, never a slice of the input.
    try testing.expect(@intFromPtr(ct.ptr) < @intFromPtr(&buf) or @intFromPtr(ct.ptr) >= @intFromPtr(&buf) + buf.len);
    var known = std.mem.eql(u8, ct, text_plain) or std.mem.eql(u8, ct, octet_stream);
    for (signatures) |sig| known = known or std.mem.eql(u8, ct, sig.content_type);
    try testing.expect(known);

    // Bytes past the window never change the answer.
    if (in.len > sniff_len) try testing.expectEqualStrings(ct, detectContentType(in[0..sniff_len]));
    // Plain text only when no binary byte is in the window.
    if (std.mem.eql(u8, ct, octet_stream)) try testing.expect(looksBinary(in[0..@min(in.len, sniff_len)]));

    if (std.mem.startsWith(u8, ct, "text/html")) {
        SniffMark.mark(.html);
    } else if (std.mem.eql(u8, ct, text_plain)) {
        SniffMark.mark(.text);
    } else if (std.mem.eql(u8, ct, octet_stream)) {
        SniffMark.mark(.binary);
    } else SniffMark.mark(.other_signature);
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
