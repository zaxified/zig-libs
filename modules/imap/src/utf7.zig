// SPDX-License-Identifier: MIT

//! Modified UTF-7 as IMAP uses it for mailbox names (RFC 3501 §5.1.3, carried
//! forward by RFC 9051 §5.1 for servers that still speak it).
//!
//! It is UTF-7 (RFC 2152) with two changes that exist because mailbox names
//! travel through a protocol where `/` is a plausible hierarchy delimiter and
//! `+` is unremarkable:
//!
//!   * the shift character is **`&`**, not `+` — so a literal `&` is written
//!     `&-`;
//!   * the last two base64 characters are **`+` and `,`**, not `+` and `/`.
//!
//! Padding is never emitted and never accepted, and a base64 run may not encode
//! a character that could have been written directly — both are what make the
//! encoding canonical, which matters because mailbox names are compared as
//! byte strings.
//!
//! Ported from `emersion/go-imap` v2 `internal/utf7` (MIT — see
//! `modules/imap/NOTICE`). Divergence from the Go original is listed at the
//! bottom of this file.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// Lowest self-representing byte (SP).
const min_direct = 0x20;
/// Highest self-representing byte (`~`).
const max_direct = 0x7e;

/// Base64 with `,` in place of `/`, and no padding at all.
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";
const b64_decoder = std.base64.Base64Decoder.init(alphabet.*, null);
const b64_encoder = std.base64.Base64Encoder.init(alphabet.*, null);

pub const DecodeError = error{
    /// The input is not well-formed modified UTF-7.
    InvalidUtf7,
    /// The input is not valid UTF-8 (raw UTF-8 passes through, so it must be
    /// valid to begin with).
    InvalidUtf8,
    OutOfMemory,
};

pub const EncodeError = error{ InvalidUtf8, OutOfMemory };

/// Decode a mailbox name from modified UTF-7 into UTF-8. Raw UTF-8 in the
/// input is passed through unchanged, which is what RFC 9051 servers send.
pub fn decodeAlloc(gpa: Allocator, src: []const u8) DecodeError![]u8 {
    if (!std.unicode.utf8ValidateSlice(src)) return error.InvalidUtf8;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, src.len);

    // False only immediately after a base64 run. Two runs back to back
    // ("&AAA-&AAA-") are a "null shift": the encoder should have put them in
    // one run, so accepting it would make the encoding non-canonical.
    var ascii = true;

    var i: usize = 0;
    while (i < src.len) {
        const ch = src[i];

        // Control characters and DEL are never legal here. Bytes >= 0x80 are,
        // because raw UTF-8 is allowed through.
        if (ch < min_direct or (ch > max_direct and ch < 0x80)) return error.InvalidUtf7;

        if (ch != '&') {
            try out.append(gpa, ch);
            ascii = true;
            i += 1;
            continue;
        }

        // Scan to the '-' that closes the shifted run.
        const start = i + 1;
        i += 1;
        while (i < src.len and src[i] != '-') : (i += 1) {
            // A base64 decoder that skips CR/LF would silently accept a name
            // split across lines; reject instead.
            if (src[i] == '\r' or src[i] == '\n') return error.InvalidUtf7;
        }
        if (i == src.len) return error.InvalidUtf7; // unterminated "&..."

        if (i == start) {
            // "&-" is a literal ampersand.
            try out.append(gpa, '&');
            ascii = true;
        } else {
            if (!ascii) return error.InvalidUtf7; // null shift
            try decodeRun(gpa, &out, src[start..i]);
            ascii = false;
        }
        i += 1; // consume the '-'
    }

    return out.toOwnedSlice(gpa);
}

/// Decode one base64 run (the bytes between `&` and `-`) as UTF-16BE and
/// append it as UTF-8.
fn decodeRun(gpa: Allocator, out: *std.ArrayList(u8), run: []const u8) DecodeError!void {
    // Padding is not part of the encoding. Rejecting it explicitly says so;
    // the decoder would reject '=' as an out-of-alphabet byte anyway.
    if (std.mem.indexOfScalar(u8, run, '=') != null) return error.InvalidUtf7;

    const n = b64_decoder.calcSizeForSlice(run) catch return error.InvalidUtf7;
    // UTF-16BE, so an odd byte count cannot be a sequence of code units.
    if (n % 2 != 0) return error.InvalidUtf7;

    const units = try gpa.alloc(u8, n);
    defer gpa.free(units);
    b64_decoder.decode(units, run) catch return error.InvalidUtf7;

    var j: usize = 0;
    while (j < n) : (j += 2) {
        const first: u21 = (@as(u21, units[j]) << 8) | units[j + 1];

        var scalar: u21 = first;
        if (first >= 0xd800 and first <= 0xdbff) {
            // High surrogate: the low one must follow in the same run.
            if (j + 4 > n) return error.InvalidUtf7;
            const second: u21 = (@as(u21, units[j + 2]) << 8) | units[j + 3];
            if (second < 0xdc00 or second > 0xdfff) return error.InvalidUtf7;
            scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
            j += 2;
        } else if (first >= 0xdc00 and first <= 0xdfff) {
            return error.InvalidUtf7; // lone low surrogate
        } else if (first >= min_direct and first <= max_direct) {
            // Encodable directly, so encoding it in base64 is non-canonical.
            return error.InvalidUtf7;
        }

        var buf: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(@intCast(scalar), &buf) catch return error.InvalidUtf7;
        try out.appendSlice(gpa, buf[0..len]);
    }
}

/// Encode a UTF-8 mailbox name as modified UTF-7.
pub fn encodeAlloc(gpa: Allocator, src: []const u8) EncodeError![]u8 {
    if (!std.unicode.utf8ValidateSlice(src)) return error.InvalidUtf8;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.ensureTotalCapacity(gpa, src.len);

    var i: usize = 0;
    while (i < src.len) {
        const ch = src[i];
        if (ch >= min_direct and ch <= max_direct) {
            try out.append(gpa, ch);
            if (ch == '&') try out.append(gpa, '-');
            i += 1;
            continue;
        }

        // Run of everything that cannot be written directly. Scanning by BYTE
        // is safe: every byte of a multi-byte UTF-8 sequence is >= 0x80, so a
        // sequence is never split.
        const start = i;
        i += 1;
        while (i < src.len and (src[i] < min_direct or src[i] > max_direct)) : (i += 1) {}
        try encodeRun(gpa, &out, src[start..i]);
    }

    return out.toOwnedSlice(gpa);
}

fn encodeRun(gpa: Allocator, out: *std.ArrayList(u8), run: []const u8) EncodeError!void {
    // UTF-8 -> UTF-16BE. Worst case is 2 code units per scalar.
    var units: std.ArrayList(u8) = .empty;
    defer units.deinit(gpa);
    try units.ensureTotalCapacity(gpa, run.len * 2);

    var it = std.unicode.Utf8Iterator{ .bytes = run, .i = 0 };
    while (it.nextCodepoint()) |cp| {
        if (cp < 0x10000) {
            try units.append(gpa, @intCast(cp >> 8));
            try units.append(gpa, @intCast(cp & 0xff));
        } else {
            const v = cp - 0x10000;
            const hi: u16 = @intCast(0xd800 + (v >> 10));
            const lo: u16 = @intCast(0xdc00 + (v & 0x3ff));
            try units.append(gpa, @intCast(hi >> 8));
            try units.append(gpa, @intCast(hi & 0xff));
            try units.append(gpa, @intCast(lo >> 8));
            try units.append(gpa, @intCast(lo & 0xff));
        }
    }

    const enc_len = b64_encoder.calcSize(units.items.len);
    try out.append(gpa, '&');
    const at = out.items.len;
    try out.resize(gpa, at + enc_len);
    _ = b64_encoder.encode(out.items[at..][0..enc_len], units.items);
    try out.append(gpa, '-');
}

// ── tests ───────────────────────────────────────────────────────────────────
//
// Anchoring, stated honestly (CONVENTIONS §5):
//
//   * TIER 1 — the worked examples published in RFC 3501 §5.1.3 and RFC 2152.
//     These are independent of any implementation.
//   * TIER 2 — the vector table from `emersion/go-imap`'s own
//     `internal/utf7/decoder_test.go`. It is the implementation this file was
//     ported from, so it catches TRANSCRIPTION slips and cannot catch a shared
//     misreading of the RFC. It is labelled as such and not counted as an
//     external anchor.

test "tier 1: RFC 3501 §5.1.3 worked example" {
    const gpa = testing.allocator;

    // The RFC's own example: "~peter/mail/台北/日本語".
    const encoded = "~peter/mail/&U,BTFw-/&ZeVnLIqe-";
    const decoded = "~peter/mail/\u{53f0}\u{5317}/\u{65e5}\u{672c}\u{8a9e}";

    const got = try decodeAlloc(gpa, encoded);
    defer gpa.free(got);
    try testing.expectEqualStrings(decoded, got);

    // And back, byte for byte -- the encoding is canonical, so the round trip
    // must reproduce the RFC's spelling exactly, not merely something that
    // decodes the same.
    const back = try encodeAlloc(gpa, decoded);
    defer gpa.free(back);
    try testing.expectEqualStrings(encoded, back);
}

test "tier 1: the ',' alphabet is what distinguishes this from RFC 2152 UTF-7" {
    const gpa = testing.allocator;
    // U+53F0 U+5317 is the run that produces a ',' in modified UTF-7 and a '/'
    // in the standard alphabet -- the single most likely porting slip, since
    // every base64 helper defaults to '/'.
    const got = try encodeAlloc(gpa, "\u{53f0}\u{5317}");
    defer gpa.free(got);
    try testing.expectEqualStrings("&U,BTFw-", got);
    try testing.expect(std.mem.indexOfScalar(u8, got, '/') == null);
}

test "tier 2 (go-imap table): accepted forms" {
    const gpa = testing.allocator;
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "", .want = "" },
        .{ .in = "abc", .want = "abc" },
        .{ .in = "&-abc", .want = "&abc" },
        .{ .in = "abc&-", .want = "abc&" },
        .{ .in = "a&-b&-c", .want = "a&b&c" },
        .{ .in = "&ABk-", .want = "\x19" },
        .{ .in = "&AB8-", .want = "\x1f" },
        .{ .in = "ABk-", .want = "ABk-" }, // no '&', so it is literal text
        .{ .in = "&-,&-&AP8-&-", .want = "&,&\u{00ff}&" },
        .{ .in = "&-&-,&AP8-&-", .want = "&&,\u{00ff}&" },
        .{ .in = "abc &- &AP8A,wD,- &- xyz", .want = "abc & \u{00ff}\u{00ff}\u{00ff} & xyz" },
    };
    for (cases) |c| {
        const got = decodeAlloc(gpa, c.in) catch |e| {
            std.debug.print("\nunexpected error {t} decoding {s}\n", .{ e, c.in });
            return e;
        };
        defer gpa.free(got);
        try testing.expectEqualStrings(c.want, got);
    }
}

test "tier 2 (go-imap table): every rejection" {
    const gpa = testing.allocator;
    const bad = [_][]const u8{
        // Control characters and DEL are not self-representing.
        "\x00",           "\x1f",           "abc\n",              "abc\x7fxyz",
        // Invalid UTF-8.
        "\xc3\x28",       "\xe2\x82\x28",
        // Characters outside the modified alphabet, incl. RFC 2152's '/'.
          "&/+8-",              "&*-",
        // Whitespace or line breaks inside a base64 run.
        "&ZeVnLIqe -",    "&ZeVnLIqe\r\n-", "&ZeVnLIqe\r\n\r\n-", "&ZeVn\r\n\r\nLIqe-",
        // Padding is never part of the encoding.
        "&AAAAHw=-",      "&AAAAHw==-",     "&AAAAHwB,AIA=-",     "&AAAAHwB,AIA==-",
        // Unpaired surrogates.
        "&2A-",           "&2ADc-",
        // Truncated / mis-padded runs.
                "&AAAAHwB,A-",        "&AAAAHwB,A=-",
        "&AAAAHwB,A==-",  "&AAAAHwB,A===-", "&AAAAHwB,AI-",       "&AAAAHwB,AI=-",
        "&AAAAHwB,AI==-",
        // Unterminated shifts.
        "&",              "&Jjo",               "Jjo&",
        "&Jjo&",
    };
    for (bad) |s| {
        const r = decodeAlloc(gpa, s);
        if (r) |ok| {
            gpa.free(ok);
            std.debug.print("\nexpected rejection of {any}\n", .{s});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "a base64 run may not encode what could be written directly" {
    const gpa = testing.allocator;
    // "&AGE-" is 'a' the long way round. Accepting it would give one mailbox
    // name two spellings, and mailbox names are compared as byte strings.
    try testing.expectError(error.InvalidUtf7, decodeAlloc(gpa, "&AGE-"));
    // The boundaries of that rule, both sides.
    try testing.expectError(error.InvalidUtf7, decodeAlloc(gpa, "&ACA-")); // U+0020
    try testing.expectError(error.InvalidUtf7, decodeAlloc(gpa, "&AH4-")); // U+007E
    // Just outside it, both sides, are legal.
    const lo = try decodeAlloc(gpa, "&AB8-"); // U+001F
    defer gpa.free(lo);
    try testing.expectEqualStrings("\x1f", lo);
    const hi = try decodeAlloc(gpa, "&AH8-"); // U+007F
    defer gpa.free(hi);
    try testing.expectEqualStrings("\x7f", hi);
}

test "null shift: two base64 runs back to back are rejected" {
    const gpa = testing.allocator;
    // Both spell U+00FF twice; only the single-run form is canonical.
    try testing.expectError(error.InvalidUtf7, decodeAlloc(gpa, "&AP8-&AP8-"));
    const one = try decodeAlloc(gpa, "&AP8A,w-");
    defer gpa.free(one);
    try testing.expectEqualStrings("\u{00ff}\u{00ff}", one);
    // ...and the encoder produces exactly the accepted one.
    const enc = try encodeAlloc(gpa, "\u{00ff}\u{00ff}");
    defer gpa.free(enc);
    try testing.expectEqualStrings("&AP8A,w-", enc);
}

test "round trip over the awkward cases" {
    const gpa = testing.allocator;
    const names = [_][]const u8{
        "INBOX",
        "INBOX/Sent",
        "R&D", // the ampersand escape
        "&", // nothing but an ampersand
        "\u{00e9}", // one non-ASCII scalar
        "a\u{00e9}b", // run bounded on both sides
        "\u{1f600}", // outside the BMP -- a surrogate pair
        "a\u{1f600}\u{00e9}b", // surrogate pair inside a longer run
        "\u{7f}", // DEL: not self-representing, so it shifts
        "\x01\x02", // control characters likewise
        "Ελληνικά",
        "почта",
    };
    for (names) |name| {
        const enc = try encodeAlloc(gpa, name);
        defer gpa.free(enc);
        const dec = try decodeAlloc(gpa, enc);
        defer gpa.free(dec);
        try testing.expectEqualStrings(name, dec);
    }
}

test "encoder output is itself always decodable, and canonical" {
    const gpa = testing.allocator;
    // Encoding twice must not double-encode: the second pass sees only
    // self-representing characters plus '&' escapes.
    const once = try encodeAlloc(gpa, "a\u{53f0}b&c");
    defer gpa.free(once);
    const twice = try encodeAlloc(gpa, once);
    defer gpa.free(twice);
    try testing.expect(!std.mem.eql(u8, once, twice)); // '&' got escaped again
    const back = try decodeAlloc(gpa, twice);
    defer gpa.free(back);
    try testing.expectEqualStrings(once, back);
}

test "invalid UTF-8 is rejected by both directions" {
    const gpa = testing.allocator;
    try testing.expectError(error.InvalidUtf8, decodeAlloc(gpa, "\xff"));
    try testing.expectError(error.InvalidUtf8, encodeAlloc(gpa, "\xff"));
}

// ── divergence from the Go original ─────────────────────────────────────────
//
// D1. `Encode` in Go substitutes U+FFFD for an unpaired surrogate or an
//     out-of-range rune and encodes it silently. Here `encodeAlloc` validates
//     first and returns `error.InvalidUtf8`, because a mailbox name that
//     silently changes identity is worse than a failed call -- the caller
//     cannot notice the substitution, but it can handle an error.
//
// D2. Go's `Decode` rejects a run whose LAST byte is '='; a '=' anywhere else
//     is rejected later by the base64 decoder. This rejects any '=' up front.
//     The accepted set is identical; only the error's provenance differs.

// ── fuzz ─────────────────────────────────────────────────────────────────
//
// Mailbox names arrive from the server in modified UTF-7 and are decoded
// before anything else looks at them, so this is untrusted input on the same
// footing as the wire grammar. The decoder is also the strictest thing in the
// module -- it rejects padding, a null shift, non-canonical runs, unpaired
// surrogates and CR/LF inside a run -- and every one of those rejections is a
// branch reached only by input no legitimate server sends.
//
// The property is that it always returns: either bytes or a typed error, for
// any input at all. Base64 decoding into a UTF-16 buffer and then folding
// surrogate pairs is the kind of index arithmetic where a truncated run at
// the very end of the input is the classic off-by-one.

test "fuzz: modified UTF-7 decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [256]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    const out = decodeAlloc(testing.allocator, buf[0..len]) catch return;
    defer testing.allocator.free(out);

    // Whatever came back must be valid UTF-8 -- the decoder's contract, and a
    // stronger check than "it did not crash". A surrogate mishandled as a
    // lone code point would produce well-formed-looking bytes that are not.
    try testing.expect(std.unicode.utf8ValidateSlice(out));
}
