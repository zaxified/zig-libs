// SPDX-License-Identifier: MIT

//! PEM armour (RFC 7468 textual encoding, plus the RFC 1421 header lines
//! OpenSSL still writes for a legacy encrypted key).
//!
//! The block walk is safe over text that holds secret blocks: it never feeds
//! a body to a Boyer-Moore-Horspool search (`std.mem.find`), whose skip table
//! is indexed by the text's characters. A body is crossed by a scan for its
//! END line's first `-`, a compare that is false on every base64 character,
//! so the walk depends on the body's length, not on its characters. The body
//! is decoded by `b64ct`, in constant time. (Moved here from
//! `tlsserver/src/keys.zig` `BlockIterator` and `acme/src/x509.zig`
//! `pemBlockStart`, ctgrind 2026-10-18.)

const std = @import("std");
const b64ct = @import("b64ct");

const b64 = b64ct.standard;

pub const Error = error{
    /// A BEGIN line without its END line, an END line naming another label,
    /// a label that runs past its line, or an unterminated header block.
    InvalidPem,
};

/// The longest label accepted (`ENCRYPTED PRIVATE KEY` is 21; RFC 7468's
/// labels are all well under this).
pub const max_label_len = 64;

pub const Block = struct {
    label: []const u8,
    /// The base64 text between the BEGIN line (or its RFC 1421 headers)
    /// and the END line, whitespace included.
    body: []const u8,
    /// The RFC 1421 header lines (`Proc-Type: ...`), empty when absent.
    headers: []const u8,

    /// RFC 1421 `Proc-Type: 4,ENCRYPTED`: OpenSSL's legacy encrypted key.
    pub fn isEncrypted(b: Block) bool {
        var it = std.mem.splitScalar(u8, b.headers, '\n');
        while (it.next()) |line| {
            const l = std.mem.trimEnd(u8, line, "\r");
            if (std.mem.startsWith(u8, l, "Proc-Type:") and std.mem.find(u8, l, "ENCRYPTED") != null) return true;
        }
        return false;
    }

    /// Decodes the body into `out` (constant time in the body's characters).
    /// `NoSpaceLeft` when `out` is too small (`decodedLenBound` sizes it);
    /// an empty body or a non-base64 character is `InvalidPem`.
    pub fn decode(b: Block, out: []u8) (Error || error{NoSpaceLeft})![]u8 {
        const der = b64.decodeIgnoring(out, b.body, b64ct.pem_whitespace) catch |err| return switch (err) {
            error.NoSpaceLeft => error.NoSpaceLeft,
            else => error.InvalidPem,
        };
        if (der.len == 0) return error.InvalidPem;
        return der;
    }

    /// An upper bound on `decode`'s output length.
    pub fn decodedLenBound(b: Block) usize {
        return b64.maxDecodedLen(b.body.len);
    }
};

/// Every `-----BEGIN <label>-----` block of `text`, in order. Text between
/// blocks is ignored (comments, `openssl` `-text` output, `EC PARAMETERS`
/// blocks are just other blocks), and so is a `-----BEGIN ` that does not
/// start a well-formed BEGIN line (a label of at most `max_label_len` bytes
/// closed by five dashes on the same line), as Go's `pem.Decode` skips it.
/// A block whose BEGIN line is well formed but whose END line is missing or
/// names another label is an error, never skipped: it would otherwise
/// swallow the next block's BEGIN. The body may start on the BEGIN line
/// itself (a one-line PEM, as CI secret stores keep them). `pos` is where
/// the walk stands: the text after the last block returned.
pub const Iterator = struct {
    text: []const u8,
    pos: usize = 0,

    pub fn init(text: []const u8) Iterator {
        return .{ .text = text };
    }

    pub fn next(it: *Iterator) Error!?Block {
        const begin = "-----BEGIN ";
        const end = "-----END ";
        const dashes = "-----";
        var bi: usize = undefined;
        var label: []const u8 = undefined;
        var label_end: usize = undefined;
        while (true) {
            bi = std.mem.findPos(u8, it.text, it.pos, begin) orelse {
                it.pos = it.text.len;
                return null;
            };
            const label_start = bi + begin.len;
            // The label ends at the first '-' (RFC 7468 labels hold none) and
            // must be followed by the five dashes on the same line; anything
            // else is not a BEGIN line, and the search goes on after it.
            it.pos = label_start;
            label_end = std.mem.findScalarPos(u8, it.text, label_start, '-') orelse continue;
            label = it.text[label_start..label_end];
            if (label.len > max_label_len or std.mem.findAny(u8, label, "\r\n") != null) continue;
            if (!std.mem.startsWith(u8, it.text[label_end..], dashes)) continue;
            break;
        }
        var body_start = label_end + dashes.len;
        // Rest of the BEGIN line: only optional trailing whitespace.
        while (body_start < it.text.len and (it.text[body_start] == ' ' or it.text[body_start] == '\t')) body_start += 1;
        if (body_start < it.text.len and it.text[body_start] == '\r') body_start += 1;
        if (body_start < it.text.len and it.text[body_start] == '\n') body_start += 1;

        // RFC 1421 headers: public text, up to the first empty line. A
        // header line is a token of header-name characters and a ':';
        // base64 has no ':', so a body line never qualifies.
        var headers: []const u8 = &.{};
        if (startsHeader(it.text[body_start..])) {
            const h_start = body_start;
            while (true) {
                const eol = std.mem.findScalarPos(u8, it.text, body_start, '\n') orelse return error.InvalidPem;
                const line = std.mem.trimEnd(u8, it.text[body_start..eol], "\r");
                body_start = eol + 1;
                if (line.len == 0) break;
            }
            headers = it.text[h_start..body_start];
        }

        const body_end = std.mem.findScalarPos(u8, it.text, body_start, '-') orelse return error.InvalidPem;
        const tail = it.text[body_end..];
        if (!std.mem.startsWith(u8, tail, end) or !std.mem.startsWith(u8, tail[end.len..], label) or
            !std.mem.startsWith(u8, tail[end.len + label.len ..], dashes)) return error.InvalidPem;
        // Past the END marker, not its line: `cat` of files without a final
        // newline puts the next BEGIN on the same line.
        it.pos = body_end + end.len + label.len + dashes.len;
        return .{ .label = label, .body = it.text[body_start..body_end], .headers = headers };
    }
};

/// `Proc-Type:` / `DEK-Info:` style: a non-empty token of letters, digits
/// and '-', then ':'. Over a body line this reads no character unless the
/// line holds a ':' (a one-line PEM followed by a comment), and then it
/// classifies every character before the ':' without an early exit, so
/// which characters a secret body holds does not steer it.
fn startsHeader(s: []const u8) bool {
    const eol = std.mem.findScalar(u8, s, '\n') orelse s.len;
    const line = s[0..eol];
    const colon = std.mem.findScalar(u8, line, ':') orelse return false;
    if (colon == 0) return false;
    var bad: u8 = 0;
    for (line[0..colon]) |c| bad |= ~tokenMask(c);
    return bad == 0;
}

/// 0xff for [A-Za-z0-9-], else 0, without a branch on `c`.
fn tokenMask(c: u8) u8 {
    const lower = c | 0x20; // folds A-Z onto a-z (and nothing else onto it)
    return inRange(lower, 'a', 'z') | inRange(c, '0', '9') | eqMask(c, '-');
}

/// 0xff for lo <= c <= hi, else 0: the sign bit of each 16-bit difference.
fn inRange(c: u8, lo: u8, hi: u8) u8 {
    const below: u16 = (@as(u16, c) -% lo) >> 15; // 1 iff c < lo
    const above: u16 = (@as(u16, hi) -% c) >> 15; // 1 iff c > hi
    return @as(u8, @truncate(below | above)) -% 1;
}

fn eqMask(c: u8, v: u8) u8 {
    const d: u16 = @as(u16, c ^ v);
    return @as(u8, @truncate((d -% 1) >> 8)); // 0xff iff d == 0
}

/// The first block of `text` whose label is `label`.
pub fn find(text: []const u8, label: []const u8) Error!?Block {
    var it: Iterator = .init(text);
    while (try it.next()) |b| if (std.mem.eql(u8, b.label, label)) return b;
    return null;
}

/// Bytes `encode` writes for `der_len` octets under `label`. Saturating,
/// as `b64ct`'s lengths are: a length no buffer can hold comes out as
/// `maxInt(usize)`, and `encode` then reports `NoSpaceLeft`.
pub fn encodedLen(label: []const u8, der_len: usize) usize {
    const frame = "-----BEGIN -----\n".len + "-----END -----\n".len;
    return b64.encodedWrappedLen(der_len, 64, .lf) +| (frame +| 2 *| label.len); // every line LF-terminated
}

/// One PEM block (64-column lines, LF), the shape `openssl` writes. The
/// base64 is `b64ct`'s, constant time: safe for a secret DER. `NoSpaceLeft`
/// when `out` is shorter than `encodedLen`; an over-long label or one with a
/// '-' or a line break is `InvalidPem`.
pub fn encode(out: []u8, label: []const u8, der: []const u8) (Error || error{NoSpaceLeft})![]u8 {
    if (label.len > max_label_len or std.mem.findAny(u8, label, "-\r\n") != null) return error.InvalidPem;
    const total = encodedLen(label, der.len);
    if (out.len < total) return error.NoSpaceLeft;
    var w: std.Io.Writer = .fixed(out);
    w.print("-----BEGIN {s}-----\n", .{label}) catch unreachable; // sized above
    const body = b64.encodeWrapped(out[w.end..], der, 64, .lf);
    w.end += body.len;
    w.print("-----END {s}-----\n", .{label}) catch unreachable;
    std.debug.assert(w.end == total);
    return out[0..total];
}

const t = std.testing;

test "iterator: blocks in order, other text ignored, END must match" {
    const text =
        "comment line\n" ++
        "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n" ++
        "-----BEGIN X-----\r\nAAEC\r\nAw==\r\n-----END X----------BEGIN Y-----\nAA==\n-----END Y-----";
    var it: Iterator = .init(text);
    const a = (try it.next()).?;
    try t.expectEqualStrings("EC PARAMETERS", a.label);
    const b = (try it.next()).?;
    try t.expectEqualStrings("X", b.label);
    var buf: [8]u8 = undefined;
    try t.expectEqualSlices(u8, &.{ 0, 1, 2, 3 }, try b.decode(&buf));
    const c = (try it.next()).?; // on the END line of the previous block
    try t.expectEqualStrings("Y", c.label);
    try t.expectEqual(@as(?Block, null), try it.next());

    for ([_][]const u8{
        "-----BEGIN X-----\nAA==\n-----END Y-----\n", // another label
        "-----BEGIN X-----\nAA==\n", // no END
        "-----BEGIN X-----\nProc-Type: 4,ENCRYPTED\nAA==\n-----END X-----\n", // no empty line after headers
        "-----BEGIN X-----\nAA==\n-----END X---\n", // short dashes
    }) |bad| {
        var it2: Iterator = .init(bad);
        try t.expectError(error.InvalidPem, it2.next());
    }
}

test "tokenMask classifies every byte" {
    for (0..256) |i| {
        const c: u8 = @intCast(i);
        const want = std.ascii.isAlphanumeric(c) or c == '-';
        try t.expectEqual(@as(u8, if (want) 0xff else 0), tokenMask(c));
    }
}

test "iterator: a stray BEGIN is skipped, a one-line PEM with a trailing comment reads" {
    const text = "see -----BEGIN the docs\n-----BEGIN K-----\nAAEC\n-----END K-----\n";
    const b = (try find(text, "K")).?;
    try t.expectEqualStrings("AAEC\n", b.body);
    const one_line = "-----BEGIN K----- AAEC -----END K----- # note: x";
    const o = (try find(one_line, "K")).?;
    try t.expect(!o.isEncrypted());
    var buf: [4]u8 = undefined;
    try t.expectEqualSlices(u8, &.{ 0, 1, 2 }, try o.decode(&buf));
    // A header token holds no blank: a colon after base64 on the line is not a header.
    try t.expect(!startsHeader("AAEC -----END K----- # note: x"));
    try t.expect(startsHeader("Proc-Type: 4,ENCRYPTED\n"));
    try t.expect(!startsHeader(": x\n"));
}

test "block: headers, encryption flag, decode errors" {
    const text = "-----BEGIN EC PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAEC\n-----END EC PRIVATE KEY-----\n";
    const b = (try find(text, "EC PRIVATE KEY")).?;
    try t.expect(b.isEncrypted());
    try t.expectEqualStrings("AAEC\n", b.body);
    const plain = (try find("-----BEGIN K-----\nAAEC\n-----END K-----\n", "K")).?;
    try t.expect(!plain.isEncrypted());
    var one: [2]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, plain.decode(&one));
    const empty = (try find("-----BEGIN K-----\n-----END K-----\n", "K")).?;
    try t.expectError(error.InvalidPem, empty.decode(&one));
    const bad = (try find("-----BEGIN K-----\nAA*C\n-----END K-----\n", "K")).?;
    var four: [4]u8 = undefined;
    try t.expectError(error.InvalidPem, bad.decode(&four));
    try t.expectEqual(@as(?Block, null), try find("-----BEGIN K-----\nAAEC\n-----END K-----\n", "L"));
}

test "encode: openssl's shape, round trip through the iterator, sizes" {
    var der: [100]u8 = undefined;
    for (&der, 0..) |*d, i| d.* = @intCast(i);
    var buf: [256]u8 = undefined;
    for ([_]usize{ 1, 47, 48, 49, 100 }) |n| {
        const pem = try encode(&buf, "PRIVATE KEY", der[0..n]);
        try t.expectEqual(encodedLen("PRIVATE KEY", n), pem.len);
        try t.expect(std.mem.endsWith(u8, pem, "\n-----END PRIVATE KEY-----\n"));
        var lines = std.mem.splitScalar(u8, pem, '\n');
        while (lines.next()) |l| try t.expect(l.len <= 64);
        const b = (try find(pem, "PRIVATE KEY")).?;
        var back: [100]u8 = undefined;
        try t.expectEqualSlices(u8, der[0..n], try b.decode(&back));
    }
    try t.expectError(error.NoSpaceLeft, encode(buf[0..40], "PRIVATE KEY", der[0..10]));
    try t.expectEqual(std.math.maxInt(usize), encodedLen("PRIVATE KEY", std.math.maxInt(usize) - 3));
    try t.expectError(error.InvalidPem, encode(&buf, "A-B", der[0..1]));
    try t.expectError(error.InvalidPem, encode(&buf, "A\nB", der[0..1]));
}

test "startsHeader: the first character of the token counts" {
    try t.expect(!startsHeader("#abc: x\n"));
    try t.expect(!startsHeader("a b: x\n"));
    try t.expect(startsHeader("a-B9: x\n"));
}
