// SPDX-License-Identifier: MIT

//! UTF-8 decoding with the invalid-input policy, and encoding.
//!
//! Well-formedness is Unicode 17 Table 3-7 (no overlongs, no surrogates, nothing
//! above U+10FFFF). An ill-formed stretch is split into **maximal subparts**
//! (Unicode §3.9 best practice; the WHATWG Encoding Standard; Rust's
//! `String::from_utf8_lossy`; CPython's `errors="replace"`): `E2 82` at the end
//! of the input is one unit, `ED A0 80` is three.

const std = @import("std");

/// What to do with a byte sequence that is not well-formed UTF-8.
pub const InvalidUtf8 = enum {
    /// Return `error.InvalidUtf8`. Output already written by the call stays in the writer.
    reject,
    /// One U+FFFD per maximal subpart (Unicode §3.9; WHATWG; Rust `from_utf8_lossy`;
    /// CPython `decode(errors="replace")`; Go's `strings.ToValidUTF8` differs: it
    /// replaces a whole run with one replacement).
    replace,
    /// Copy the ill-formed bytes to the output unchanged and never fail. They are
    /// neutral to every algorithm: not cased, not a mark, a starter for normalization.
    pass_through,
};

pub const Step = struct {
    /// The scalar value; U+FFFD when `!valid`.
    cp: u21,
    /// Bytes consumed, 1..4.
    len: u3,
    valid: bool,
};

/// Decode the unit at `s[i]` (`i < s.len`).
pub fn step(s: []const u8, i: usize) Step {
    const b0 = s[i];
    if (b0 < 0x80) return .{ .cp = b0, .len = 1, .valid = true };
    var need: u3 = undefined;
    var lo: u8 = 0x80;
    var hi: u8 = 0xBF;
    var cp: u21 = undefined;
    switch (b0) {
        0xC2...0xDF => {
            need = 1;
            cp = b0 & 0x1F;
        },
        0xE0 => {
            need = 2;
            lo = 0xA0;
            cp = b0 & 0x0F;
        },
        0xE1...0xEC, 0xEE, 0xEF => {
            need = 2;
            cp = b0 & 0x0F;
        },
        0xED => {
            need = 2;
            hi = 0x9F;
            cp = b0 & 0x0F;
        },
        0xF0 => {
            need = 3;
            lo = 0x90;
            cp = b0 & 0x07;
        },
        0xF1...0xF3 => {
            need = 3;
            cp = b0 & 0x07;
        },
        0xF4 => {
            need = 3;
            hi = 0x8F;
            cp = b0 & 0x07;
        },
        else => return .{ .cp = 0xFFFD, .len = 1, .valid = false },
    }
    var k: u3 = 1;
    while (k <= need) : (k += 1) {
        if (i + k >= s.len) return .{ .cp = 0xFFFD, .len = k, .valid = false };
        const b = s[i + k];
        const l: u8 = if (k == 1) lo else 0x80;
        const h: u8 = if (k == 1) hi else 0xBF;
        if (b < l or b > h) return .{ .cp = 0xFFFD, .len = k, .valid = false };
        cp = (cp << 6) | (b & 0x3F);
    }
    return .{ .cp = cp, .len = need + 1, .valid = true };
}

/// One decoded unit under a policy: a scalar, or (only for `.pass_through`) raw bytes.
pub const Unit = struct {
    cp: u21,
    len: u3,
    /// True only for an ill-formed stretch under `.pass_through`: copy `s[i..][0..len]`.
    raw: bool,
};

pub fn unit(s: []const u8, i: usize, policy: InvalidUtf8) error{InvalidUtf8}!Unit {
    const st = step(s, i);
    if (st.valid) return .{ .cp = st.cp, .len = st.len, .raw = false };
    return switch (policy) {
        .reject => error.InvalidUtf8,
        .replace => .{ .cp = 0xFFFD, .len = st.len, .raw = false },
        .pass_through => .{ .cp = 0xFFFD, .len = st.len, .raw = true },
    };
}

/// Encode a scalar value (`cp` must not be a surrogate and not above U+10FFFF; every
/// value the tables produce is a scalar) into `buf`; returns the length.
pub fn encode(cp: u21, buf: *[4]u8) u3 {
    if (cp < 0x80) {
        buf[0] = @intCast(cp);
        return 1;
    }
    if (cp < 0x800) {
        buf[0] = @intCast(0xC0 | (cp >> 6));
        buf[1] = @intCast(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        buf[0] = @intCast(0xE0 | (cp >> 12));
        buf[1] = @intCast(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = @intCast(0x80 | (cp & 0x3F));
        return 3;
    }
    buf[0] = @intCast(0xF0 | ((cp >> 18) & 0x07));
    buf[1] = @intCast(0x80 | ((cp >> 12) & 0x3F));
    buf[2] = @intCast(0x80 | ((cp >> 6) & 0x3F));
    buf[3] = @intCast(0x80 | (cp & 0x3F));
    return 4;
}

test "step: maximal subparts and every Table 3-7 boundary" {
    const t = std.testing;
    // well-formed
    try t.expectEqual(@as(u21, 0x20AC), step("\xE2\x82\xAC", 0).cp);
    try t.expectEqual(@as(u21, 0x10FFFF), step("\xF4\x8F\xBF\xBF", 0).cp);
    try t.expectEqual(@as(u21, 0x800), step("\xE0\xA0\x80", 0).cp);
    // maximal subparts
    try t.expectEqual(@as(u3, 2), step("\xE2\x82", 0).len);
    try t.expectEqual(@as(u3, 3), step("\xF0\x9F\x98", 0).len);
    try t.expectEqual(@as(u3, 1), step("\xED\xA0\x80", 0).len);
    try t.expect(!step("\xED\xA0\x80", 0).valid);
    try t.expectEqual(@as(u3, 1), step("\xE0\x80\x80", 0).len);
    try t.expectEqual(@as(u3, 1), step("\xF4\x90\x80\x80", 0).len);
    try t.expectEqual(@as(u3, 1), step("\xC0\xAF", 0).len);
    try t.expectEqual(@as(u3, 1), step("\xF5\x80", 0).len);
    try t.expectEqual(@as(u3, 1), step("\x80", 0).len);
    try t.expectEqual(@as(u3, 1), step("\xFF", 0).len);
    try t.expectEqual(@as(u3, 2), step("\xF1\x80\x41", 0).len);
}

fn allValid(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) {
        const st = step(s, i);
        if (!st.valid) return false;
        i += st.len;
    }
    return true;
}

test "step agrees with std.unicode on every scalar, and its validity with utf8ValidateSlice on all short strings" {
    var buf: [4]u8 = undefined;
    var cp: u21 = 0;
    while (cp <= 0x10FFFF) : (cp += 1) {
        if (cp >= 0xD800 and cp < 0xE000) continue;
        const n = encode(cp, &buf);
        const st = step(buf[0..n], 0);
        if (!st.valid or st.cp != cp or st.len != n) return error.RoundTripFailed;
        var ref: [4]u8 = undefined;
        const m = try std.unicode.utf8Encode(cp, &ref);
        if (m != n or !std.mem.eql(u8, ref[0..m], buf[0..n])) return error.EncodeDiffers;
    }
    // every 1- and 2-byte string, and 3/4-byte strings over the boundary bytes of Table 3-7
    var a: usize = 0;
    while (a < 256) : (a += 1) {
        const s1 = [_]u8{@intCast(a)};
        try std.testing.expectEqual(std.unicode.utf8ValidateSlice(&s1), allValid(&s1));
        var b: usize = 0;
        while (b < 256) : (b += 1) {
            const s2 = [_]u8{ @intCast(a), @intCast(b) };
            try std.testing.expectEqual(std.unicode.utf8ValidateSlice(&s2), allValid(&s2));
        }
    }
    const edge = [_]u8{ 0x00, 0x41, 0x7F, 0x80, 0x8F, 0x90, 0x9F, 0xA0, 0xBF, 0xC0, 0xC1, 0xC2, 0xDF, 0xE0, 0xE1, 0xEC, 0xED, 0xEE, 0xF0, 0xF1, 0xF3, 0xF4, 0xF5, 0xFF };
    for (edge) |x| for (edge) |y| for (edge) |z| {
        const s3 = [_]u8{ x, y, z };
        try std.testing.expectEqual(std.unicode.utf8ValidateSlice(&s3), allValid(&s3));
        for (edge) |w| {
            const s4 = [_]u8{ x, y, z, w };
            try std.testing.expectEqual(std.unicode.utf8ValidateSlice(&s4), allValid(&s4));
        }
    };
}
