// SPDX-License-Identifier: MIT

//! RFC 4954 — the SMTP AUTH extension, PLAIN (RFC 4616) and LOGIN.
//!
//! Both mechanisms transmit the password in the clear after a base64 encode
//! that is not encryption. RFC 4954 §14 is blunt about it: "the AUTH command
//! ... MUST NOT be used over an unencrypted connection unless the client has
//! explicitly requested it". `session.zig` enforces exactly that — AUTH is
//! refused on a plaintext link unless the caller sets
//! `Options.allow_plaintext_auth`, and the refusal is a typed error, not a
//! warning.
//!
//! LOGIN was never standardised (it has no RFC; the challenges are the literal
//! base64 of "Username:" and "Password:"). It is implemented because a large
//! minority of servers offer nothing else, and it is chosen only after PLAIN.
//!
//! Credentials are validated before they are encoded: a NUL byte inside a
//! PLAIN credential would forge the field separators of RFC 4616, and a CR or
//! LF anywhere would forge a whole SMTP command line.

const std = @import("std");
const testing = std.testing;

pub const AuthError = error{
    /// A NUL in a credential (would forge the RFC 4616 field separator) or a
    /// CR/LF (would forge a command line).
    InvalidCredential,
    /// The encoded response does not fit the caller's buffer.
    NoSpaceLeft,
    /// The server sent a challenge that is not valid base64.
    MalformedChallenge,
    /// The server sent a challenge we do not understand for this mechanism.
    UnexpectedChallenge,
};

const b64 = std.base64.standard;

/// The two challenges LOGIN uses, base64 as they appear on the wire.
pub const login_username_challenge = "VXNlcm5hbWU6"; // "Username:"
pub const login_password_challenge = "UGFzc3dvcmQ6"; // "Password:"

fn checkCredential(s: []const u8) AuthError!void {
    for (s) |c| {
        if (c == 0 or c == '\r' or c == '\n') return error.InvalidCredential;
    }
}

/// Encoded length of `n` raw octets (base64 with padding).
pub fn encodedLen(n: usize) usize {
    return b64.Encoder.calcSize(n);
}

/// RFC 4616 §2: `authzid NUL authcid NUL passwd`, base64-encoded. `authzid` is
/// almost always empty (an empty authorization identity means "the identity in
/// authcid").
pub fn plainResponse(buf: []u8, authzid: []const u8, authcid: []const u8, passwd: []const u8) AuthError![]const u8 {
    try checkCredential(authzid);
    try checkCredential(authcid);
    try checkCredential(passwd);
    const raw_len = authzid.len + 1 + authcid.len + 1 + passwd.len;
    if (encodedLen(raw_len) > buf.len) return error.NoSpaceLeft;

    // The raw form is built in a stack buffer that is wiped afterwards: it
    // holds the plaintext password.
    var raw: [1024]u8 = undefined;
    if (raw_len > raw.len) return error.NoSpaceLeft;
    defer std.crypto.secureZero(u8, raw[0..raw_len]);
    var i: usize = 0;
    @memcpy(raw[i..][0..authzid.len], authzid);
    i += authzid.len;
    raw[i] = 0;
    i += 1;
    @memcpy(raw[i..][0..authcid.len], authcid);
    i += authcid.len;
    raw[i] = 0;
    i += 1;
    @memcpy(raw[i..][0..passwd.len], passwd);
    i += passwd.len;
    return b64.Encoder.encode(buf, raw[0..i]);
}

/// One LOGIN step: base64 of the credential the server just asked for.
pub fn loginResponse(buf: []u8, credential: []const u8) AuthError![]const u8 {
    try checkCredential(credential);
    if (encodedLen(credential.len) > buf.len) return error.NoSpaceLeft;
    return b64.Encoder.encode(buf, credential);
}

/// Decode a server challenge (the text of a `334` reply). An empty challenge is
/// legal and decodes to an empty slice.
pub fn decodeChallenge(buf: []u8, challenge: []const u8) AuthError![]const u8 {
    const trimmed = std.mem.trim(u8, challenge, " \t");
    if (trimmed.len == 0) return buf[0..0];
    const n = b64.Decoder.calcSizeForSlice(trimmed) catch return error.MalformedChallenge;
    if (n > buf.len) return error.NoSpaceLeft;
    b64.Decoder.decode(buf[0..n], trimmed) catch return error.MalformedChallenge;
    return buf[0..n];
}

/// Which LOGIN credential a `334` challenge is asking for. Servers differ in
/// what they put in the challenge (some send "Username:", some "User Name",
/// some nothing at all), so the *order* of the exchange is authoritative and
/// the challenge text is only used to catch an obviously reversed server.
pub const LoginStep = enum { username, password, unknown };

pub fn classifyLoginChallenge(challenge: []const u8) LoginStep {
    var buf: [128]u8 = undefined;
    const decoded = decodeChallenge(&buf, challenge) catch return .unknown;
    if (asciiContains(decoded, "user")) return .username;
    if (asciiContains(decoded, "pass")) return .password;
    return .unknown;
}

fn asciiContains(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(hay[i..][0..needle.len], needle)) return true;
    }
    return false;
}

// ── tests ──────────────────────────────────────────────────────────────────

test "RFC 4616 §4 worked example" {
    // The RFC's own example: authzid empty, authcid "tim", passwd "tanstaaftanstaaf".
    var buf: [128]u8 = undefined;
    const r = try plainResponse(&buf, "", "tim", "tanstaaftanstaaf");
    try testing.expectEqualStrings("AHRpbQB0YW5zdGFhZnRhbnN0YWFm", r);

    // ...and it really is NUL "tim" NUL "tanstaaftanstaaf".
    var dec: [128]u8 = undefined;
    const back = try decodeChallenge(&dec, r);
    try testing.expectEqualSlices(u8, "\x00tim\x00tanstaaftanstaaf", back);
}

test "RFC 4954 §4 AUTH PLAIN example" {
    // The RFC's example is base64("\0test\0tEsTiNg") = "AHRlc3QAdEVzVGlOZw==".
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("AHRlc3QAdEVzVGlOZw==", try plainResponse(&buf, "", "test", "tEsTiNg"));
}

test "PLAIN with a non-empty authorization identity" {
    var buf: [128]u8 = undefined;
    const r = try plainResponse(&buf, "admin", "tim", "pw");
    var dec: [128]u8 = undefined;
    try testing.expectEqualSlices(u8, "admin\x00tim\x00pw", try decodeChallenge(&dec, r));
}

test "LOGIN challenges are the literal base64 the servers send" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, "Username:", try decodeChallenge(&buf, login_username_challenge));
    try testing.expectEqualSlices(u8, "Password:", try decodeChallenge(&buf, login_password_challenge));
    try testing.expectEqual(LoginStep.username, classifyLoginChallenge(login_username_challenge));
    try testing.expectEqual(LoginStep.password, classifyLoginChallenge(login_password_challenge));
    // A server that sends something else is not fatal — the order rules.
    try testing.expectEqual(LoginStep.unknown, classifyLoginChallenge("Zm9v"));
    try testing.expectEqual(LoginStep.unknown, classifyLoginChallenge("not base64!!"));

    try testing.expectEqualStrings("dXNlckBleGFtcGxlLmNvbQ==", try loginResponse(&buf, "user@example.com"));
    try testing.expectEqualStrings("c2VjcmV0", try loginResponse(&buf, "secret"));
}

test "credentials that would forge a separator or a command line are refused" {
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "", "ti\x00m", "pw"));
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "", "tim", "pw\x00extra"));
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "", "tim", "pw\r\nQUIT"));
    try testing.expectError(error.InvalidCredential, plainResponse(&buf, "a\nb", "tim", "pw"));
    try testing.expectError(error.InvalidCredential, loginResponse(&buf, "user\r\nMAIL FROM:<x@example.com>"));
}

test "buffers that are too small are an error, never a truncation" {
    var small: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, plainResponse(&small, "", "tim", "tanstaaftanstaaf"));
    try testing.expectError(error.NoSpaceLeft, loginResponse(&small, "a-long-username"));
    var out: [4]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, decodeChallenge(&out, "dXNlckBleGFtcGxlLmNvbQ=="));
}

test "a malformed base64 challenge is a typed error" {
    var buf: [64]u8 = undefined;
    try testing.expectError(error.MalformedChallenge, decodeChallenge(&buf, "!!!!"));
    try testing.expectError(error.MalformedChallenge, decodeChallenge(&buf, "AAAAA"));
    try testing.expectEqualSlices(u8, "", try decodeChallenge(&buf, ""));
    try testing.expectEqualSlices(u8, "", try decodeChallenge(&buf, "  "));
}

test "fuzz: arbitrary challenges and credentials never crash" {
    try testing.fuzz({}, fuzzAuth, .{});
}

fn fuzzAuth(_: void, smith: *std.testing.Smith) !void {
    var raw: [200]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    const s = raw[0..len];
    var buf: [512]u8 = undefined;
    _ = plainResponse(&buf, "", s, s) catch {};
    _ = loginResponse(&buf, s) catch {};
    _ = decodeChallenge(&buf, s) catch {};
    _ = classifyLoginChallenge(s);
}
