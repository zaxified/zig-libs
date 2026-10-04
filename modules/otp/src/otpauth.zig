// SPDX-License-Identifier: MIT
//! `otpauth://` provisioning URIs (Google Authenticator "Key Uri Format"):
//! the text an authenticator app scans from a QR code to enrol a TOTP/HOTP
//! secret.
//!
//! ```
//! otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
//! ```
//!
//! `parse` treats the URI as hostile input (a scanned QR code): it is
//! length-capped, allocation-free (every decoded byte lands in a caller
//! buffer of at most `uri.len` bytes) and fail-closed with a typed error per
//! fault. `format` writes the canonical form that pyotp's
//! `provisioning_uri` produces for the same inputs, and everything `parse`
//! accepts survives `format` -> `parse` unchanged.
//!
//! Decisions on points where the format is loose (each is also in SPEC.md):
//!   * unknown query parameters are ignored, as the format says;
//!   * a KNOWN parameter given twice is `DuplicateParameter`;
//!   * `issuer=` and a label prefix that both appear must be byte-equal
//!     after decoding, else `IssuerMismatch` (Google: "should be equal");
//!   * `digits` is 6, 7 or 8 (the format names 6 and 8; 7 is accepted, 1..5
//!     and 9 are not); `period` is 1..`max_period`;
//!   * `+` is a literal plus in labels and values (RFC 3986), never a space;
//!   * a label holds at most one issuer separator (`:` or `%3A`): a second
//!     one is `InvalidLabel`, as the format forbids a colon in either part.

const std = @import("std");
const base32 = @import("base32");
const root = @import("root.zig");

pub const Algorithm = root.Algorithm;

pub const Kind = enum { totp, hotp };

/// Longest URI `parse` will look at. A QR code holds at most ~2.9 KB and real
/// provisioning URIs are under 200 bytes.
pub const max_uri_len = 2048;
pub const min_uri_digits: u5 = 6;
pub const max_uri_digits: u5 = 8;
pub const default_period: u32 = 30;
/// Largest accepted `period` (one day), seconds.
pub const max_period: u32 = 86_400;

/// A parsed (or to-be-formatted) provisioning URI.
pub const KeyUri = struct {
    kind: Kind,
    /// The raw (base32-decoded) shared secret, never empty.
    secret: []const u8,
    /// Account name (percent-decoded), never empty, no `:`.
    account: []const u8,
    /// Issuer (percent-decoded), from the `issuer` parameter or the label
    /// prefix; null when neither is present.
    issuer: ?[]const u8 = null,
    algorithm: Algorithm = .sha1,
    digits: u5 = min_uri_digits,
    /// TOTP only (ignored for HOTP).
    period: u32 = default_period,
    /// HOTP only: the initial counter (ignored for TOTP).
    counter: u64 = 0,

    pub const WrongKind = error{WrongKind};

    /// The TOTP code for `unix_time` (RFC 6238, `t0 = 0`). Runtime-dispatches
    /// `algorithm` to `root.totp`.
    pub fn totpCode(self: KeyUri, unix_time: u64) WrongKind!u32 {
        if (self.kind != .totp) return error.WrongKind;
        return switch (self.algorithm) {
            inline else => |a| root.totp(a, self.secret, unix_time, self.period, 0, self.digits),
        };
    }

    /// The HOTP code for `counter` (RFC 4226).
    pub fn hotpCode(self: KeyUri, counter: u64) WrongKind!u32 {
        if (self.kind != .hotp) return error.WrongKind;
        return switch (self.algorithm) {
            inline else => |a| root.hotp(a, self.secret, counter, self.digits),
        };
    }
};

pub const ParseError = error{
    /// Longer than `max_uri_len`.
    UriTooLong,
    /// Not `otpauth://<type>/<label>[?query]`, or contains a `#` fragment.
    InvalidUri,
    /// Type is neither `totp` nor `hotp`.
    UnknownType,
    /// Empty/malformed account or issuer prefix, second `:`, an account
    /// starting with a space, bad percent-escape, invalid UTF-8 or a
    /// control byte.
    InvalidLabel,
    /// `issuer=` empty, containing `:`, or malformed (same rules as the
    /// label).
    InvalidIssuer,
    /// No `secret` parameter.
    MissingSecret,
    /// `secret` is empty or not canonical base32.
    InvalidSecret,
    /// `algorithm` is not SHA1/SHA256/SHA512 (any case).
    InvalidAlgorithm,
    InvalidDigits,
    InvalidPeriod,
    InvalidCounter,
    /// HOTP without `counter`.
    MissingCounter,
    /// A known parameter appeared twice.
    DuplicateParameter,
    /// `issuer=` disagrees with the label's issuer prefix.
    IssuerMismatch,
    /// `buf` cannot hold the decoded fields (`buf.len >= uri.len` always
    /// suffices).
    BufferTooSmall,
};

/// Bump allocator over the caller's buffer.
const Bump = struct {
    buf: []u8,
    used: usize = 0,

    fn rest(self: *Bump) []u8 {
        return self.buf[self.used..];
    }
    /// Keep the first `n` bytes of `rest()` as an allocation.
    fn commit(self: *Bump, n: usize) []u8 {
        const s = self.buf[self.used..][0..n];
        self.used += n;
        return s;
    }
};

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Percent-decode `raw` into the bump buffer. Null on a bad escape or when
/// the buffer is too small (`.overflow` distinguishes).
const DecodeResult = union(enum) { ok: []u8, bad_escape, overflow };

fn percentDecode(bump: *Bump, raw: []const u8) DecodeResult {
    const out = bump.rest();
    if (out.len < raw.len) return .overflow; // decoded <= raw
    var o: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (o += 1) {
        if (raw[i] == '%') {
            if (i + 2 >= raw.len) return .bad_escape;
            const hi = hexVal(raw[i + 1]) orelse return .bad_escape;
            const lo = hexVal(raw[i + 2]) orelse return .bad_escape;
            out[o] = hi << 4 | lo;
            i += 3;
        } else {
            out[o] = raw[i];
            i += 1;
        }
    }
    return .{ .ok = bump.commit(o) };
}

/// Non-empty, valid UTF-8, no C0 control bytes and no DEL.
fn validText(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c < 0x20 or c == 0x7f) return false;
    return std.unicode.utf8ValidateSlice(s);
}

/// Index of the first issuer separator (`:`, `%3A`, `%3a`) in a raw label,
/// with its length.
fn findSeparator(raw: []const u8) ?struct { at: usize, len: usize } {
    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        if (raw[i] == ':') return .{ .at = i, .len = 1 };
        if (raw[i] == '%' and raw.len - i >= 3 and raw[i + 1] == '3' and (raw[i + 2] == 'A' or raw[i + 2] == 'a'))
            return .{ .at = i, .len = 3 };
    }
    return null;
}

fn strictDecimal(comptime T: type, s: []const u8) ?T {
    if (s.len == 0 or s.len > 20) return null;
    var v: T = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = std.math.mul(T, v, 10) catch return null;
        v = std.math.add(T, v, c - '0') catch return null;
    }
    return v;
}

fn hasPrefixIgnoreCase(s: []const u8, prefix: []const u8) bool {
    return s.len >= prefix.len and std.ascii.eqlIgnoreCase(s[0..prefix.len], prefix);
}

/// Parse an `otpauth://totp/...` or `otpauth://hotp/...` URI. All slices in
/// the result point into `buf`; `buf.len >= uri.len` is always enough.
pub fn parse(uri: []const u8, buf: []u8) ParseError!KeyUri {
    if (uri.len > max_uri_len) return error.UriTooLong;
    const scheme = "otpauth://";
    if (!hasPrefixIgnoreCase(uri, scheme)) return error.InvalidUri;
    if (std.mem.indexOfScalar(u8, uri, '#') != null) return error.InvalidUri;
    const after = uri[scheme.len..];

    const slash = std.mem.indexOfScalar(u8, after, '/') orelse return error.InvalidUri;
    const type_text = after[0..slash];
    const kind: Kind = if (std.ascii.eqlIgnoreCase(type_text, "totp"))
        .totp
    else if (std.ascii.eqlIgnoreCase(type_text, "hotp"))
        .hotp
    else
        return error.UnknownType;

    const tail = after[slash + 1 ..];
    const q = std.mem.indexOfScalar(u8, tail, '?');
    const label_raw = if (q) |i| tail[0..i] else tail;
    const query = if (q) |i| tail[i + 1 ..] else "";

    var bump: Bump = .{ .buf = buf };

    // ── label ──
    var prefix_issuer: ?[]const u8 = null;
    var account_raw = label_raw;
    if (findSeparator(label_raw)) |sep| {
        const issuer_raw = label_raw[0..sep.at];
        account_raw = label_raw[sep.at + sep.len ..];
        // "optional spaces may precede the account name"
        while (true) {
            if (account_raw.len >= 1 and account_raw[0] == ' ') {
                account_raw = account_raw[1..];
            } else if (account_raw.len >= 3 and std.mem.eql(u8, account_raw[0..3], "%20")) {
                account_raw = account_raw[3..];
            } else break;
        }
        const d = switch (percentDecode(&bump, issuer_raw)) {
            .ok => |s| s,
            .bad_escape => return error.InvalidLabel,
            .overflow => return error.BufferTooSmall,
        };
        if (!validText(d)) return error.InvalidLabel;
        prefix_issuer = d;
    }
    if (findSeparator(account_raw) != null) return error.InvalidLabel;
    const account = switch (percentDecode(&bump, account_raw)) {
        .ok => |s| s,
        .bad_escape => return error.InvalidLabel,
        .overflow => return error.BufferTooSmall,
    };
    if (!validText(account) or account[0] == ' ') return error.InvalidLabel;

    // ── query ──
    var secret: ?[]const u8 = null;
    var param_issuer: ?[]const u8 = null;
    var algorithm: ?Algorithm = null;
    var digits: ?u5 = null;
    var period: ?u32 = null;
    var counter: ?u64 = null;

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=');
        const name = if (eq) |i| pair[0..i] else pair;
        const value = if (eq) |i| pair[i + 1 ..] else "";

        if (std.mem.eql(u8, name, "secret")) {
            if (secret != null) return error.DuplicateParameter;
            if (value.len == 0) return error.InvalidSecret;
            const out = bump.rest();
            if (out.len < base32.decodedLenUpperBound(value.len)) return error.BufferTooSmall;
            const n = base32.decode(out, value, .{ .padding = .optional, .case = .insensitive }) catch return error.InvalidSecret;
            if (n == 0) return error.InvalidSecret;
            secret = bump.commit(n);
        } else if (std.mem.eql(u8, name, "issuer")) {
            if (param_issuer != null) return error.DuplicateParameter;
            const d = switch (percentDecode(&bump, value)) {
                .ok => |s| s,
                .bad_escape => return error.InvalidIssuer,
                .overflow => return error.BufferTooSmall,
            };
            if (!validText(d) or std.mem.indexOfScalar(u8, d, ':') != null) return error.InvalidIssuer;
            param_issuer = d;
        } else if (std.mem.eql(u8, name, "algorithm")) {
            if (algorithm != null) return error.DuplicateParameter;
            algorithm = if (std.ascii.eqlIgnoreCase(value, "SHA1"))
                .sha1
            else if (std.ascii.eqlIgnoreCase(value, "SHA256"))
                .sha256
            else if (std.ascii.eqlIgnoreCase(value, "SHA512"))
                .sha512
            else
                return error.InvalidAlgorithm;
        } else if (std.mem.eql(u8, name, "digits")) {
            if (digits != null) return error.DuplicateParameter;
            const d = strictDecimal(u8, value) orelse return error.InvalidDigits;
            if (d < min_uri_digits or d > max_uri_digits) return error.InvalidDigits;
            digits = @intCast(d);
        } else if (std.mem.eql(u8, name, "period")) {
            if (period != null) return error.DuplicateParameter;
            const p = strictDecimal(u32, value) orelse return error.InvalidPeriod;
            if (p == 0 or p > max_period) return error.InvalidPeriod;
            period = p;
        } else if (std.mem.eql(u8, name, "counter")) {
            if (counter != null) return error.DuplicateParameter;
            counter = strictDecimal(u64, value) orelse return error.InvalidCounter;
        }
        // Unknown parameters are ignored.
    }

    const secret_bytes = secret orelse return error.MissingSecret;
    if (kind == .hotp and counter == null) return error.MissingCounter;

    var issuer: ?[]const u8 = param_issuer;
    if (prefix_issuer) |p| {
        if (param_issuer) |pi| {
            if (!std.mem.eql(u8, p, pi)) return error.IssuerMismatch;
        } else issuer = p;
    }

    return .{
        .kind = kind,
        .secret = secret_bytes,
        .account = account,
        .issuer = issuer,
        .algorithm = algorithm orelse .sha1,
        .digits = digits orelse min_uri_digits,
        .period = period orelse default_period,
        .counter = counter orelse 0,
    };
}

pub const FormatError = error{
    /// Account empty/invalid, contains `:` or starts with a space.
    InvalidLabel,
    /// Issuer empty/invalid or contains `:`.
    InvalidIssuer,
    /// Empty secret.
    InvalidSecret,
    InvalidDigits,
    InvalidPeriod,
} || std.Io.Writer.Error;

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

/// RFC 3986 percent-encoding of everything except the unreserved set (so
/// `/`, `@`, `:` and space are all escaped; upper-case hex).
fn writePercent(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        if (isUnreserved(c)) {
            try w.writeByte(c);
        } else {
            try w.writeAll(&.{ '%', hex[c >> 4], hex[c & 15] });
        }
    }
}

/// Write `k` as a provisioning URI. Field order and elision follow pyotp's
/// `provisioning_uri`: `secret`, `issuer`, `counter` (HOTP), then `algorithm`,
/// `digits`, `period` (TOTP) only when they differ from SHA1 / 6 / 30. The
/// secret is written as unpadded upper-case base32. Validates before writing
/// anything, so an error leaves `w` untouched.
pub fn format(w: *std.Io.Writer, k: KeyUri) FormatError!void {
    if (!validText(k.account) or std.mem.indexOfScalar(u8, k.account, ':') != null) return error.InvalidLabel;
    if (k.issuer) |iss| {
        if (!validText(iss) or std.mem.indexOfScalar(u8, iss, ':') != null) return error.InvalidIssuer;
    }
    if (k.account[0] == ' ') return error.InvalidLabel;
    if (k.secret.len == 0) return error.InvalidSecret;
    if (k.digits < min_uri_digits or k.digits > max_uri_digits) return error.InvalidDigits;
    if (k.kind == .totp and (k.period == 0 or k.period > max_period)) return error.InvalidPeriod;

    try w.writeAll(switch (k.kind) {
        .totp => "otpauth://totp/",
        .hotp => "otpauth://hotp/",
    });
    if (k.issuer) |iss| {
        try writePercent(w, iss);
        try w.writeByte(':');
    }
    try writePercent(w, k.account);
    try w.writeAll("?secret=");
    var i: usize = 0;
    while (i < k.secret.len) {
        const take = @min(40, k.secret.len - i); // 40 bytes -> 64 symbols, no padding mid-stream
        var tmp: [64]u8 = undefined;
        const text = base32.encode(&tmp, k.secret[i..][0..take], .{ .pad = false }) catch unreachable;
        try w.writeAll(text);
        i += take;
    }
    if (k.issuer) |iss| {
        try w.writeAll("&issuer=");
        try writePercent(w, iss);
    }
    if (k.kind == .hotp) try w.print("&counter={d}", .{k.counter});
    switch (k.algorithm) {
        .sha1 => {},
        .sha256 => try w.writeAll("&algorithm=SHA256"),
        .sha512 => try w.writeAll("&algorithm=SHA512"),
    }
    if (k.digits != min_uri_digits) try w.print("&digits={d}", .{k.digits});
    if (k.kind == .totp and k.period != default_period) try w.print("&period={d}", .{k.period});
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn render(buf: []u8, k: KeyUri) ![]const u8 {
    var w = std.Io.Writer.fixed(buf);
    try format(&w, k);
    return w.buffered();
}

// Vector provenance: the two Google URIs are the examples on the Google
// Authenticator "Key Uri Format" wiki page (fetched 2026-09-30). The pyotp
// outputs are the ones pyotp's README shows for `provisioning_uri`; pyotp was
// NOT importable here, so they are recalled from its documentation, not
// executed. The RFC secret's base32 was produced by Python's b32encode.

const rfc_sha1 = "12345678901234567890";
const rfc_sha1_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const rfc_sha256 = "12345678901234567890123456789012";
const rfc_sha256_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const rfc_sha512 = "1234567890123456789012345678901234567890123456789012345678901234";
const rfc_sha512_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

test "Google wiki example 1: label prefix + issuer parameter" {
    var buf: [256]u8 = undefined;
    const k = try parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example", &buf);
    try testing.expectEqual(Kind.totp, k.kind);
    try testing.expectEqualStrings("alice@google.com", k.account);
    try testing.expectEqualStrings("Example", k.issuer.?);
    try testing.expectEqualSlices(u8, "Hello!\xde\xad\xbe\xef", k.secret);
    try testing.expectEqual(Algorithm.sha1, k.algorithm);
    try testing.expectEqual(@as(u5, 6), k.digits);
    try testing.expectEqual(@as(u32, 30), k.period);
}

test "Google wiki example 2: every optional parameter, percent-encoded issuer" {
    var buf: [256]u8 = undefined;
    const k = try parse("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30", &buf);
    try testing.expectEqualStrings("john.doe@email.com", k.account);
    try testing.expectEqualStrings("ACME Co", k.issuer.?);
    try testing.expectEqual(@as(usize, 20), k.secret.len);
    try testing.expectEqualSlices(u8, &.{ 0x3d, 0xc6, 0xca, 0xa4, 0x82, 0x4a, 0x6d, 0x28, 0x87, 0x67, 0xb2, 0x33, 0x1e, 0x20, 0xb4, 0x31, 0x66, 0xcb, 0x85, 0xd9 }, k.secret);
}

test "Google label grammar: literal or encoded colon, spaces after it" {
    var buf: [256]u8 = undefined;
    const s = "&secret=JBSWY3DPEHPK3PXP".*;
    const cases = [_]struct { label: []const u8, issuer: ?[]const u8, account: []const u8 }{
        .{ .label = "Example:alice@gmail.com", .issuer = "Example", .account = "alice@gmail.com" },
        .{ .label = "Provider1:Alice%20Smith", .issuer = "Provider1", .account = "Alice Smith" },
        .{ .label = "Big%20Corporation%3A%20alice%40bigco.com", .issuer = "Big Corporation", .account = "alice@bigco.com" },
        .{ .label = "Big%20Corporation%3a%20%20alice", .issuer = "Big Corporation", .account = "alice" },
        .{ .label = "alice%40example.com", .issuer = null, .account = "alice@example.com" },
        .{ .label = "Zaří:Žluťoučký%20kůň", .issuer = "Zaří", .account = "Žluťoučký kůň" },
    };
    for (cases) |c| {
        var uri: [200]u8 = undefined;
        const text = try std.fmt.bufPrint(&uri, "otpauth://totp/{s}?{s}", .{ c.label, s[1..] });
        const k = try parse(text, &buf);
        try testing.expectEqualStrings(c.account, k.account);
        if (c.issuer) |i| try testing.expectEqualStrings(i, k.issuer.?) else try testing.expect(k.issuer == null);
    }
}

test "case handling: scheme/type/algorithm case-insensitive, secret lower-case and padded ok" {
    var buf: [128]u8 = undefined;
    const k = try parse("OTPAUTH://TOTP/x?secret=jbswy3dpehpk3pxp&algorithm=sha256", &buf);
    try testing.expectEqual(Algorithm.sha256, k.algorithm);
    try testing.expectEqual(@as(usize, 10), k.secret.len);
    const p = try parse("otpauth://totp/x?secret=MZXW6===", &buf);
    try testing.expectEqualStrings("foo", p.secret);
    // parameter NAMES are case-sensitive: `SECRET` is an unknown parameter
    try testing.expectError(error.MissingSecret, parse("otpauth://totp/x?SECRET=MZXW6", &buf));
}

test "unknown parameters are ignored, empty pairs skipped" {
    var buf: [128]u8 = undefined;
    const k = try parse("otpauth://totp/x?&foo=bar&secret=MZXW6&image=http%3A%2F%2Fx&foo=again&&lock", &buf);
    try testing.expectEqualStrings("foo", k.secret);
}

test "hotp requires counter; counter parsed as u64" {
    var buf: [128]u8 = undefined;
    try testing.expectError(error.MissingCounter, parse("otpauth://hotp/x?secret=MZXW6", &buf));
    const k = try parse("otpauth://hotp/x?secret=MZXW6&counter=18446744073709551615", &buf);
    try testing.expectEqual(std.math.maxInt(u64), k.counter);
    try testing.expectError(error.InvalidCounter, parse("otpauth://hotp/x?secret=MZXW6&counter=18446744073709551616", &buf));
    try testing.expectError(error.InvalidCounter, parse("otpauth://hotp/x?secret=MZXW6&counter=-1", &buf));
    try testing.expectError(error.InvalidCounter, parse("otpauth://hotp/x?secret=MZXW6&counter=+1", &buf));
    try testing.expectError(error.InvalidCounter, parse("otpauth://hotp/x?secret=MZXW6&counter=", &buf));
}

test "parse rejection classes" {
    var buf: [512]u8 = undefined;
    const bad = [_]struct { uri: []const u8, err: ParseError }{
        .{ .uri = "http://totp/x?secret=MZXW6", .err = error.InvalidUri },
        .{ .uri = "otpauth:/totp/x?secret=MZXW6", .err = error.InvalidUri },
        .{ .uri = "otpauth://totp", .err = error.InvalidUri },
        .{ .uri = "otpauth://totp/x?secret=MZXW6#frag", .err = error.InvalidUri },
        .{ .uri = "otpauth://steam/x?secret=MZXW6", .err = error.UnknownType },
        .{ .uri = "otpauth:///x?secret=MZXW6", .err = error.UnknownType },
        .{ .uri = "otpauth://totp/?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/Example:?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/:alice?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a:b:c?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a%3Ab%3Ac?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/%20x?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&issuer=a%3Ab", .err = error.InvalidIssuer },
        .{ .uri = "otpauth://totp/a%zz?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a%4?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a%?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a%00b?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a%0Ab?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/a%FFb?secret=MZXW6", .err = error.InvalidLabel },
        .{ .uri = "otpauth://totp/x", .err = error.MissingSecret },
        .{ .uri = "otpauth://totp/x?issuer=Y", .err = error.MissingSecret },
        .{ .uri = "otpauth://totp/x?secret=", .err = error.InvalidSecret },
        .{ .uri = "otpauth://totp/x?secret=MZXW1", .err = error.InvalidSecret },
        .{ .uri = "otpauth://totp/x?secret=MZ", .err = error.InvalidSecret }, // non-canonical bits
        .{ .uri = "otpauth://totp/x?secret=MZXW6=", .err = error.InvalidSecret }, // partial padding
        .{ .uri = "otpauth://totp/x?secret=MZXW%36", .err = error.InvalidSecret }, // no percent-decoding in secret
        .{ .uri = "otpauth://totp/x?secret=MZXW6&secret=MZXW6", .err = error.DuplicateParameter },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&issuer=A&issuer=A", .err = error.DuplicateParameter },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&digits=6&digits=6", .err = error.DuplicateParameter },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&issuer=", .err = error.InvalidIssuer },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&issuer=a%zz", .err = error.InvalidIssuer },
        .{ .uri = "otpauth://totp/A:x?secret=MZXW6&issuer=B", .err = error.IssuerMismatch },
        .{ .uri = "otpauth://totp/A:x?secret=MZXW6&issuer=a", .err = error.IssuerMismatch },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&algorithm=MD5", .err = error.InvalidAlgorithm },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&algorithm=", .err = error.InvalidAlgorithm },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&digits=5", .err = error.InvalidDigits },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&digits=9", .err = error.InvalidDigits },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&digits=six", .err = error.InvalidDigits },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&digits=256", .err = error.InvalidDigits },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&period=0", .err = error.InvalidPeriod },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&period=86401", .err = error.InvalidPeriod },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&period=4294967296", .err = error.InvalidPeriod },
        .{ .uri = "otpauth://totp/x?secret=MZXW6&period=-30", .err = error.InvalidPeriod },
    };
    for (bad) |c| {
        try testing.expectError(c.err, parse(c.uri, &buf));
    }
    // accepted boundaries
    _ = try parse("otpauth://totp/x?secret=MZXW6&digits=8&period=86400", &buf);
    _ = try parse("otpauth://totp/x?secret=MZXW6&digits=7&period=1", &buf);
}

test "parse is bounded: length cap and buffer size" {
    var big: [max_uri_len + 1]u8 = undefined;
    @memset(&big, 'A');
    @memcpy(big[0.."otpauth://totp/x?secret=".len], "otpauth://totp/x?secret=");
    var buf: [max_uri_len + 8]u8 = undefined;
    try testing.expectError(error.UriTooLong, parse(&big, &buf));
    // buf.len == uri.len is always enough; one byte less for a label-only
    // decode need not be
    const uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example";
    var exact: [uri.len]u8 = undefined;
    _ = try parse(uri, &exact);
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, parse(uri, &tiny));
    // A 2 KB secret is fine within the cap and the buffer.
    var long: [max_uri_len]u8 = undefined;
    const prefix = "otpauth://totp/x?secret=";
    @memcpy(long[0..prefix.len], prefix);
    @memset(long[prefix.len..], 'A');
    const k = try parse(&long, &buf);
    try testing.expectEqual((max_uri_len - prefix.len) * 5 / 8, k.secret.len);
}

test "format: pyotp provisioning_uri outputs (recalled from pyotp docs)" {
    var out: [256]u8 = undefined;
    const secret = try base32.decodeAlloc(testing.allocator, "JBSWY3DPEHPK3PXP", .{ .padding = .optional });
    defer testing.allocator.free(secret);
    try testing.expectEqualStrings(
        "otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Secure%20App",
        try render(&out, .{ .kind = .totp, .secret = secret, .account = "alice@google.com", .issuer = "Secure App" }),
    );
    const hs = try base32.decodeAlloc(testing.allocator, "BASE32SECRET3232", .{});
    defer testing.allocator.free(hs);
    try testing.expectEqualStrings(
        "otpauth://hotp/Secure%20App:alice%40google.com?secret=BASE32SECRET3232&issuer=Secure%20App&counter=0",
        try render(&out, .{ .kind = .hotp, .secret = hs, .account = "alice@google.com", .issuer = "Secure App", .counter = 0 }),
    );
}

test "format: elision, order and escaping" {
    var out: [512]u8 = undefined;
    try testing.expectEqualStrings(
        "otpauth://totp/a%2Fb%3Fc%23d%26e%3Df%2Bg%25h?secret=MZXW6",
        try render(&out, .{ .kind = .totp, .secret = "foo", .account = "a/b?c#d&e=f+g%h" }),
    );
    try testing.expectEqualStrings(
        "otpauth://totp/x?secret=MZXW6&algorithm=SHA512&digits=8&period=60",
        try render(&out, .{ .kind = .totp, .secret = "foo", .account = "x", .algorithm = .sha512, .digits = 8, .period = 60 }),
    );
    // HOTP: counter yes, period never
    try testing.expectEqualStrings(
        "otpauth://hotp/x?secret=MZXW6&counter=7&algorithm=SHA256",
        try render(&out, .{ .kind = .hotp, .secret = "foo", .account = "x", .counter = 7, .algorithm = .sha256, .period = 99 }),
    );
    // non-ASCII: UTF-8 bytes percent-encoded
    try testing.expectEqualStrings(
        "otpauth://totp/%C5%BDlu%C5%A5:%C5%A0t%C4%9Bp%C3%A1n?secret=MZXW6&issuer=%C5%BDlu%C5%A5",
        try render(&out, .{ .kind = .totp, .secret = "foo", .account = "Štěpán", .issuer = "Žluť" }),
    );
    // a secret longer than one encoding chunk (40 bytes) crosses the chunk seam
    var long_uri: [400]u8 = undefined;
    const lk: KeyUri = .{ .kind = .totp, .secret = rfc_sha512, .account = "x" };
    try testing.expectEqualStrings("otpauth://totp/x?secret=" ++ rfc_sha512_b32, try render(&long_uri, lk));
}

test "format: validation happens before any byte is written" {
    var out: [256]u8 = undefined;
    const base: KeyUri = .{ .kind = .totp, .secret = "foo", .account = "x" };
    const cases = [_]struct { k: KeyUri, err: FormatError }{
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "" }, .err = error.InvalidLabel },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "a:b" }, .err = error.InvalidLabel },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "a\nb" }, .err = error.InvalidLabel },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = " x", .issuer = "I" }, .err = error.InvalidLabel },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = " x" }, .err = error.InvalidLabel },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "x", .issuer = "" }, .err = error.InvalidIssuer },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "x", .issuer = "a:b" }, .err = error.InvalidIssuer },
        .{ .k = .{ .kind = .totp, .secret = "", .account = "x" }, .err = error.InvalidSecret },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "x", .digits = 5 }, .err = error.InvalidDigits },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "x", .digits = 9 }, .err = error.InvalidDigits },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "x", .period = 0 }, .err = error.InvalidPeriod },
        .{ .k = .{ .kind = .totp, .secret = "foo", .account = "x", .period = max_period + 1 }, .err = error.InvalidPeriod },
    };
    for (cases) |c| {
        var w = std.Io.Writer.fixed(&out);
        try testing.expectError(c.err, format(&w, c.k));
        try testing.expectEqual(@as(usize, 0), w.buffered().len);
    }
    // A too-small writer surfaces WriteFailed rather than truncating silently.
    var tiny: [8]u8 = undefined;
    var w = std.Io.Writer.fixed(&tiny);
    try testing.expectError(error.WriteFailed, format(&w, base));
}

test "round trip: parse -> format -> parse (fixed corpus)" {
    const uris = [_][]const u8{
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
        "otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=mzxw6ytboi&digits=8&period=45&algorithm=sha512",
        "otpauth://hotp/only-account?secret=MZXW6YTBOI======&counter=42",
        "otpauth://hotp/I:a?secret=MZXW6&counter=0&issuer=I&digits=7&algorithm=SHA256",
        "otpauth://totp/%C5%BDlu%C5%A5:Štěpán?secret=MZXW6&issuer=%C5%BDlu%C5%A5",
        "otpauth://totp/x?secret=" ++ rfc_sha512_b32,
    };
    for (uris) |u| {
        var b1: [512]u8 = undefined;
        var b2: [512]u8 = undefined;
        var text: [1024]u8 = undefined;
        const k1 = try parse(u, &b1);
        const t = try render(&text, k1);
        const k2 = try parse(t, &b2);
        try testing.expectEqual(k1.kind, k2.kind);
        try testing.expectEqualSlices(u8, k1.secret, k2.secret);
        try testing.expectEqualStrings(k1.account, k2.account);
        try testing.expectEqualStrings(k1.issuer orelse "", k2.issuer orelse "");
        try testing.expectEqual(k1.issuer == null, k2.issuer == null);
        try testing.expectEqual(k1.algorithm, k2.algorithm);
        try testing.expectEqual(k1.digits, k2.digits);
        if (k1.kind == .totp) try testing.expectEqual(k1.period, k2.period) else try testing.expectEqual(k1.counter, k2.counter);
        // format is a fixpoint after one normalisation
        var text2: [1024]u8 = undefined;
        try testing.expectEqualStrings(t, try render(&text2, k2));
    }
}

test "round trip: random fields through format -> parse" {
    var prng = std.Random.DefaultPrng.init(0x6f747061);
    const rnd = prng.random();
    // Whole code points, ':' deliberately absent (illegal in labels).
    const cps = [_][]const u8{ "a", "Z", "7", " ", "/", "?", "#", "&", "=", "+", "%", "@", "\u{e9}", "\u{17e}", "\u{4e2d}", "\u{1f600}", "-", ".", "_", "~" };
    var secret: [100]u8 = undefined;
    var acct: [40]u8 = undefined;
    var iss: [40]u8 = undefined;
    for (0..300) |_| {
        const sl = rnd.intRangeAtMost(usize, 1, 100);
        rnd.bytes(secret[0..sl]);
        var al: usize = 0;
        var il: usize = 0;
        const an = rnd.intRangeAtMost(usize, 1, 8);
        for (0..an) |_| {
            const cp = cps[rnd.uintLessThan(usize, cps.len)];
            @memcpy(acct[al..][0..cp.len], cp);
            al += cp.len;
        }
        const with_issuer = rnd.boolean();
        if (with_issuer) {
            const n = rnd.intRangeAtMost(usize, 1, 8);
            for (0..n) |_| {
                const cp = cps[rnd.uintLessThan(usize, cps.len)];
                @memcpy(iss[il..][0..cp.len], cp);
                il += cp.len;
            }
        }
        if (acct[0] == ' ') acct[0] = 'a';
        const k: KeyUri = .{
            .kind = if (rnd.boolean()) .totp else .hotp,
            .secret = secret[0..sl],
            .account = acct[0..al],
            .issuer = if (with_issuer) iss[0..il] else null,
            .algorithm = rnd.enumValue(Algorithm),
            .digits = rnd.intRangeAtMost(u5, 6, 8),
            .period = rnd.intRangeAtMost(u32, 1, max_period),
            .counter = rnd.int(u64),
        };
        var text: [1024]u8 = undefined;
        const t = try render(&text, k);
        var b: [1024]u8 = undefined;
        const p = try parse(t, &b);
        try testing.expectEqual(k.kind, p.kind);
        try testing.expectEqualSlices(u8, k.secret, p.secret);
        try testing.expectEqualStrings(k.account, p.account);
        try testing.expectEqual(k.issuer == null, p.issuer == null);
        if (k.issuer) |i| try testing.expectEqualStrings(i, p.issuer.?);
        try testing.expectEqual(k.algorithm, p.algorithm);
        try testing.expectEqual(k.digits, p.digits);
        if (k.kind == .totp) try testing.expectEqual(k.period, p.period) else try testing.expectEqual(k.counter, p.counter);
    }
}

test "codes from a parsed URI equal the RFC 4226 / 6238 results for the raw secret" {
    var buf: [512]u8 = undefined;
    // RFC 6238 Appendix B, T = 59 s: 94287082 / 46119246 / 90693936, 8 digits.
    const sha1 = try parse("otpauth://totp/rfc?secret=" ++ rfc_sha1_b32 ++ "&digits=8", &buf);
    try testing.expectEqualSlices(u8, rfc_sha1, sha1.secret);
    try testing.expectEqual(@as(u32, 94287082), try sha1.totpCode(59));
    try testing.expectEqual(root.totp(.sha1, rfc_sha1, 1111111109, 30, 0, 8), try sha1.totpCode(1111111109));
    try testing.expectEqual(@as(u32, 7081804), try sha1.totpCode(1111111109));

    var buf2: [512]u8 = undefined;
    const sha256 = try parse("otpauth://totp/rfc?secret=" ++ rfc_sha256_b32 ++ "&digits=8&algorithm=SHA256", &buf2);
    try testing.expectEqualSlices(u8, rfc_sha256, sha256.secret);
    try testing.expectEqual(@as(u32, 46119246), try sha256.totpCode(59));

    var buf3: [512]u8 = undefined;
    const sha512 = try parse("otpauth://totp/rfc?secret=" ++ rfc_sha512_b32 ++ "&digits=8&algorithm=SHA512", &buf3);
    try testing.expectEqualSlices(u8, rfc_sha512, sha512.secret);
    try testing.expectEqual(@as(u32, 90693936), try sha512.totpCode(59));

    // HOTP: RFC 4226 Appendix D counts 0 and 1: 755224, 287082.
    const h = try parse("otpauth://hotp/rfc?secret=" ++ rfc_sha1_b32 ++ "&counter=0", &buf);
    try testing.expectEqual(@as(u32, 755224), try h.hotpCode(0));
    try testing.expectEqual(@as(u32, 287082), try h.hotpCode(1));
    try testing.expectError(error.WrongKind, h.totpCode(59));
    try testing.expectError(error.WrongKind, sha1.hotpCode(0));
}

test "fuzz: parse never panics, and everything accepted re-formats and re-parses" {
    try testing.fuzz({}, fuzzParse, .{ .corpus = &fuzz_seeds });
}

const testkit = @import("testkit");
const fuzz_seeds = [_][]const u8{
    testkit.fuzz.seed("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"),
    testkit.fuzz.seed("otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"),
    testkit.fuzz.seed("otpauth://hotp/a%3Ab?secret=MZXW6&counter=1"),
    testkit.fuzz.seed("otpauth://totp/%zz%"),
    testkit.fuzz.seed("otpauth://"),
    testkit.fuzz.seed(""),
};

fn fuzzParse(_: void, smith: *testing.Smith) !void {
    var input: [640]u8 = undefined;
    const len: usize = smith.slice(&input);
    var buf: [640]u8 = undefined;
    const k = parse(input[0..len], &buf) catch return;
    var out: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&out);
    // Percent-encoding can expand a 640-byte input past both the writer and
    // the URI cap; that is a size limit, not a defect.
    format(&w, k) catch |e| switch (e) {
        error.WriteFailed => return,
        else => return e,
    };
    if (w.buffered().len > max_uri_len) return;
    var buf2: [2048]u8 = undefined;
    const k2 = try parse(w.buffered(), &buf2);
    try testing.expectEqualSlices(u8, k.secret, k2.secret);
    try testing.expectEqualStrings(k.account, k2.account);
    try testing.expectEqual(k.issuer == null, k2.issuer == null);
    if (k.issuer) |i| try testing.expectEqualStrings(i, k2.issuer.?);
}

// ── tests: mutation-run additions (2026-10-04) ──────────────────────────────

test "parse: a truncated %3 at the end of the label is a bad escape, not an out-of-bounds read" {
    // `findSeparator` looks for `%3A`/`%3a`; a label ending in `%3` has only
    // two bytes left and must be passed on to the percent decoder, which
    // rejects the incomplete escape (documented: bad percent-escape ->
    // InvalidLabel).
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidLabel, parse("otpauth://totp/a%3?secret=MZXW6", &buf));
    try testing.expectError(error.InvalidLabel, parse("otpauth://totp/I:a%3?secret=MZXW6", &buf));
}

test "parse: the last C0 control byte (0x1F) and DEL (0x7F) are rejected in label and issuer" {
    // Documented rule: "label and issuer must be non-empty valid UTF-8 without
    // C0 controls or DEL"; C0 is 0x00..0x1F, so 0x1F is the boundary byte.
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidLabel, parse("otpauth://totp/a%1Fb?secret=MZXW6", &buf));
    try testing.expectError(error.InvalidLabel, parse("otpauth://totp/a%7Fb?secret=MZXW6", &buf));
    try testing.expectError(error.InvalidLabel, parse("otpauth://totp/I%7F:a?secret=MZXW6", &buf));
    try testing.expectError(error.InvalidIssuer, parse("otpauth://totp/a?secret=MZXW6&issuer=x%1Fy", &buf));
    try testing.expectError(error.InvalidIssuer, parse("otpauth://totp/a?secret=MZXW6&issuer=x%7Fy", &buf));
    // 0x20 (space) and 0x7E (~) are the neighbours that stay valid.
    const k = try parse("otpauth://totp/a%20b%7E?secret=MZXW6", &buf);
    try testing.expectEqualStrings("a b~", k.account);
}

test "parse: a decimal field that overflows u64 is InvalidCounter (no wrap-around)" {
    // 20 nines is 10^20 - 1 > 2^64 - 1 (about 1.8e19): the multiply by 10
    // overflows before the add does, so a wrapping multiply would let it through.
    var buf: [128]u8 = undefined;
    try testing.expectError(error.InvalidCounter, parse("otpauth://hotp/x?secret=MZXW6&counter=99999999999999999999", &buf));
    try testing.expectError(error.InvalidCounter, parse("otpauth://hotp/x?secret=MZXW6&counter=184467440737095516160", &buf));
}

test "parse: a buffer that exactly fits the decoded fields is enough" {
    // Decoded sizes: account "a" = 1, secret MFRGGZDF = 5 bytes, issuer "ab"
    // = 2; 8 bytes in total. `BufferTooSmall` is only for a field that does
    // not fit, so the last field (issuer) landing on the very last byte
    // must succeed.
    var buf: [8]u8 = undefined;
    const k = try parse("otpauth://totp/a?secret=MFRGGZDF&issuer=ab", &buf);
    try testing.expectEqualStrings("a", k.account);
    try testing.expectEqualStrings("abcde", k.secret);
    try testing.expectEqualStrings("ab", k.issuer.?);
    var short: [7]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, parse("otpauth://totp/a?secret=MFRGGZDF&issuer=ab", &short));
}

test "format: period 86400 is accepted, 86401 is not; the unreserved set includes ~" {
    var out: [256]u8 = undefined;
    // Documented bound `period` 1..86400 (the same one `parse` enforces).
    try testing.expectEqualStrings(
        "otpauth://totp/x?secret=MZXW6&period=86400",
        try render(&out, .{ .kind = .totp, .secret = "foo", .account = "x", .period = max_period }),
    );
    var w = std.Io.Writer.fixed(&out);
    try testing.expectError(error.InvalidPeriod, format(&w, .{ .kind = .totp, .secret = "foo", .account = "x", .period = max_period + 1 }));
    // Percent-encoding escapes everything but `A-Za-z0-9-._~` (RFC 3986 unreserved).
    try testing.expectEqualStrings(
        "otpauth://totp/a-b.c_d~e?secret=MZXW6",
        try render(&out, .{ .kind = .totp, .secret = "foo", .account = "a-b.c_d~e" }),
    );
}
