// SPDX-License-Identifier: MIT

//! OpenSSH `known_hosts` (sshd(8), "SSH_KNOWN_HOSTS FILE FORMAT") as a
//! ready-made host-key policy — Go's `knownhosts` package. The module still
//! touches no filesystem: the caller reads the file and hands the text in, and
//! appends the line `writeLine` produces when it decides to trust a new key.
//!
//! A line is `[@marker] patterns keytype base64-key [comment]`:
//!   - patterns — comma-separated; `*` and `?` wildcards, a leading `!`
//!     negates; a non-22 port is spelled `[host]:port`; or one hashed entry
//!     `|1|base64(salt)|base64(HMAC-SHA1(salt, name))`;
//!   - `@revoked` — this key is refused for every host, whatever else says;
//!   - `@cert-authority` — a CA for host certificates (not supported here
//!     yet: certificates are the Go-parity plan's P3), skipped.
//!
//! The name looked up is the host lowercased, as OpenSSH's client does before
//! it consults the file (and `ssh-keygen -H` before it hashes): `host` for
//! port 22, `[host]:port` otherwise.
//!
//! Verdicts, in OpenSSH's order: a `@revoked` line with this key → `revoked`;
//! a matching line with this key → `accept`; a matching line with the same
//! key TYPE and other key material → `key_mismatch`; otherwise
//! `unknown_host` (including a host known only under other key types, which
//! OpenSSH also treats as a key to confirm, not as an attack).

const std = @import("std");
const keys = @import("keys.zig");
const transport = @import("transport.zig");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const b64 = std.base64.standard;

pub const Marker = enum { none, cert_authority, revoked };

/// One usable `known_hosts` line.
pub const Entry = struct {
    marker: Marker,
    /// The raw host-pattern field; ask `matches`.
    patterns: []const u8,
    key: keys.PublicKey,
    comment: []const u8,

    /// Whether this line names `host`:`port` (`host` as the caller dialled
    /// it; lowercased here).
    pub fn matches(self: Entry, host: []const u8, port: u16) bool {
        var name_buf: [max_name_len]u8 = undefined;
        const name = lookupName(&name_buf, host, port) orelse return false;
        return matchPatterns(self.patterns, name);
    }
};

/// Longest host name handled: a DNS name (253) in `[…]:65535` form.
pub const max_name_len = 253 + 8;

/// The lookup name: `host` lowercased, as `[host]:port` unless `port` is 22.
/// Null when `host` is empty or longer than a DNS name.
pub fn lookupName(out: *[max_name_len]u8, host: []const u8, port: u16) ?[]const u8 {
    if (host.len == 0 or host.len > 253) return null;
    var w: std.Io.Writer = .fixed(out);
    if (port == 22) {
        for (host) |c| w.writeByte(std.ascii.toLower(c)) catch unreachable;
    } else {
        w.writeByte('[') catch unreachable;
        for (host) |c| w.writeByte(std.ascii.toLower(c)) catch unreachable;
        w.print("]:{d}", .{port}) catch unreachable;
    }
    return w.buffered();
}

/// OpenSSH's `match_pattern`: `*` any run, `?` one character, the rest
/// compared without regard to ASCII case.
fn globMatch(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    var star_p: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and pattern[p] == '*') {
            star_p = p;
            star_n = n;
            p += 1;
        } else if (p < pattern.len and (pattern[p] == '?' or std.ascii.toLower(pattern[p]) == std.ascii.toLower(name[n]))) {
            p += 1;
            n += 1;
        } else if (star_p) |sp| {
            p = sp + 1;
            star_n += 1;
            n = star_n;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

/// `|1|salt|hash` against `name`: HMAC-SHA1 keyed with the salt.
fn hashedMatch(entry: []const u8, name: []const u8) bool {
    const rest = entry["|1|".len..];
    const bar = std.mem.indexOfScalar(u8, rest, '|') orelse return false;
    var salt: [64]u8 = undefined;
    var want: [HmacSha1.mac_length]u8 = undefined;
    const s_len = b64.Decoder.calcSizeForSlice(rest[0..bar]) catch return false;
    if (s_len > salt.len) return false;
    b64.Decoder.decode(salt[0..s_len], rest[0..bar]) catch return false;
    const hash_len = b64.Decoder.calcSizeForSlice(rest[bar + 1 ..]) catch return false;
    if (hash_len != want.len) return false;
    b64.Decoder.decode(&want, rest[bar + 1 ..]) catch return false;
    var got: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&got, name, salt[0..s_len]);
    return std.mem.eql(u8, &got, &want);
}

/// A pattern list against an already-normalised lookup name: true when some
/// plain pattern matches and no negated one does (sshd(8)).
fn matchPatterns(patterns: []const u8, name: []const u8) bool {
    if (std.mem.startsWith(u8, patterns, "|1|")) return hashedMatch(patterns, name);
    var hit = false;
    var it = std.mem.splitScalar(u8, patterns, ',');
    while (it.next()) |raw| {
        if (raw.len == 0) continue;
        const negated = raw[0] == '!';
        const pat = if (negated) raw[1..] else raw;
        if (!globMatch(pat, name)) continue;
        if (negated) return false;
        hit = true;
    }
    return hit;
}

pub const LineError = keys.LineError;

/// Parse one `known_hosts` line; the key blob is decoded into `blob_buf`.
pub fn parseLine(line_in: []const u8, blob_buf: []u8) LineError!Entry {
    var line = std.mem.trim(u8, line_in, " \t\r\n");
    if (line.len == 0 or line[0] == '#') return error.InvalidLine;
    var marker: Marker = .none;
    if (line[0] == '@') {
        const end = std.mem.indexOfAny(u8, line, " \t") orelse return error.InvalidLine;
        const word = line[0..end];
        marker = if (std.mem.eql(u8, word, "@revoked"))
            .revoked
        else if (std.mem.eql(u8, word, "@cert-authority"))
            .cert_authority
        else
            return error.InvalidLine;
        line = std.mem.trimStart(u8, line[end..], " \t");
    }
    const end = std.mem.indexOfAny(u8, line, " \t") orelse return error.InvalidLine;
    // `keys.parseAuthorizedKeyLine` would also accept an options field here;
    // the rest of a known_hosts line is exactly `keytype base64 [comment]`.
    const fields = std.mem.trimStart(u8, line[end..], " \t");
    if (fields.len == 0 or fields[0] == '#') return error.InvalidLine;
    const r = try keys.parseAuthorizedKeyLine(fields, blob_buf);
    if (r.options.len != 0) return error.InvalidLine;
    return .{ .marker = marker, .patterns = line[0..end], .key = r.key, .comment = r.comment };
}

/// Walks a `known_hosts` file, skipping blank lines, comments and lines this
/// module cannot use; `skipped` counts the last.
pub const Iterator = struct {
    rest: []const u8,
    line_number: usize = 0,
    skipped: usize = 0,

    pub fn init(text: []const u8) Iterator {
        return .{ .rest = text };
    }

    pub fn next(self: *Iterator, blob_buf: []u8) ?Entry {
        while (self.rest.len != 0) {
            const end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse self.rest.len;
            const line = self.rest[0..end];
            self.rest = if (end < self.rest.len) self.rest[end + 1 ..] else self.rest[self.rest.len..];
            self.line_number += 1;
            const t = std.mem.trim(u8, line, " \t\r");
            if (t.len == 0 or t[0] == '#') continue;
            if (parseLine(t, blob_buf)) |e| return e else |_| self.skipped += 1;
        }
        return null;
    }
};

/// The verdict `known_hosts` text gives for `key_blob` offered by
/// `host`:`port` (module doc for the order). Pure: the text is not changed.
// secret-api-ok: `key_blob` is the server's PUBLIC host key.
pub fn check(text: []const u8, host: []const u8, port: u16, key_blob: []const u8) transport.HostKeyVerdict {
    const offered = keys.PublicKey.parse(key_blob) catch return .{ .reject = .other };
    var name_buf: [max_name_len]u8 = undefined;
    const name = lookupName(&name_buf, host, port) orelse return .{ .reject = .unknown_host };
    var buf: [keys.max_blob_len]u8 = undefined;

    // Revocation first: one pass over the whole file, any host.
    var it = Iterator.init(text);
    while (it.next(&buf)) |e| {
        if (e.marker == .revoked and e.key.eql(offered)) return .{ .reject = .revoked };
    }
    var mismatch = false;
    it = Iterator.init(text);
    while (it.next(&buf)) |e| {
        if (e.marker != .none or !matchPatterns(e.patterns, name)) continue;
        if (e.key.eql(offered)) return .accept;
        if (e.key.kind == offered.kind) mismatch = true;
    }
    return .{ .reject = if (mismatch) .key_mismatch else .unknown_host };
}

/// A `transport.HostKeyVerifier` over `known_hosts` text the caller loaded.
/// `text` must outlive every handshake that uses the verifier.
pub const KnownHosts = struct {
    text: []const u8,

    fn verify(ctx: *anyopaque, info: transport.HostKeyInfo) transport.HostKeyVerdict {
        const self: *const KnownHosts = @ptrCast(@alignCast(ctx));
        return check(self.text, info.host, info.port, info.key_blob);
    }

    pub fn verifier(self: *KnownHosts) transport.HostKeyVerifier {
        return .{ .ctx = self, .verifyFn = verify };
    }
};

/// A `transport.HostKeyVerifier` that accepts exactly one key (Go's
/// `FixedHostKey`); `blob` is borrowed for the verifier's lifetime.
pub const FixedHostKey = struct {
    blob: []const u8,

    fn verify(ctx: *anyopaque, info: transport.HostKeyInfo) transport.HostKeyVerdict {
        const self: *const FixedHostKey = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, self.blob, info.key_blob)) return .accept;
        return .{ .reject = .key_mismatch };
    }

    pub fn verifier(self: *FixedHostKey) transport.HostKeyVerifier {
        return .{ .ctx = self, .verifyFn = verify };
    }
};

/// Salt length `ssh-keygen -H` uses (the SHA-1 output length).
pub const salt_len = HmacSha1.mac_length;

/// Write a hashed pattern `|1|salt|hash` for `host`:`port` (Go's
/// `HashHostname`). The salt must be fresh random bytes per line — a reused
/// salt lets a reader test one guess against every line at once.
pub fn writeHashedName(w: *std.Io.Writer, host: []const u8, port: u16, salt: *const [salt_len]u8) std.Io.Writer.Error!void {
    var name_buf: [max_name_len]u8 = undefined;
    const name = lookupName(&name_buf, host, port) orelse return error.WriteFailed;
    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, name, salt);
    var enc: [28]u8 = undefined;
    try w.writeAll("|1|");
    try w.writeAll(b64.Encoder.encode(&enc, salt));
    try w.writeByte('|');
    try w.writeAll(b64.Encoder.encode(&enc, &mac));
}

/// Write a `known_hosts` line for `key` at `host`:`port`, hashed when `salt`
/// is given (what `ssh` writes with `HashKnownHosts yes`), plain otherwise.
pub fn writeLine(w: *std.Io.Writer, host: []const u8, port: u16, key: keys.PublicKey, salt: ?*const [salt_len]u8) std.Io.Writer.Error!void {
    if (salt) |s| {
        try writeHashedName(w, host, port, s);
    } else {
        var name_buf: [max_name_len]u8 = undefined;
        try w.writeAll(lookupName(&name_buf, host, port) orelse return error.WriteFailed);
    }
    try w.writeByte(' ');
    try keys.writeAuthorizedKey(w, key, "");
}

// ── tests ──────────────────────────────────────────────────────────────────

const hv = @import("hostkey_vectors.zig");
const tt = std.testing;

fn blobOf(buf: []u8, text: []const u8) []u8 {
    const n = b64.Decoder.calcSizeForSlice(text) catch unreachable;
    b64.Decoder.decode(buf[0..n], text) catch unreachable;
    return buf[0..n];
}

test "globMatch: OpenSSH wildcards, case-insensitive" {
    try tt.expect(globMatch("*.example.com", "a.b.EXAMPLE.com"));
    try tt.expect(!globMatch("*.example.com", "example.com"));
    try tt.expect(globMatch("host?", "host1"));
    try tt.expect(!globMatch("host?", "host12"));
    try tt.expect(globMatch("*", "anything"));
    try tt.expect(globMatch("a*b*c", "aXXbYYc"));
    try tt.expect(!globMatch("a*b*c", "aXXbYY"));
    try tt.expect(globMatch("[*.lan]:2222", "[box.lan]:2222"));
}

test "matchPatterns: negation wins, empty items ignored" {
    try tt.expect(matchPatterns("*.lan,!evil.lan", "good.lan"));
    try tt.expect(!matchPatterns("*.lan,!evil.lan", "evil.lan"));
    try tt.expect(!matchPatterns("!evil.lan", "other.lan"));
    try tt.expect(matchPatterns("a,,b", "b"));
}

test "hashed names equal what ssh-keygen -H writes (OpenSSH 10.2, 2026-10-10)" {
    // `ssh-keygen -H` over the line `Example.COM ssh-ed25519 …`: the name is
    // lowercased before hashing.
    const line = "|1|SrxGMHuk9oiuwIgLV7hiRk2MLsE=|LU5223GUYLZ3JlZFOJW0pEfLlS8= ssh-ed25519 " ++ hv.ed25519_pub_b64;
    var buf: [keys.max_blob_len]u8 = undefined;
    const e = try parseLine(line, &buf);
    try tt.expect(e.matches("example.com", 22));
    try tt.expect(e.matches("EXAMPLE.com", 22));
    try tt.expect(!e.matches("example.org", 22));
    try tt.expect(!e.matches("example.com", 2222));

    // And writing it back with the same salt reproduces ssh-keygen's bytes.
    var salt: [salt_len]u8 = undefined;
    _ = try b64.Decoder.decode(&salt, "SrxGMHuk9oiuwIgLV7hiRk2MLsE=");
    var out: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeLine(&w, "Example.COM", 22, e.key, &salt);
    try tt.expectEqualStrings(line ++ "\n", w.buffered());
}

test "check: accept, mismatch, unknown type, revoked, port form" {
    var b1: [keys.max_blob_len]u8 = undefined;
    var b2: [keys.max_blob_len]u8 = undefined;
    var b3: [keys.max_blob_len]u8 = undefined;
    const ed = blobOf(&b1, hv.ed25519_pub_b64);
    const ed_other = blobOf(&b2, hv.ed25519_enc_ctr_pub_b64);
    const p256 = blobOf(&b3, hv.ecdsa_p256_pub_b64);
    const text =
        "# known hosts\n" ++
        "box.lan,10.0.0.5 ssh-ed25519 " ++ hv.ed25519_pub_b64 ++ "\n" ++
        "[box.lan]:2222 ssh-ed25519 " ++ hv.ed25519_enc_ctr_pub_b64 ++ " other port\n" ++
        "@cert-authority *.lan ssh-ed25519 " ++ hv.ed25519_enc_cbc_pub_b64 ++ "\n" ++
        "@revoked * ecdsa-sha2-nistp256 " ++ hv.ecdsa_p256_pub_b64 ++ "\n" ++
        "broken line\n";
    try tt.expectEqual(transport.HostKeyVerdict.accept, check(text, "BOX.lan", 22, ed));
    try tt.expectEqual(transport.HostKeyVerdict.accept, check(text, "10.0.0.5", 22, ed));
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .key_mismatch }, check(text, "box.lan", 22, ed_other));
    try tt.expectEqual(transport.HostKeyVerdict.accept, check(text, "box.lan", 2222, ed_other));
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .key_mismatch }, check(text, "box.lan", 2222, ed));
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .unknown_host }, check(text, "new.lan", 22, ed));
    // Revoked beats everything, for any host.
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .revoked }, check(text, "box.lan", 22, p256));
    // The cert-authority line is not a host key.
    var b4: [keys.max_blob_len]u8 = undefined;
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .unknown_host }, check(text, "x.lan", 22, blobOf(&b4, hv.ed25519_enc_cbc_pub_b64)));

    var it = Iterator.init(text);
    var n: usize = 0;
    while (it.next(&b4)) |_| n += 1;
    try tt.expectEqual(@as(usize, 4), n);
    try tt.expectEqual(@as(usize, 1), it.skipped);
}

test "check: a host known only under another key type is unknown, not mismatched" {
    var b: [keys.max_blob_len]u8 = undefined;
    const text = "box.lan ecdsa-sha2-nistp384 " ++ hv.ecdsa_p384_pub_b64 ++ "\n";
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .unknown_host }, check(text, "box.lan", 22, blobOf(&b, hv.ed25519_pub_b64)));
}

test "KnownHosts and FixedHostKey as verifiers" {
    var b: [keys.max_blob_len]u8 = undefined;
    const ed = blobOf(&b, hv.ed25519_pub_b64);
    var kh: KnownHosts = .{ .text = "box.lan ssh-ed25519 " ++ hv.ed25519_pub_b64 ++ "\n" };
    const v = kh.verifier();
    try tt.expectEqual(transport.HostKeyVerdict.accept, v.verify(.{ .host = "box.lan", .port = 22, .key_type = "ssh-ed25519", .key_blob = ed }));
    var fixed: FixedHostKey = .{ .blob = ed };
    const fv = fixed.verifier();
    try tt.expectEqual(transport.HostKeyVerdict.accept, fv.verify(.{ .host = "", .port = 22, .key_type = "ssh-ed25519", .key_blob = ed }));
    var b2: [keys.max_blob_len]u8 = undefined;
    try tt.expectEqual(transport.HostKeyVerdict{ .reject = .key_mismatch }, fv.verify(.{ .host = "", .port = 22, .key_type = "ssh-ed25519", .key_blob = blobOf(&b2, hv.ed25519_enc_ctr_pub_b64) }));
}

test "writeLine plain: port 22 bare, others bracketed, round-trips" {
    var b: [keys.max_blob_len]u8 = undefined;
    const key = try keys.PublicKey.parse(blobOf(&b, hv.ecdsa_p521_pub_b64));
    var out: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeLine(&w, "Box.Lan", 2222, key, null);
    try tt.expect(std.mem.startsWith(u8, w.buffered(), "[box.lan]:2222 ecdsa-sha2-nistp521 "));
    var b2: [keys.max_blob_len]u8 = undefined;
    try tt.expectEqual(transport.HostKeyVerdict.accept, check(w.buffered(), "box.lan", 2222, key.blob));
    _ = &b2;
}
