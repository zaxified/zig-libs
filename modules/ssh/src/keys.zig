// SPDX-License-Identifier: MIT

//! Public keys as values: the wire blob → typed key layer that `known_hosts`,
//! `authorized_keys`, fingerprints and certificates all hang on (Go's
//! `ssh.ParsePublicKey` / `ParseAuthorizedKey` / `MarshalAuthorizedKey` /
//! `FingerprintSHA256` / `FingerprintLegacyMD5`).
//!
//! Before this file a key existed only as the raw bytes of `HostKeyInfo.key_blob`
//! or the `publickey` request, and every caller re-parsed it by hand.
//!
//! Formats:
//!   - wire blob — RFC 4253 §6.6 (`ssh-rsa`), RFC 8709 §4 (`ssh-ed25519`),
//!     RFC 5656 §3.1 (`ecdsa-sha2-nistp256/384/521`);
//!   - `authorized_keys` line — sshd(8) "AUTHORIZED_KEYS FILE FORMAT":
//!     `[options] keytype base64-blob [comment]`, options comma-separated with
//!     double-quoted values that may contain `\"`;
//!   - SHA-256 fingerprint — `SHA256:` + unpadded base64 of SHA-256(blob), as
//!     `ssh-keygen -l` prints it; MD5 — colon-separated hex of MD5(blob), Go's
//!     `FingerprintLegacyMD5` shape (`ssh-keygen -E md5` prefixes `MD5:`).
//!
//! Every slice a parsed value carries is borrowed: `PublicKey.blob` from the
//! buffer it was parsed from, an `AuthorizedKey`'s strings from the input text.
//! Nothing here allocates.

const std = @import("std");
const messages = @import("messages.zig");
const transport = @import("transport.zig");
const rsa = @import("rsa");
const p521 = @import("p521");

const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const EcdsaP521 = p521.EcdsaP521Sha512;
const Cursor = messages.Cursor;
const b64 = std.base64.standard;

/// The key types this module can parse and verify with.
pub const KeyType = enum {
    ed25519,
    rsa,
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_p521,

    /// The key-type string inside the blob and in the second field of a
    /// `known_hosts` line (`ssh-rsa` for RSA, whatever hash signs with it).
    pub fn name(self: KeyType) []const u8 {
        return switch (self) {
            .ed25519 => "ssh-ed25519",
            .rsa => "ssh-rsa",
            .ecdsa_p256 => "ecdsa-sha2-nistp256",
            .ecdsa_p384 => "ecdsa-sha2-nistp384",
            .ecdsa_p521 => "ecdsa-sha2-nistp521",
        };
    }

    /// The inverse of `name`; null for any other string (certificates,
    /// `sk-*` security keys and `ssh-dss` are not supported).
    pub fn fromName(s: []const u8) ?KeyType {
        inline for (std.meta.fields(KeyType)) |f| {
            const k: KeyType = @enumFromInt(f.value);
            if (std.mem.eql(u8, s, k.name())) return k;
        }
        return null;
    }
};

/// Largest blob `PublicKey.parse` accepts: an RSA key at the `rsa` module's
/// modulus cap (`string "ssh-rsa"`, `mpint e` of at most 4 bytes plus a sign
/// byte, `mpint n` with its sign byte). Every other type is smaller.
pub const max_blob_len = (4 + 7) + (4 + 5) + (4 + 1 + rsa.max_modulus_len);

/// Length of `PublicKey.fingerprintSha256`'s result: `SHA256:` + 43.
pub const fingerprint_sha256_len = 7 + 43;
/// Length of `PublicKey.fingerprintMd5`'s result: 16 hex pairs, 15 colons.
pub const fingerprint_md5_len = 16 * 3 - 1;

pub const ParseError = error{
    /// The blob is malformed: truncated, trailing bytes, a wrong-length
    /// field, a curve name that is not the type's, a point not on the curve,
    /// an RSA modulus or exponent the `rsa` module refuses.
    InvalidKey,
    /// Well-formed framing, but a key type this module does not support.
    UnsupportedKeyType,
};

pub const VerifyError = error{
    /// The signature blob is malformed, names an algorithm that does not
    /// belong to this key's type, or does not verify.
    InvalidSignature,
    /// The signature algorithm is not one this module can verify (e.g. the
    /// SHA-1 `ssh-rsa` signature).
    UnsupportedAlgorithm,
};

/// A parsed, validated public key. `blob` is the canonical wire encoding —
/// what `known_hosts`' base64 field decodes to, what the fingerprints hash and
/// what two keys are compared by — borrowed from the caller's buffer.
pub const PublicKey = struct {
    kind: KeyType,
    blob: []const u8,

    /// Parse and validate a wire blob (Go's `ParsePublicKey`). Refuses
    /// trailing bytes after the key's last field, as Go does; checks every
    /// field the verification path would reject later (point on the curve,
    /// curve name = type, RSA bounds), so a key that parses can be used.
    pub fn parse(blob: []const u8) ParseError!PublicKey {
        if (blob.len > max_blob_len) return error.InvalidKey;
        var c = Cursor{ .b = blob };
        const type_name = c.string() catch return error.InvalidKey;
        const kind = KeyType.fromName(type_name) orelse return error.UnsupportedKeyType;
        switch (kind) {
            .ed25519 => {
                const pk = c.string() catch return error.InvalidKey;
                if (pk.len != Ed25519.PublicKey.encoded_length) return error.InvalidKey;
                _ = Ed25519.PublicKey.fromBytes(pk[0..32].*) catch return error.InvalidKey;
            },
            .rsa => {
                const e = c.string() catch return error.InvalidKey;
                const n = c.string() catch return error.InvalidKey;
                // mpints: a set top bit is a negative number (RFC 4251 §5).
                if (e.len == 0 or n.len == 0 or e[0] & 0x80 != 0 or n[0] & 0x80 != 0) return error.InvalidKey;
                _ = rsa.PublicKey.fromBytes(n, e) catch return error.InvalidKey;
            },
            .ecdsa_p256 => try parseEcdsa(EcdsaP256, "nistp256", &c),
            .ecdsa_p384 => try parseEcdsa(EcdsaP384, "nistp384", &c),
            .ecdsa_p521 => try parseEcdsa(EcdsaP521, "nistp521", &c),
        }
        if (!c.atEnd()) return error.InvalidKey;
        return .{ .kind = kind, .blob = blob };
    }

    /// Two keys are the same key when their canonical blobs are equal.
    pub fn eql(a: PublicKey, b: PublicKey) bool {
        return std.mem.eql(u8, a.blob, b.blob);
    }

    /// Verify an SSH signature blob (`string algorithm || string signature`)
    /// over `data` (Go's `PublicKey.Verify`). The algorithm must belong to
    /// this key's type: `rsa-sha2-256`/`-512` for `ssh-rsa`, the type name
    /// itself for the others.
    pub fn verify(self: PublicKey, sig_blob: []const u8, data: []const u8) VerifyError!void {
        var c = Cursor{ .b = sig_blob };
        const algorithm = c.string() catch return error.InvalidSignature;
        _ = c.string() catch return error.InvalidSignature;
        if (!c.atEnd()) return error.InvalidSignature;
        const blob_type = transport.keyBlobTypeFor(algorithm) orelse return error.UnsupportedAlgorithm;
        if (!std.mem.eql(u8, blob_type, self.kind.name())) return error.InvalidSignature;
        transport.verifySignature(self.kind.name(), self.blob, sig_blob, data) catch |e| return switch (e) {
            error.UnsupportedAlgorithm => error.UnsupportedAlgorithm,
            else => error.InvalidSignature,
        };
    }

    /// `SHA256:<unpadded base64>` — what `ssh-keygen -l` and OpenSSH's
    /// "host key fingerprint is" line print (Go's `FingerprintSHA256`).
    pub fn fingerprintSha256(self: PublicKey, out: *[fingerprint_sha256_len]u8) []const u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.blob, &digest, .{});
        @memcpy(out[0..7], "SHA256:");
        _ = std.base64.standard_no_pad.Encoder.encode(out[7..], &digest);
        return out;
    }

    /// Colon-separated lowercase hex of MD5(blob), Go's
    /// `FingerprintLegacyMD5` (`ssh-keygen -E md5` prints it after `MD5:`).
    pub fn fingerprintMd5(self: PublicKey, out: *[fingerprint_md5_len]u8) []const u8 {
        var digest: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(self.blob, &digest, .{});
        const hex = "0123456789abcdef";
        for (digest, 0..) |byte, i| {
            out[i * 3] = hex[byte >> 4];
            out[i * 3 + 1] = hex[byte & 0xf];
            if (i != 15) out[i * 3 + 2] = ':';
        }
        return out;
    }
};

fn parseEcdsa(comptime E: type, comptime curve: []const u8, c: *Cursor) ParseError!void {
    const curve_name = c.string() catch return error.InvalidKey;
    if (!std.mem.eql(u8, curve_name, curve)) return error.InvalidKey;
    const q = c.string() catch return error.InvalidKey;
    // SEC1 uncompressed or compressed; never the one-byte identity encoding.
    if (q.len == 0 or (q[0] != 0x02 and q[0] != 0x03 and q[0] != 0x04)) return error.InvalidKey;
    _ = E.PublicKey.fromSec1(q) catch return error.InvalidKey;
}

/// Write `key` as an `authorized_keys` / `known_hosts` key field:
/// `type base64[ comment]\n` (Go's `MarshalAuthorizedKey`, which has no
/// comment; pass `""` for the same bytes).
pub fn writeAuthorizedKey(w: *std.Io.Writer, key: PublicKey, comment: []const u8) std.Io.Writer.Error!void {
    var buf: [b64.Encoder.calcSize(max_blob_len)]u8 = undefined;
    try w.writeAll(key.kind.name());
    try w.writeByte(' ');
    try w.writeAll(b64.Encoder.encode(buf[0..b64.Encoder.calcSize(key.blob.len)], key.blob));
    if (comment.len != 0) {
        try w.writeByte(' ');
        try w.writeAll(comment);
    }
    try w.writeByte('\n');
}

/// One parsed `authorized_keys` line.
pub const AuthorizedKey = struct {
    key: PublicKey,
    /// The raw options field (`from="10.0.0.0/8",no-pty`), `""` if none.
    /// Walk it with `optionIterator`. Interpreting options is the caller's
    /// job, as in Go and OpenSSH's own library layer.
    options: []const u8,
    /// Everything after the base64 field, leading blanks stripped; may be `""`.
    comment: []const u8,

    pub fn optionIterator(self: AuthorizedKey) OptionIterator {
        return .{ .rest = self.options };
    }
};

/// Splits an options field on the commas that are outside double quotes.
/// Each item is returned raw (`command="echo \"hi\""` keeps its quotes and
/// escapes), as Go's `ParseAuthorizedKey` returns them.
pub const OptionIterator = struct {
    rest: []const u8,

    pub fn next(self: *OptionIterator) ?[]const u8 {
        if (self.rest.len == 0) return null;
        var in_quote = false;
        var i: usize = 0;
        while (i < self.rest.len) : (i += 1) {
            const ch = self.rest[i];
            if (ch == '"' and !(i > 0 and self.rest[i - 1] == '\\')) in_quote = !in_quote;
            if (ch == ',' and !in_quote) break;
        }
        const item = self.rest[0..i];
        self.rest = if (i < self.rest.len) self.rest[i + 1 ..] else self.rest[self.rest.len..];
        return item;
    }
};

pub const LineError = ParseError || error{
    /// Not of the shape `[options] keytype base64 [comment]`: an empty line,
    /// a comment, bad base64, an unterminated quote, or a type field that
    /// disagrees with the type inside the blob.
    InvalidLine,
    /// The decoded blob does not fit `blob_buf` (size it `max_blob_len`).
    NoSpaceLeft,
};

fn isBlank(ch: u8) bool {
    return ch == ' ' or ch == '\t';
}

fn trimBlanks(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

/// Parse one `authorized_keys` line. The decoded blob goes into `blob_buf`
/// (`max_blob_len` bytes always suffice); `key.blob` points into it. Tries
/// the line as `keytype base64 …` first and only then as `options keytype
/// base64 …`, the order sshd and Go use, so an option list can never be
/// mistaken for a key.
pub fn parseAuthorizedKeyLine(line_in: []const u8, blob_buf: []u8) LineError!AuthorizedKey {
    const line = trimBlanks(line_in);
    if (line.len == 0 or line[0] == '#') return error.InvalidLine;
    const first_err = if (parseKeyFields(line, blob_buf)) |r| {
        return .{ .key = r.key, .options = "", .comment = r.comment };
    } else |e| e;

    // The options field ends at the first blank outside double quotes.
    var in_quote = false;
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        const ch = line[i];
        if (!in_quote and isBlank(ch)) break;
        if (ch == '"' and !(i > 0 and line[i - 1] == '\\')) in_quote = !in_quote;
    }
    if (in_quote or i == line.len) return first_err;
    const r = parseKeyFields(trimBlanks(line[i..]), blob_buf) catch return first_err;
    return .{ .key = r.key, .options = line[0..i], .comment = r.comment };
}

const KeyFields = struct { key: PublicKey, comment: []const u8 };

/// `keytype base64[ comment]` with `line` already trimmed.
fn parseKeyFields(line: []const u8, blob_buf: []u8) LineError!KeyFields {
    const type_end = std.mem.indexOfAny(u8, line, " \t") orelse return error.InvalidLine;
    const type_name = line[0..type_end];
    const rest = std.mem.trimStart(u8, line[type_end..], " \t");
    const b64_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
    const text = rest[0..b64_end];
    const n = b64.Decoder.calcSizeForSlice(text) catch return error.InvalidLine;
    if (n > blob_buf.len) return error.NoSpaceLeft;
    b64.Decoder.decode(blob_buf[0..n], text) catch return error.InvalidLine;
    const key = try PublicKey.parse(blob_buf[0..n]);
    // sshd refuses a line whose type field names another type than the blob.
    if (!std.mem.eql(u8, type_name, key.kind.name())) return error.InvalidLine;
    return .{ .key = key, .comment = std.mem.trimStart(u8, rest[b64_end..], " \t") };
}

/// Walks an `authorized_keys` file, skipping blank lines, comments and lines
/// it cannot use (unsupported key types, malformed lines) the way sshd does
/// — `skipped` counts the last two, so a caller can log that a file holds
/// entries this module ignored.
pub const AuthorizedKeysIterator = struct {
    rest: []const u8,
    /// 1-based number of the line `next` last returned.
    line_number: usize = 0,
    /// Non-blank, non-comment lines skipped so far.
    skipped: usize = 0,

    pub fn init(text: []const u8) AuthorizedKeysIterator {
        return .{ .rest = text };
    }

    /// The next usable entry; its `key.blob` points into `blob_buf`, which
    /// the following call overwrites.
    pub fn next(self: *AuthorizedKeysIterator, blob_buf: []u8) ?AuthorizedKey {
        while (self.rest.len != 0) {
            const end = std.mem.indexOfScalar(u8, self.rest, '\n') orelse self.rest.len;
            const line = self.rest[0..end];
            self.rest = if (end < self.rest.len) self.rest[end + 1 ..] else self.rest[self.rest.len..];
            self.line_number += 1;
            const t = trimBlanks(line);
            if (t.len == 0 or t[0] == '#') continue;
            if (parseAuthorizedKeyLine(t, blob_buf)) |entry| return entry else |_| self.skipped += 1;
        }
        return null;
    }
};

/// The first entry of `authorized_keys` text whose key is `blob` — the check
/// a server's `AuthorizedKeyCheck` makes (`userauth.zig`) — or null. The
/// entry's options are returned so the caller can enforce them.
pub fn findAuthorizedKey(text: []const u8, blob: []const u8, blob_buf: []u8) ?AuthorizedKey {
    var it = AuthorizedKeysIterator.init(text);
    while (it.next(blob_buf)) |entry| {
        if (std.mem.eql(u8, entry.key.blob, blob)) return entry;
    }
    return null;
}

// ── tests ──────────────────────────────────────────────────────────────────

const hv = @import("hostkey_vectors.zig");
const server = @import("server.zig");

fn decodeB64(buf: []u8, text: []const u8) []u8 {
    const n = b64.Decoder.calcSizeForSlice(text) catch unreachable;
    b64.Decoder.decode(buf[0..n], text) catch unreachable;
    return buf[0..n];
}

/// Fingerprints printed by OpenSSH 10.2's `ssh-keygen -lf` (`-E sha256` and
/// `-E md5`) for the fixture keys of `hostkey_vectors.zig`, 2026-10-10.
const fingerprint_vectors = [_]struct { b64: []const u8, kind: KeyType, sha256: []const u8, md5: []const u8 }{
    .{ .b64 = hv.ed25519_pub_b64, .kind = .ed25519, .sha256 = "SHA256:iL8zJBKxvwD8D8mh37xpHo+AJmjAkl0P7cxIPSRvS/k", .md5 = "5b:75:48:da:48:9f:5d:97:fa:e8:7b:b6:06:f5:8b:70" },
    .{ .b64 = hv.rsa_pub_b64, .kind = .rsa, .sha256 = "SHA256:JFma1K0t5v4k6tBK/MtiIddBR3ENmI9L6ruNbfLCWT8", .md5 = "da:e9:88:ae:04:26:c3:66:38:6b:f8:b5:c5:bb:99:cf" },
    .{ .b64 = hv.ecdsa_p256_pub_b64, .kind = .ecdsa_p256, .sha256 = "SHA256:Jhhstfiy9S+p3EG2Xrv4K4Qk4stfxsk9UpX2bOut+Yc", .md5 = "4b:1e:1d:40:83:db:c9:5f:8b:03:34:47:9a:87:38:36" },
    .{ .b64 = hv.ecdsa_p384_pub_b64, .kind = .ecdsa_p384, .sha256 = "SHA256:Ygebt15qWfTetHAwC2+1STLRqmFzq2ILHxndacKfasw", .md5 = "39:4f:86:72:1b:33:8a:c3:16:0d:f6:79:33:b4:4f:3f" },
    .{ .b64 = hv.ecdsa_p521_pub_b64, .kind = .ecdsa_p521, .sha256 = "SHA256:XjX6I4hiSnTUr7TU6LzIjULW/41S2BuJOAqfLtMePYM", .md5 = "90:dc:9f:a1:87:87:7c:01:04:e6:ae:04:40:12:00:9a" },
};

test "parse + fingerprints match ssh-keygen for every supported type" {
    const t = std.testing;
    for (fingerprint_vectors) |v| {
        var buf: [max_blob_len]u8 = undefined;
        const key = try PublicKey.parse(decodeB64(&buf, v.b64));
        try t.expectEqual(v.kind, key.kind);
        var fs: [fingerprint_sha256_len]u8 = undefined;
        try t.expectEqualStrings(v.sha256, key.fingerprintSha256(&fs));
        var fm: [fingerprint_md5_len]u8 = undefined;
        try t.expectEqualStrings(v.md5, key.fingerprintMd5(&fm));
    }
}

test "parse refuses truncation, trailing bytes and foreign types at every length" {
    const t = std.testing;
    for (fingerprint_vectors) |v| {
        var buf: [max_blob_len + 1]u8 = undefined;
        const blob = decodeB64(&buf, v.b64);
        for (0..blob.len) |n| {
            if (PublicKey.parse(blob[0..n])) |_| return error.TestUnexpectedResult else |_| {}
        }
        buf[blob.len] = 0;
        try t.expectError(error.InvalidKey, PublicKey.parse(buf[0 .. blob.len + 1]));
    }
    // A well-framed but unsupported type, and a certificate type.
    const dss = "\x00\x00\x00\x07ssh-dss";
    try t.expectError(error.UnsupportedKeyType, PublicKey.parse(dss));
    const cert = "\x00\x00\x00\x1cssh-ed25519-cert-v01@openssh.com";
    try t.expectError(error.UnsupportedKeyType, PublicKey.parse(cert));
}

test "parse refuses a curve name that is not the type's and an off-curve point" {
    const t = std.testing;
    var buf: [max_blob_len]u8 = undefined;
    const blob = decodeB64(&buf, hv.ecdsa_p256_pub_b64);
    // `string "ecdsa-sha2-nistp256"` (4+19), then `string "nistp256"`.
    var bad: [max_blob_len]u8 = undefined;
    @memcpy(bad[0..blob.len], blob);
    bad[4 + 19 + 4 + 7] = '4'; // "nistp254"
    try t.expectError(error.InvalidKey, PublicKey.parse(bad[0..blob.len]));
    @memcpy(bad[0..blob.len], blob);
    bad[blob.len - 1] ^= 1; // y off the curve
    try t.expectError(error.InvalidKey, PublicKey.parse(bad[0..blob.len]));
}

test "verify accepts the key's own signature, refuses another type's algorithm" {
    const t = std.testing;
    const gpa = t.allocator;
    const pems = [_][]const u8{ hv.ed25519_key, hv.rsa_key, hv.ecdsa_p256_key, hv.ecdsa_p384_key, hv.ecdsa_p521_key };
    for (pems) |pem| {
        var hk: server.HostKey = undefined;
        try hk.fromOpenSSH(pem, null);
        const blob = try hk.publicBlob(gpa);
        defer gpa.free(blob);
        const key = try PublicKey.parse(blob);
        const sig = try hk.sign(gpa, "data to sign");
        defer gpa.free(sig);
        try key.verify(sig, "data to sign");
        try t.expectError(error.InvalidSignature, key.verify(sig, "data to sigN"));

        // Same signature bytes relabelled with another type's algorithm.
        var c = Cursor{ .b = sig };
        _ = try c.string();
        const raw = try c.string();
        var relabelled: std.Io.Writer.Allocating = .init(gpa);
        defer relabelled.deinit();
        const other = if (key.kind == .ed25519) "ecdsa-sha2-nistp256" else "ssh-ed25519";
        try messages.writeString(&relabelled.writer, other);
        try messages.writeString(&relabelled.writer, raw);
        try t.expectError(error.InvalidSignature, key.verify(relabelled.written(), "data to sign"));
    }
}

test "verify: the SHA-1 ssh-rsa signature algorithm is unsupported" {
    const t = std.testing;
    var buf: [max_blob_len]u8 = undefined;
    const key = try PublicKey.parse(decodeB64(&buf, hv.rsa_pub_b64));
    const sig = "\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01\x00";
    try t.expectError(error.UnsupportedAlgorithm, key.verify(sig, "x"));
}

test "writeAuthorizedKey round-trips through parseAuthorizedKeyLine" {
    const t = std.testing;
    for (fingerprint_vectors) |v| {
        var buf: [max_blob_len]u8 = undefined;
        const key = try PublicKey.parse(decodeB64(&buf, v.b64));
        var out: [4096]u8 = undefined;
        var w: std.Io.Writer = .fixed(&out);
        try writeAuthorizedKey(&w, key, "user@host");
        const line = w.buffered();
        try t.expect(std.mem.startsWith(u8, line, v.kind.name()));
        try t.expect(std.mem.endsWith(u8, line, " user@host\n"));
        var buf2: [max_blob_len]u8 = undefined;
        const entry = try parseAuthorizedKeyLine(line, &buf2);
        try t.expect(entry.key.eql(key));
        try t.expectEqualStrings("user@host", entry.comment);
        try t.expectEqualStrings("", entry.options);
    }
}

test "authorized_keys: options with quoted commas and blanks, escaped quotes" {
    const t = std.testing;
    var buf: [max_blob_len]u8 = undefined;
    const line = "from=\"10.0.0.1, 10.0.0.2\",command=\"echo \\\"a b\\\"\",no-pty ssh-ed25519 " ++ hv.ed25519_pub_b64 ++ " alice laptop";
    const e = try parseAuthorizedKeyLine(line, &buf);
    try t.expectEqual(KeyType.ed25519, e.key.kind);
    try t.expectEqualStrings("alice laptop", e.comment);
    var it = e.optionIterator();
    try t.expectEqualStrings("from=\"10.0.0.1, 10.0.0.2\"", it.next().?);
    try t.expectEqualStrings("command=\"echo \\\"a b\\\"\"", it.next().?);
    try t.expectEqualStrings("no-pty", it.next().?);
    try t.expect(it.next() == null);
}

test "authorized_keys: refusals" {
    const t = std.testing;
    var buf: [max_blob_len]u8 = undefined;
    try t.expectError(error.InvalidLine, parseAuthorizedKeyLine("", &buf));
    try t.expectError(error.InvalidLine, parseAuthorizedKeyLine("# ssh-ed25519 " ++ hv.ed25519_pub_b64, &buf));
    // Type field disagrees with the blob.
    try t.expectError(error.InvalidLine, parseAuthorizedKeyLine("ssh-rsa " ++ hv.ed25519_pub_b64, &buf));
    // Unterminated quote in the options.
    try t.expectError(error.InvalidLine, parseAuthorizedKeyLine("command=\"x ssh-ed25519 " ++ hv.ed25519_pub_b64, &buf));
    // Too small a buffer.
    var small: [16]u8 = undefined;
    try t.expectError(error.NoSpaceLeft, parseAuthorizedKeyLine("ssh-ed25519 " ++ hv.ed25519_pub_b64, &small));
}

test "AuthorizedKeysIterator skips what sshd skips and findAuthorizedKey matches by blob" {
    const t = std.testing;
    const text =
        "# comment\n" ++
        "\n" ++
        "ssh-ed25519 " ++ hv.ed25519_pub_b64 ++ " first\r\n" ++
        "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t x\n" ++
        "garbage line\n" ++
        "no-pty ecdsa-sha2-nistp256 " ++ hv.ecdsa_p256_pub_b64 ++ "\n" ++
        "ecdsa-sha2-nistp521 " ++ hv.ecdsa_p521_pub_b64;
    var buf: [max_blob_len]u8 = undefined;
    var it = AuthorizedKeysIterator.init(text);
    try t.expectEqual(KeyType.ed25519, it.next(&buf).?.key.kind);
    try t.expectEqual(@as(usize, 3), it.line_number);
    const e2 = it.next(&buf).?;
    try t.expectEqual(KeyType.ecdsa_p256, e2.key.kind);
    try t.expectEqualStrings("no-pty", e2.options);
    try t.expectEqual(@as(usize, 6), it.line_number);
    try t.expectEqual(KeyType.ecdsa_p521, it.next(&buf).?.key.kind);
    try t.expect(it.next(&buf) == null);
    try t.expectEqual(@as(usize, 2), it.skipped);

    var wanted: [max_blob_len]u8 = undefined;
    const blob = decodeB64(&wanted, hv.ecdsa_p256_pub_b64);
    const hit = findAuthorizedKey(text, blob, &buf).?;
    try t.expectEqualStrings("no-pty", hit.options);
    var other: [max_blob_len]u8 = undefined;
    try t.expect(findAuthorizedKey(text, decodeB64(&other, hv.ecdsa_p384_pub_b64), &buf) == null);
}
