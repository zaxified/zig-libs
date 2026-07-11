// SPDX-License-Identifier: MIT

//! dtls.messages — ClientHello / ServerHello / EncryptedExtensions /
//! Finished message-BODY framing (the bytes after `handshake.zig`'s 12-byte
//! header has been stripped/reassembled). These bodies are structurally
//! identical to TLS 1.3's (RFC 8446 §4.1) — DTLS 1.3 reuses them verbatim
//! (RFC 9147 §5.3/§5.4); only the record and handshake HEADERS differ
//! between TLS and DTLS, never these message shapes.
//!
//! PSK-mode only (RFC 8446 §4.2.11 `pre_shared_key`/`psk_key_exchange_modes`
//! extensions — no certificate path). Fields whose meaning is entirely
//! cryptographic (the PSK binder value, Finished's `verify_data`) are
//! modeled as opaque `[]const u8`: real bytes flow through so framing
//! round-trips, but this file never computes or interprets them — that's
//! `keyschedule.zig`'s job.

const std = @import("std");

pub const MessageError = error{
    BufferTooShort,
    Malformed,
    TooManyExtensions,
    ListTooLong,
};

/// RFC 8446 §4 handshake message types this PSK-only scaffold needs.
/// (`certificate`/`certificate_verify`/`certificate_request` are
/// intentionally omitted — out of scope, see the module doc comment in
/// `root.zig`.)
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    finished = 20,
    _,
};

pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_versions = 43,
    cookie = 44,
    pre_shared_key = 41,
    psk_key_exchange_modes = 45,
    _,
};

/// RFC 9147 §5.3: DTLS 1.3's ClientHello.legacy_version stays {254, 253}
/// ("DTLS 1.2") on the wire, for backward/middlebox compatibility — actual
/// version negotiation happens via the `supported_versions` extension
/// (mirrors TLS 1.3's ClientHello.legacy_version = {3, 3}, RFC 8446 §4.1.2).
pub const legacy_version_dtls12 = [2]u8{ 0xFE, 0xFD };

/// RFC 8446 §4.1.3: the ServerHello.random magic value that means "this is
/// actually a HelloRetryRequest" (same message type, distinguished only by
/// this field). RFC 9147 does not redefine it, so it's reused directly from
/// Zig std's own TLS 1.3 client rather than re-transcribed by hand — a
/// spec-mandated public constant, not an implementation detail worth
/// duplicating: `std.crypto.tls.hello_retry_request_sequence`.
pub const hello_retry_request_random = std.crypto.tls.hello_retry_request_sequence;

pub fn isHelloRetryRequest(random: [32]u8) bool {
    return std.mem.eql(u8, &random, &hello_retry_request_random);
}

// ── generic extension list (RFC 8446 §4.2) ───────────────────────────────

pub const Extension = struct {
    ext_type: u16,
    data: []const u8,
};

/// Encodes `exts` as a u16-length-prefixed list of `{type: u16, length:
/// u16, data}` entries (RFC 8446 §4.2). Returns the slice of `out` used,
/// including the outer 2-byte list length.
pub fn encodeExtensions(exts: []const Extension, out: []u8) MessageError![]u8 {
    var body_len: usize = 0;
    for (exts) |e| body_len += 4 + e.data.len;
    if (body_len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 2 + body_len) return error.BufferTooShort;

    std.mem.writeInt(u16, out[0..2], @intCast(body_len), .big);
    var i: usize = 2;
    for (exts) |e| {
        std.mem.writeInt(u16, out[i..][0..2], e.ext_type, .big);
        std.mem.writeInt(u16, out[i + 2 ..][0..2], @intCast(e.data.len), .big);
        @memcpy(out[i + 4 ..][0..e.data.len], e.data);
        i += 4 + e.data.len;
    }
    return out[0..i];
}

/// Decodes an extension list into caller-supplied `out`. Each returned
/// `Extension.data` aliases into `buf` — no copy.
pub fn decodeExtensions(buf: []const u8, out: []Extension) MessageError![]Extension {
    if (buf.len < 2) return error.BufferTooShort;
    const body_len: usize = std.mem.readInt(u16, buf[0..2], .big);
    if (buf.len < 2 + body_len) return error.BufferTooShort;

    var i: usize = 2;
    const end = 2 + body_len;
    var n: usize = 0;
    while (i < end) {
        if (i + 4 > end) return error.Malformed;
        const ext_type = std.mem.readInt(u16, buf[i..][0..2], .big);
        const len: usize = std.mem.readInt(u16, buf[i + 2 ..][0..2], .big);
        i += 4;
        if (i + len > end) return error.Malformed;
        if (n >= out.len) return error.TooManyExtensions;
        out[n] = .{ .ext_type = ext_type, .data = buf[i..][0..len] };
        n += 1;
        i += len;
    }
    return out[0..n];
}

// ── cookie extension (RFC 8446 §4.2.2, framing reused by DTLS 1.3's
// HelloRetryRequest-based cookie exchange — RFC 9147 §5.3) ──────────────

pub fn encodeCookieExtension(cookie: []const u8, out: []u8) MessageError![]u8 {
    if (cookie.len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < 2 + cookie.len) return error.BufferTooShort;
    std.mem.writeInt(u16, out[0..2], @intCast(cookie.len), .big);
    @memcpy(out[2..][0..cookie.len], cookie);
    return out[0 .. 2 + cookie.len];
}

pub fn decodeCookieExtension(data: []const u8) MessageError![]const u8 {
    if (data.len < 2) return error.BufferTooShort;
    const len: usize = std.mem.readInt(u16, data[0..2], .big);
    if (data.len < 2 + len) return error.Malformed;
    return data[2..][0..len];
}

// ── psk_key_exchange_modes extension (RFC 8446 §4.2.9) ───────────────────

pub const PskKeyExchangeMode = enum(u8) {
    psk_ke = 0,
    psk_dhe_ke = 1,
    _,
};

pub fn encodePskKeyExchangeModes(modes: []const PskKeyExchangeMode, out: []u8) MessageError![]u8 {
    if (modes.len == 0 or modes.len > 255) return error.Malformed;
    if (out.len < 1 + modes.len) return error.BufferTooShort;
    out[0] = @intCast(modes.len);
    for (modes, 0..) |m, i| out[1 + i] = @intFromEnum(m);
    return out[0 .. 1 + modes.len];
}

pub fn decodePskKeyExchangeModes(data: []const u8, out: []PskKeyExchangeMode) MessageError![]PskKeyExchangeMode {
    if (data.len < 1) return error.BufferTooShort;
    const n = data[0];
    if (data.len < 1 + @as(usize, n)) return error.Malformed;
    if (n > out.len) return error.TooManyExtensions;
    for (0..n) |i| out[i] = @enumFromInt(data[1 + i]);
    return out[0..n];
}

// ── pre_shared_key extension, ClientHello form (RFC 8446 §4.2.11) ───────
//
// The binder VALUE is crypto-core (`keyschedule.zig`'s `pskBinder`); this
// file only frames whatever binder bytes it's handed.

pub const PskIdentity = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

pub const OfferedPsks = struct {
    identities: []const PskIdentity,
    binders: []const []const u8,
};

pub fn encodeOfferedPsks(psks: OfferedPsks, out: []u8) MessageError![]u8 {
    var ids_len: usize = 0;
    for (psks.identities) |id| ids_len += 2 + id.identity.len + 4;
    var binders_len: usize = 0;
    for (psks.binders) |b| binders_len += 1 + b.len;
    if (ids_len > std.math.maxInt(u16) or binders_len > std.math.maxInt(u16)) return error.ListTooLong;

    const needed = 2 + ids_len + 2 + binders_len;
    if (out.len < needed) return error.BufferTooShort;

    std.mem.writeInt(u16, out[0..2], @intCast(ids_len), .big);
    var i: usize = 2;
    for (psks.identities) |id| {
        std.mem.writeInt(u16, out[i..][0..2], @intCast(id.identity.len), .big);
        i += 2;
        @memcpy(out[i..][0..id.identity.len], id.identity);
        i += id.identity.len;
        std.mem.writeInt(u32, out[i..][0..4], id.obfuscated_ticket_age, .big);
        i += 4;
    }

    std.mem.writeInt(u16, out[i..][0..2], @intCast(binders_len), .big);
    i += 2;
    for (psks.binders) |b| {
        if (b.len > 255) return error.ListTooLong;
        out[i] = @intCast(b.len);
        i += 1;
        @memcpy(out[i..][0..b.len], b);
        i += b.len;
    }
    return out[0..i];
}

pub const DecodedOfferedPsks = struct {
    identities: []PskIdentity,
    binders: [][]const u8,
};

pub fn decodeOfferedPsks(
    buf: []const u8,
    identities_out: []PskIdentity,
    binders_out: [][]const u8,
) MessageError!DecodedOfferedPsks {
    if (buf.len < 2) return error.BufferTooShort;
    const ids_len: usize = std.mem.readInt(u16, buf[0..2], .big);
    if (buf.len < 2 + ids_len + 2) return error.BufferTooShort;

    var i: usize = 2;
    const ids_end = 2 + ids_len;
    var n_ids: usize = 0;
    while (i < ids_end) {
        if (i + 2 > ids_end) return error.Malformed;
        const id_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
        i += 2;
        if (i + id_len + 4 > ids_end) return error.Malformed;
        if (n_ids >= identities_out.len) return error.TooManyExtensions;
        identities_out[n_ids] = .{
            .identity = buf[i..][0..id_len],
            .obfuscated_ticket_age = std.mem.readInt(u32, buf[i + id_len ..][0..4], .big),
        };
        i += id_len + 4;
        n_ids += 1;
    }

    if (buf.len < i + 2) return error.BufferTooShort;
    const binders_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    i += 2;
    if (buf.len < i + binders_len) return error.BufferTooShort;

    const binders_end = i + binders_len;
    var n_binders: usize = 0;
    while (i < binders_end) {
        const b_len = buf[i];
        i += 1;
        if (i + b_len > binders_end) return error.Malformed;
        if (n_binders >= binders_out.len) return error.TooManyExtensions;
        binders_out[n_binders] = buf[i..][0..b_len];
        i += b_len;
        n_binders += 1;
    }

    return .{
        .identities = identities_out[0..n_ids],
        .binders = binders_out[0..n_binders],
    };
}

/// Server's `pre_shared_key` extension response (RFC 8446 §4.2.11): just
/// the selected identity's index into the ClientHello's list.
pub fn encodeSelectedIdentity(index: u16, out: *[2]u8) void {
    std.mem.writeInt(u16, out, index, .big);
}

pub fn decodeSelectedIdentity(buf: *const [2]u8) u16 {
    return std.mem.readInt(u16, buf, .big);
}

// ── ClientHello (RFC 8446 §4.1.2, reused by DTLS 1.3 — RFC 9147 §5.3) ────

pub const ClientHello = struct {
    random: [32]u8,
    /// <= 32 bytes.
    legacy_session_id: []const u8,
    cipher_suites: []const u16,
    extensions: []const Extension,
};

pub fn encodeClientHello(ch: ClientHello, out: []u8) MessageError![]u8 {
    if (ch.legacy_session_id.len > 32) return error.Malformed;
    var i: usize = 0;
    if (out.len < 2 + 32 + 1) return error.BufferTooShort;
    out[0..2].* = legacy_version_dtls12;
    i = 2;
    @memcpy(out[i..][0..32], &ch.random);
    i += 32;

    if (out.len < i + 1 + ch.legacy_session_id.len) return error.BufferTooShort;
    out[i] = @intCast(ch.legacy_session_id.len);
    i += 1;
    @memcpy(out[i..][0..ch.legacy_session_id.len], ch.legacy_session_id);
    i += ch.legacy_session_id.len;

    const cs_len = ch.cipher_suites.len * 2;
    if (cs_len > std.math.maxInt(u16)) return error.ListTooLong;
    if (out.len < i + 2 + cs_len + 2) return error.BufferTooShort;
    std.mem.writeInt(u16, out[i..][0..2], @intCast(cs_len), .big);
    i += 2;
    for (ch.cipher_suites) |cs| {
        std.mem.writeInt(u16, out[i..][0..2], cs, .big);
        i += 2;
    }

    out[i] = 1; // legacy_compression_methods length
    out[i + 1] = 0; // "null" compression, the only value TLS 1.3/DTLS 1.3 allow
    i += 2;

    const ext_slice = try encodeExtensions(ch.extensions, out[i..]);
    i += ext_slice.len;
    return out[0..i];
}

pub const DecodedClientHello = struct {
    legacy_version: [2]u8,
    random: [32]u8,
    legacy_session_id: []const u8,
    /// Raw 2-bytes-per-entry (big-endian) blob — iterate with `CipherSuiteIter`.
    cipher_suites_raw: []const u8,
    extensions: []Extension,
};

pub const CipherSuiteIter = struct {
    raw: []const u8,
    pos: usize = 0,

    pub fn next(self: *CipherSuiteIter) ?u16 {
        if (self.pos + 2 > self.raw.len) return null;
        const v = std.mem.readInt(u16, self.raw[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }
};

pub fn decodeClientHello(buf: []const u8, extensions_out: []Extension) MessageError!DecodedClientHello {
    if (buf.len < 2 + 32 + 1) return error.BufferTooShort;
    const legacy_version = buf[0..2].*;
    const random = buf[2..34].*;
    var i: usize = 34;

    const sid_len = buf[i];
    i += 1;
    if (sid_len > 32) return error.Malformed;
    if (buf.len < i + sid_len + 2) return error.BufferTooShort;
    const legacy_session_id = buf[i..][0..sid_len];
    i += sid_len;

    const cs_len: usize = std.mem.readInt(u16, buf[i..][0..2], .big);
    i += 2;
    if (cs_len % 2 != 0) return error.Malformed;
    if (buf.len < i + cs_len + 1) return error.BufferTooShort;
    const cipher_suites_raw = buf[i..][0..cs_len];
    i += cs_len;

    const comp_len = buf[i];
    i += 1;
    if (buf.len < i + comp_len) return error.BufferTooShort;
    i += comp_len;

    const extensions = try decodeExtensions(buf[i..], extensions_out);

    return .{
        .legacy_version = legacy_version,
        .random = random,
        .legacy_session_id = legacy_session_id,
        .cipher_suites_raw = cipher_suites_raw,
        .extensions = extensions,
    };
}

// ── ServerHello (RFC 8446 §4.1.3, reused by DTLS 1.3 — RFC 9147 §5.4) ────

pub const ServerHello = struct {
    random: [32]u8,
    /// <= 32 bytes; echoes the ClientHello's `legacy_session_id`.
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    extensions: []const Extension,
};

pub fn encodeServerHello(sh: ServerHello, out: []u8) MessageError![]u8 {
    if (sh.legacy_session_id_echo.len > 32) return error.Malformed;
    var i: usize = 0;
    if (out.len < 2 + 32 + 1) return error.BufferTooShort;
    out[0..2].* = legacy_version_dtls12;
    i = 2;
    @memcpy(out[i..][0..32], &sh.random);
    i += 32;

    if (out.len < i + 1 + sh.legacy_session_id_echo.len + 2 + 1) return error.BufferTooShort;
    out[i] = @intCast(sh.legacy_session_id_echo.len);
    i += 1;
    @memcpy(out[i..][0..sh.legacy_session_id_echo.len], sh.legacy_session_id_echo);
    i += sh.legacy_session_id_echo.len;

    std.mem.writeInt(u16, out[i..][0..2], sh.cipher_suite, .big);
    i += 2;
    out[i] = 0; // legacy_compression_method
    i += 1;

    const ext_slice = try encodeExtensions(sh.extensions, out[i..]);
    i += ext_slice.len;
    return out[0..i];
}

pub const DecodedServerHello = struct {
    legacy_version: [2]u8,
    random: [32]u8,
    legacy_session_id_echo: []const u8,
    cipher_suite: u16,
    extensions: []Extension,
};

pub fn decodeServerHello(buf: []const u8, extensions_out: []Extension) MessageError!DecodedServerHello {
    if (buf.len < 2 + 32 + 1) return error.BufferTooShort;
    const legacy_version = buf[0..2].*;
    const random = buf[2..34].*;
    var i: usize = 34;

    const sid_len = buf[i];
    i += 1;
    if (sid_len > 32) return error.Malformed;
    if (buf.len < i + sid_len + 3) return error.BufferTooShort;
    const legacy_session_id_echo = buf[i..][0..sid_len];
    i += sid_len;

    const cipher_suite = std.mem.readInt(u16, buf[i..][0..2], .big);
    i += 2;
    i += 1; // skip legacy_compression_method

    const extensions = try decodeExtensions(buf[i..], extensions_out);

    return .{
        .legacy_version = legacy_version,
        .random = random,
        .legacy_session_id_echo = legacy_session_id_echo,
        .cipher_suite = cipher_suite,
        .extensions = extensions,
    };
}

// ── EncryptedExtensions (RFC 8446 §4.3.1) ────────────────────────────────

pub fn encodeEncryptedExtensions(exts: []const Extension, out: []u8) MessageError![]u8 {
    return encodeExtensions(exts, out);
}

pub fn decodeEncryptedExtensions(buf: []const u8, out: []Extension) MessageError![]Extension {
    return decodeExtensions(buf, out);
}

// ── Finished (RFC 8446 §4.4.4) ───────────────────────────────────────────

pub const Finished = struct {
    /// Opaque — crypto-core value (HMAC(finished_key, transcript_hash),
    /// RFC 8446 §4.4.4 / `keyschedule.zig`'s `verifyDataFinished` stub).
    /// Length equals the negotiated hash's digest length (32 for SHA-256,
    /// 48 for SHA-384); the wrapping handshake header's `length` field is
    /// what tells a decoder how many bytes to expect, so this body carries
    /// no length prefix of its own.
    verify_data: []const u8,
};

pub fn encodeFinished(f: Finished, out: []u8) MessageError![]u8 {
    if (out.len < f.verify_data.len) return error.BufferTooShort;
    @memcpy(out[0..f.verify_data.len], f.verify_data);
    return out[0..f.verify_data.len];
}

pub fn decodeFinished(buf: []const u8) Finished {
    return .{ .verify_data = buf };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "hello_retry_request_random matches std's TLS 1.3 constant, 32 bytes" {
    try testing.expectEqual(@as(usize, 32), hello_retry_request_random.len);
    try testing.expectEqualSlices(u8, &std.crypto.tls.hello_retry_request_sequence, &hello_retry_request_random);
}

test "isHelloRetryRequest: true for the magic value, false otherwise" {
    try testing.expect(isHelloRetryRequest(hello_retry_request_random));
    try testing.expect(!isHelloRetryRequest([_]u8{0} ** 32));
}

test "extension list round-trip" {
    const exts = [_]Extension{
        .{ .ext_type = 44, .data = "cookie-bytes" },
        .{ .ext_type = 45, .data = &.{ 0, 1 } },
    };
    var buf: [64]u8 = undefined;
    const enc = try encodeExtensions(&exts, &buf);

    var out: [4]Extension = undefined;
    const dec = try decodeExtensions(enc, &out);
    try testing.expectEqual(@as(usize, 2), dec.len);
    try testing.expectEqual(@as(u16, 44), dec[0].ext_type);
    try testing.expectEqualSlices(u8, "cookie-bytes", dec[0].data);
    try testing.expectEqual(@as(u16, 45), dec[1].ext_type);
    try testing.expectEqualSlices(u8, &.{ 0, 1 }, dec[1].data);
}

test "extension list: too many for caller's buffer" {
    const exts = [_]Extension{
        .{ .ext_type = 1, .data = "" },
        .{ .ext_type = 2, .data = "" },
    };
    var buf: [16]u8 = undefined;
    const enc = try encodeExtensions(&exts, &buf);
    var out: [1]Extension = undefined;
    try testing.expectError(error.TooManyExtensions, decodeExtensions(enc, &out));
}

test "cookie extension round-trip" {
    var buf: [32]u8 = undefined;
    const enc = try encodeCookieExtension("a-stateless-cookie", &buf);
    const dec = try decodeCookieExtension(enc);
    try testing.expectEqualSlices(u8, "a-stateless-cookie", dec);
}

test "psk_key_exchange_modes round-trip" {
    const modes = [_]PskKeyExchangeMode{ .psk_ke, .psk_dhe_ke };
    var buf: [8]u8 = undefined;
    const enc = try encodePskKeyExchangeModes(&modes, &buf);
    try testing.expectEqualSlices(u8, &.{ 2, 0, 1 }, enc);

    var out: [4]PskKeyExchangeMode = undefined;
    const dec = try decodePskKeyExchangeModes(enc, &out);
    try testing.expectEqualSlices(PskKeyExchangeMode, &modes, dec);
}

test "OfferedPsks round-trip with opaque binders" {
    const identities = [_]PskIdentity{
        .{ .identity = "device-042", .obfuscated_ticket_age = 0 },
    };
    const binder = [_]u8{0xAB} ** 32; // opaque; real value is crypto-core
    const binders = [_][]const u8{&binder};
    const psks = OfferedPsks{ .identities = &identities, .binders = &binders };

    var buf: [128]u8 = undefined;
    const enc = try encodeOfferedPsks(psks, &buf);

    var ids_out: [4]PskIdentity = undefined;
    var binders_out: [4][]const u8 = undefined;
    const dec = try decodeOfferedPsks(enc, &ids_out, &binders_out);
    try testing.expectEqual(@as(usize, 1), dec.identities.len);
    try testing.expectEqualSlices(u8, "device-042", dec.identities[0].identity);
    try testing.expectEqual(@as(u32, 0), dec.identities[0].obfuscated_ticket_age);
    try testing.expectEqual(@as(usize, 1), dec.binders.len);
    try testing.expectEqualSlices(u8, &binder, dec.binders[0]);
}

test "selected identity round-trip" {
    var buf: [2]u8 = undefined;
    encodeSelectedIdentity(3, &buf);
    try testing.expectEqual(@as(u16, 3), decodeSelectedIdentity(&buf));
}

test "ClientHello round-trip incl. cipher-suite iteration" {
    const exts = [_]Extension{.{ .ext_type = 45, .data = &.{0} }};
    const ch = ClientHello{
        .random = [_]u8{0x11} ** 32,
        .legacy_session_id = &.{},
        .cipher_suites = &.{ 0x1304, 0x1305 }, // AES_128_CCM_SHA256, AES_128_CCM_8_SHA256
        .extensions = &exts,
    };
    var buf: [128]u8 = undefined;
    const enc = try encodeClientHello(ch, &buf);

    var ext_out: [4]Extension = undefined;
    const dec = try decodeClientHello(enc, &ext_out);
    try testing.expectEqual(legacy_version_dtls12, dec.legacy_version);
    try testing.expectEqualSlices(u8, &ch.random, &dec.random);
    try testing.expectEqual(@as(usize, 0), dec.legacy_session_id.len);

    var iter = CipherSuiteIter{ .raw = dec.cipher_suites_raw };
    try testing.expectEqual(@as(u16, 0x1304), iter.next().?);
    try testing.expectEqual(@as(u16, 0x1305), iter.next().?);
    try testing.expectEqual(@as(?u16, null), iter.next());

    try testing.expectEqual(@as(usize, 1), dec.extensions.len);
    try testing.expectEqual(@as(u16, 45), dec.extensions[0].ext_type);
}

test "ServerHello round-trip and HelloRetryRequest detection" {
    const sh = ServerHello{
        .random = [_]u8{0x22} ** 32,
        .legacy_session_id_echo = &.{ 1, 2, 3 },
        .cipher_suite = 0x1305,
        .extensions = &.{},
    };
    var buf: [128]u8 = undefined;
    const enc = try encodeServerHello(sh, &buf);

    var ext_out: [4]Extension = undefined;
    const dec = try decodeServerHello(enc, &ext_out);
    try testing.expectEqualSlices(u8, &sh.random, &dec.random);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, dec.legacy_session_id_echo);
    try testing.expectEqual(sh.cipher_suite, dec.cipher_suite);
    try testing.expect(!isHelloRetryRequest(dec.random));

    const hrr = ServerHello{
        .random = hello_retry_request_random,
        .legacy_session_id_echo = &.{},
        .cipher_suite = 0x1305,
        .extensions = &.{},
    };
    var hrr_buf: [128]u8 = undefined;
    const hrr_enc = try encodeServerHello(hrr, &hrr_buf);
    var hrr_ext_out: [4]Extension = undefined;
    const hrr_dec = try decodeServerHello(hrr_enc, &hrr_ext_out);
    try testing.expect(isHelloRetryRequest(hrr_dec.random));
}

test "EncryptedExtensions round-trip" {
    const exts = [_]Extension{.{ .ext_type = 0, .data = "example.iot" }};
    var buf: [64]u8 = undefined;
    const enc = try encodeEncryptedExtensions(&exts, &buf);
    var out: [4]Extension = undefined;
    const dec = try decodeEncryptedExtensions(enc, &out);
    try testing.expectEqual(@as(usize, 1), dec.len);
    try testing.expectEqualSlices(u8, "example.iot", dec[0].data);
}

test "Finished round-trip (opaque verify_data)" {
    const verify_data = [_]u8{0xEE} ** 32; // opaque; real value is crypto-core
    var buf: [32]u8 = undefined;
    const enc = try encodeFinished(.{ .verify_data = &verify_data }, &buf);
    const dec = decodeFinished(enc);
    try testing.expectEqualSlices(u8, &verify_data, dec.verify_data);
}
