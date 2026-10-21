// SPDX-License-Identifier: MIT

//! tlsserver.hello — the ClientHello (RFC 8446 §4.1.2) decoded into slices
//! of the message, with every extension a TLS 1.3 server reads checked for
//! form as it is found.
//!
//! Decoding is zero-copy and allocation-free: lists stay in their wire form
//! and are walked with the iterators below, which cannot fail because the
//! decoder has already checked every length. Policy — which version, suite,
//! group or signature scheme to pick, which extension is required — is the
//! state machine's; this file only says what the client sent and refuses
//! what is malformed.
//!
//! Strictness follows rustls 0.23 (`ClientHelloPayload::read`, the
//! module's scope reference):
//!
//! - a malformed known extension is `decode_error` even if it would go
//!   unused; unknown extensions (GREASE included) are skipped;
//! - any extension type appearing twice, known or not, is
//!   `illegal_parameter`, and so is `pre_shared_key` anywhere but last;
//! - lists that RFC 8446 / RFC 6066 / RFC 7301 declare `<2..>` or `<1..>`
//!   must be non-empty, and an element list must divide into elements;
//! - an extension's body must be consumed exactly, the message too;
//! - `legacy_session_id` is at most 32 octets.
//!
//! SNI (RFC 6066 §3) is classified as rustls does: one `host_name` that is
//! a valid DNS name; an IP address literal is ignored (some clients send
//! one); anything else — an invalid name, a second `host_name`, an empty
//! list — makes the extension `invalid`, which the state machine answers
//! with `illegal_parameter`. A name type other than `host_name` ends the
//! list (its encoding is unknown, so nothing after it can be read).

const std = @import("std");
const netaddr = @import("netaddr");

/// RFC 8446 §4.2 and the registry entries a TLS 1.3 server meets.
pub const ExtensionType = enum(u16) {
    server_name = 0,
    status_request = 5,
    supported_groups = 10,
    ec_point_formats = 11,
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    compress_certificate = 27,
    session_ticket = 35,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    signature_algorithms_cert = 50,
    key_share = 51,
    renegotiation_info = 0xff01,
    _,
};

pub const Error = error{
    /// Malformed: a length that does not add up, an empty list that must
    /// not be, trailing octets (`decode_error`).
    DecodeError,
    /// A repeated extension, or `pre_shared_key` not last
    /// (`illegal_parameter`).
    IllegalParameter,
};

pub const ServerName = union(enum) {
    /// A valid DNS name, as sent (case and a trailing dot kept).
    dns_name: []const u8,
    /// An IP address literal: treated as if no SNI were sent.
    ip_address,
    /// Malformed or forbidden: the server answers `illegal_parameter`.
    invalid,
};

/// The `pre_shared_key` extension (RFC 8446 §4.2.11).
pub const PreSharedKey = struct {
    /// `PskIdentity identities<7..2^16-1>`, walked by `identities()`.
    identities_raw: []const u8,
    /// `PskBinderEntry binders<33..2^16-1>`, walked by `binders()`.
    binders_raw: []const u8,
    /// Octets of the ClientHello *body* before the binders list (its 2-octet
    /// length included in what follows): the transcript for a binder is
    /// `Hash(header ‖ body[0..binders_offset])` (§4.2.11.2), i.e.
    /// `Transcript.wouldBeHash(1, body.len, body[0..binders_offset])`.
    binders_offset: usize,

    pub fn identities(p: PreSharedKey) PskIdentityIter {
        return .{ .rest = p.identities_raw };
    }
    pub fn binders(p: PreSharedKey) Opaque8Iter {
        return .{ .rest = p.binders_raw };
    }
};

pub const ClientHello = struct {
    legacy_version: u16,
    random: *const [32]u8,
    legacy_session_id: []const u8,
    /// `CipherSuite cipher_suites<2..2^16-2>` in wire form.
    cipher_suites_raw: []const u8,
    /// `opaque legacy_compression_methods<1..2^8-1>`.
    legacy_compression_methods: []const u8,

    server_name: ?ServerName = null,
    /// `status_request` with `status_type` ocsp (RFC 6066 §8): the client
    /// accepts an OCSP staple. Another status type is ignored.
    ocsp_requested: bool = false,
    /// `signed_certificate_timestamp` (RFC 6962 §3.3.1, empty in a
    /// ClientHello): the client accepts an SCT list on the leaf.
    sct_requested: bool = false,
    supported_groups_raw: ?[]const u8 = null,
    signature_algorithms_raw: ?[]const u8 = null,
    signature_algorithms_cert_raw: ?[]const u8 = null,
    /// `ProtocolName protocol_name_list<2..2^16-1>`, walked by `alpn()`.
    alpn_raw: ?[]const u8 = null,
    supported_versions_raw: ?[]const u8 = null,
    /// `KeyShareEntry client_shares<0..2^16-1>`, walked by `keyShares()`.
    /// Present but empty is legal: the client asks for a HelloRetryRequest.
    key_shares_raw: ?[]const u8 = null,
    psk_key_exchange_modes: ?[]const u8 = null,
    pre_shared_key: ?PreSharedKey = null,
    early_data: bool = false,
    cookie: ?[]const u8 = null,
    /// RFC 8879 `CertificateCompressionAlgorithm algorithms<2..2^8-2>`.
    compress_certificate_raw: ?[]const u8 = null,
    /// The number of extensions, unknown ones included.
    extension_count: usize = 0,

    pub fn cipherSuites(ch: *const ClientHello) U16Iter {
        return .{ .rest = ch.cipher_suites_raw };
    }
    pub fn supportedGroups(ch: *const ClientHello) ?U16Iter {
        return if (ch.supported_groups_raw) |r| .{ .rest = r } else null;
    }
    pub fn signatureAlgorithms(ch: *const ClientHello) ?U16Iter {
        return if (ch.signature_algorithms_raw) |r| .{ .rest = r } else null;
    }
    pub fn signatureAlgorithmsCert(ch: *const ClientHello) ?U16Iter {
        return if (ch.signature_algorithms_cert_raw) |r| .{ .rest = r } else null;
    }
    pub fn supportedVersions(ch: *const ClientHello) ?U16Iter {
        return if (ch.supported_versions_raw) |r| .{ .rest = r } else null;
    }
    pub fn keyShares(ch: *const ClientHello) ?KeyShareIter {
        return if (ch.key_shares_raw) |r| .{ .rest = r } else null;
    }
    pub fn alpn(ch: *const ClientHello) ?Opaque8Iter {
        return if (ch.alpn_raw) |r| .{ .rest = r } else null;
    }
    pub fn compressCertificate(ch: *const ClientHello) ?U16Iter {
        return if (ch.compress_certificate_raw) |r| .{ .rest = r } else null;
    }
};

/// Big-endian u16 elements of a checked list.
pub const U16Iter = struct {
    rest: []const u8,

    pub fn next(it: *U16Iter) ?u16 {
        if (it.rest.len < 2) return null;
        defer it.rest = it.rest[2..];
        return std.mem.readInt(u16, it.rest[0..2], .big);
    }

    pub fn contains(it: U16Iter, v: u16) bool {
        var i = it;
        while (i.next()) |x| if (x == v) return true;
        return false;
    }
};

/// `opaque x<1..2^8-1>` elements (ALPN protocol names, PSK binders).
pub const Opaque8Iter = struct {
    rest: []const u8,

    pub fn next(it: *Opaque8Iter) ?[]const u8 {
        if (it.rest.len == 0) return null;
        const n: usize = it.rest[0]; // not u8: `1 + n` overflows at 255 (ReleaseFast: wraps to 0 and never advances)
        defer it.rest = it.rest[1 + n ..];
        return it.rest[1..][0..n];
    }
};

pub const KeyShareEntry = struct {
    group: u16,
    key_exchange: []const u8,
};

pub const KeyShareIter = struct {
    rest: []const u8,

    pub fn next(it: *KeyShareIter) ?KeyShareEntry {
        if (it.rest.len == 0) return null;
        const g = std.mem.readInt(u16, it.rest[0..2], .big);
        const n = std.mem.readInt(u16, it.rest[2..4], .big);
        defer it.rest = it.rest[4 + n ..];
        return .{ .group = g, .key_exchange = it.rest[4..][0..n] };
    }
};

pub const PskIdentity = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
};

pub const PskIdentityIter = struct {
    rest: []const u8,

    pub fn next(it: *PskIdentityIter) ?PskIdentity {
        if (it.rest.len == 0) return null;
        const n = std.mem.readInt(u16, it.rest[0..2], .big);
        defer it.rest = it.rest[2 + n + 4 ..];
        return .{
            .identity = it.rest[2..][0..n],
            .obfuscated_ticket_age = std.mem.readInt(u32, it.rest[2 + n ..][0..4], .big),
        };
    }
};

/// A cursor over the message with length-prefixed reads.
const Reader = struct {
    buf: []const u8,
    at: usize = 0,

    fn left(r: *const Reader) usize {
        return r.buf.len - r.at;
    }
    fn take(r: *Reader, n: usize) Error![]const u8 {
        if (r.left() < n) return error.DecodeError;
        defer r.at += n;
        return r.buf[r.at..][0..n];
    }
    fn int(r: *Reader, comptime T: type) Error!T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .big);
    }
    /// `opaque x<lo..2^(8*@sizeOf(L))-1>`: the length prefix, then that many.
    fn vec(r: *Reader, comptime L: type) Error![]const u8 {
        return r.take(try r.int(L));
    }
    fn done(r: *const Reader) Error!void {
        if (r.left() != 0) return error.DecodeError;
    }
};

/// Decode a ClientHello *body* (the handshake message without its 4-octet
/// header).
pub fn parseClientHello(body: []const u8) Error!ClientHello {
    var r: Reader = .{ .buf = body };
    var ch: ClientHello = .{
        .legacy_version = try r.int(u16),
        .random = (try r.take(32))[0..32],
        .legacy_session_id = try r.vec(u8),
        .cipher_suites_raw = try r.vec(u16),
        .legacy_compression_methods = try r.vec(u8),
    };
    if (ch.legacy_session_id.len > 32) return error.DecodeError;
    try u16List(ch.cipher_suites_raw);
    if (ch.legacy_compression_methods.len == 0) return error.DecodeError;
    // The extensions block may be absent altogether (a pre-TLS 1.2 client).
    if (r.left() == 0) return ch;

    const exts = try r.vec(u16);
    try r.done();
    var er: Reader = .{ .buf = exts };
    var seen: std.StaticBitSet(1 << 16) = .empty;
    while (er.left() > 0) {
        const t = try er.int(u16);
        const data = try er.vec(u16);
        if (seen.isSet(t)) return error.IllegalParameter;
        seen.set(t);
        ch.extension_count += 1;
        switch (@as(ExtensionType, @fromBackingInt(t))) {
            .server_name => ch.server_name = try parseServerName(data),
            .status_request => ch.ocsp_requested = try parseStatusRequest(data),
            .supported_groups => ch.supported_groups_raw = try u16ListIn(data, u16),
            .ec_point_formats => _ = try nonEmptyIn(data, u8),
            .signature_algorithms => ch.signature_algorithms_raw = try u16ListIn(data, u16),
            .signature_algorithms_cert => ch.signature_algorithms_cert_raw = try u16ListIn(data, u16),
            .application_layer_protocol_negotiation => ch.alpn_raw = try parseAlpn(data),
            .signed_certificate_timestamp => {
                if (data.len != 0) return error.DecodeError;
                ch.sct_requested = true;
            },
            .compress_certificate => ch.compress_certificate_raw = try u16ListIn(data, u8),
            .session_ticket => {}, // TLS 1.2 tickets: any payload
            .pre_shared_key => {
                // RFC 8446 §4.2.11: MUST be the last extension.
                if (er.left() != 0) return error.IllegalParameter;
                const data_at = body.len - data.len;
                ch.pre_shared_key = try parsePreSharedKey(data, data_at);
            },
            .early_data => {
                if (data.len != 0) return error.DecodeError;
                ch.early_data = true;
            },
            .supported_versions => ch.supported_versions_raw = try u16ListIn(data, u8),
            .cookie => ch.cookie = try nonEmptyIn(data, u16),
            .psk_key_exchange_modes => ch.psk_key_exchange_modes = try nonEmptyIn(data, u8),
            .certificate_authorities => try parseCertificateAuthorities(data),
            .key_share => ch.key_shares_raw = try parseKeyShares(data),
            .renegotiation_info => _ = try vecIn(data, u8),
            _ => {},
        }
    }
    return ch;
}

/// `T list<2..>` of u16 elements, already cut: non-empty, even.
fn u16List(raw: []const u8) Error!void {
    if (raw.len == 0 or raw.len % 2 != 0) return error.DecodeError;
}

/// An extension body that is exactly one `L`-length-prefixed vector.
fn vecIn(data: []const u8, comptime L: type) Error![]const u8 {
    var r: Reader = .{ .buf = data };
    const v = try r.vec(L);
    try r.done();
    return v;
}

fn nonEmptyIn(data: []const u8, comptime L: type) Error![]const u8 {
    const v = try vecIn(data, L);
    if (v.len == 0) return error.DecodeError;
    return v;
}

fn u16ListIn(data: []const u8, comptime L: type) Error![]const u8 {
    const v = try vecIn(data, L);
    try u16List(v);
    return v;
}

fn parseServerName(data: []const u8) Error!ServerName {
    var r: Reader = .{ .buf = try vecIn(data, u16) };
    var found: ?ServerName = null;
    while (r.left() > 0) {
        const name_type = try r.int(u8);
        if (name_type != 0) break; // unknown encoding: stop (rustls)
        const name = try r.vec(u16);
        if (name.len == 0) return error.DecodeError;
        // RFC 6066: no two names of one type.
        if (found != null) return .invalid;
        found = if (netaddr.parseIp(name) != null)
            .ip_address
        else if (isDnsName(name))
            .{ .dns_name = name }
        else
            .invalid;
    }
    return found orelse .invalid;
}

/// A DNS name as rustls-pki-types `DnsName` accepts it: 1..253 octets,
/// labels of 1..63 letters, digits, `_` and `-` (not first or last in a
/// label), an optional trailing dot, and a last label that is not all
/// digits (it would read as an IPv4 address).
pub fn isDnsName(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    const body = if (name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
    if (body.len == 0) return false;
    var it = std.mem.splitScalar(u8, body, '.');
    var last_all_digits = false;
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        var all_digits = true;
        for (label) |c| switch (c) {
            'a'...'z', 'A'...'Z', '_', '-' => all_digits = false,
            '0'...'9' => {},
            else => return false,
        };
        last_all_digits = all_digits;
    }
    return !last_all_digits;
}

fn parseStatusRequest(data: []const u8) Error!bool {
    var r: Reader = .{ .buf = data };
    const status_type = try r.int(u8);
    if (status_type != 1) return false; // another type: its body is opaque
    // OCSPStatusRequest: ResponderID responder_id_list<0..2^16-1>;
    // Extensions request_extensions; (RFC 6066 §8)
    var ids: Reader = .{ .buf = try r.vec(u16) };
    while (ids.left() > 0) _ = try ids.vec(u16);
    _ = try r.vec(u16);
    try r.done();
    return true;
}

fn parseAlpn(data: []const u8) Error![]const u8 {
    const list = try nonEmptyIn(data, u16);
    var r: Reader = .{ .buf = list };
    while (r.left() > 0) {
        if ((try r.vec(u8)).len == 0) return error.DecodeError;
    }
    return list;
}

fn parseKeyShares(data: []const u8) Error![]const u8 {
    const list = try vecIn(data, u16);
    var r: Reader = .{ .buf = list };
    while (r.left() > 0) {
        _ = try r.int(u16);
        _ = try r.vec(u16);
    }
    return list;
}

fn parseCertificateAuthorities(data: []const u8) Error!void {
    var r: Reader = .{ .buf = try vecIn(data, u16) };
    while (r.left() > 0) _ = try r.vec(u16);
}

fn parsePreSharedKey(data: []const u8, data_at: usize) Error!PreSharedKey {
    var r: Reader = .{ .buf = data };
    const ids = try r.vec(u16);
    const binders_offset = data_at + r.at;
    const binders = try r.vec(u16);
    try r.done();
    if (ids.len == 0 or binders.len == 0) return error.DecodeError;
    var ir: Reader = .{ .buf = ids };
    var n_ids: usize = 0;
    while (ir.left() > 0) : (n_ids += 1) {
        if ((try ir.vec(u16)).len == 0) return error.DecodeError;
        _ = try ir.int(u32);
    }
    var br: Reader = .{ .buf = binders };
    var n_binders: usize = 0;
    while (br.left() > 0) : (n_binders += 1) {
        // PskBinderEntry: opaque<32..255>; the hash length is checked when
        // the binder is verified.
        if ((try br.vec(u8)).len == 0) return error.DecodeError;
    }
    // RFC 8446 §4.2.11: one binder per identity (rustls checks it when it
    // verifies; it is a property of the message, so here).
    if (n_ids != n_binders) return error.IllegalParameter;
    return .{ .identities_raw = ids, .binders_raw = binders, .binders_offset = binders_offset };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const kat = @import("message_kat_vectors.zig");

fn hexDecode(comptime hex: []const u8) [hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

test "RFC 8448 §3 ClientHello" {
    const ch = try parseClientHello(kat.rfc8448_s3[4..]);
    try testing.expectEqual(@as(u16, 0x0303), ch.legacy_version);
    try testing.expectEqual(@as(usize, 0), ch.legacy_session_id.len);
    var cs = ch.cipherSuites();
    try testing.expectEqual(@as(?u16, 0x1301), cs.next());
    try testing.expectEqual(@as(?u16, 0x1303), cs.next());
    try testing.expectEqual(@as(?u16, 0x1302), cs.next());
    try testing.expectEqual(@as(?u16, null), cs.next());
    try testing.expectEqualStrings("server", ch.server_name.?.dns_name);
    try testing.expect(ch.supportedVersions().?.contains(0x0304));
    try testing.expect(ch.supportedGroups().?.contains(0x001d));
    try testing.expect(ch.signatureAlgorithms().?.contains(0x0804));
    var ks = ch.keyShares().?;
    const e = ks.next().?;
    try testing.expectEqual(@as(u16, 0x001d), e.group);
    try testing.expectEqual(@as(usize, 32), e.key_exchange.len);
    try testing.expectEqual(@as(u8, 0x99), e.key_exchange[0]);
    try testing.expectEqual(@as(?KeyShareEntry, null), ks.next());
    try testing.expectEqualSlices(u8, &.{1}, ch.psk_key_exchange_modes.?);
    try testing.expect(ch.pre_shared_key == null);
    try testing.expect(!ch.early_data);
    try testing.expect(ch.alpn_raw == null);
    // server_name, renegotiation_info, supported_groups, session_ticket,
    // key_share, supported_versions, signature_algorithms,
    // psk_key_exchange_modes, record_size_limit.
    try testing.expectEqual(@as(usize, 9), ch.extension_count);
}

test "RFC 8448 §4 ClientHello: pre_shared_key last, the binder prefix the RFC hashed" {
    const msg = &kat.rfc8448_s4;
    const ch = try parseClientHello(msg[4..]);
    try testing.expect(ch.early_data);
    const psk = ch.pre_shared_key.?;
    // The binder prefix is the message up to (not including) the binders.
    try testing.expectEqual(kat.rfc8448_s4_binder_prefix_len, 4 + psk.binders_offset);
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(msg[0 .. 4 + psk.binders_offset], &h, .{});
    try testing.expectEqualSlices(u8, &kat.rfc8448_s4_binder_hash, &h);
    var ids = psk.identities();
    const id = ids.next().?;
    try testing.expectEqual(@as(usize, 178), id.identity.len);
    try testing.expectEqual(@as(u32, 0xfad6aacb), id.obfuscated_ticket_age);
    try testing.expectEqual(@as(?PskIdentity, null), ids.next());
    var bs = psk.binders();
    try testing.expectEqualSlices(u8, &hexDecode("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d"), bs.next().?);
    try testing.expectEqual(@as(?[]const u8, null), bs.next());
}

test "RFC 8448 §5 ClientHello1 / ClientHello2: cookie and the retried key share" {
    const ch1 = try parseClientHello(kat.rfc8448_s5_ch1[4..]);
    try testing.expect(ch1.cookie == null);
    const ch2 = try parseClientHello(kat.rfc8448_s5_ch2[4..]);
    try testing.expectEqual(@as(usize, 0x72), ch2.cookie.?.len);
    var ks = ch2.keyShares().?;
    const e = ks.next().?;
    try testing.expectEqual(@as(u16, 0x0017), e.group);
    try testing.expectEqual(@as(usize, 65), e.key_exchange.len);
    // Same random in both (RFC 8446 §4.1.2: ClientHello2 repeats it).
    try testing.expectEqualSlices(u8, ch1.random, ch2.random);
}

/// A ClientHello body with the given extension block (or none).
fn buildHello(buf: []u8, exts: ?[]const u8) []const u8 {
    var n: usize = 0;
    const fixed = [_]u8{ 3, 3 } ++ @as([32]u8, @splat(0xab)) ++ [_]u8{0} ++ [_]u8{ 0, 2, 0x13, 0x01 } ++ [_]u8{ 1, 0 };
    @memcpy(buf[0..fixed.len], &fixed);
    n = fixed.len;
    if (exts) |e| {
        std.mem.writeInt(u16, buf[n..][0..2], @intCast(e.len), .big);
        @memcpy(buf[n + 2 ..][0..e.len], e);
        n += 2 + e.len;
    }
    return buf[0..n];
}

fn ext(comptime t: u16, comptime data: []const u8) [4 + data.len]u8 {
    var out: [4 + data.len]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], t, .big);
    std.mem.writeInt(u16, out[2..4], data.len, .big);
    @memcpy(out[4..], data);
    return out;
}

test "no extensions at all; an empty extension block" {
    var b: [256]u8 = undefined;
    const ch = try parseClientHello(buildHello(&b, null));
    try testing.expectEqual(@as(usize, 0), ch.extension_count);
    try testing.expect(ch.supported_versions_raw == null);
    _ = try parseClientHello(buildHello(&b, ""));
}

test "fixed fields: session id over 32, empty or odd suites, no compression, trailing octets" {
    var b: [256]u8 = undefined;
    const good = buildHello(&b, "");
    var m: [256]u8 = undefined;
    // legacy_session_id of 33 octets.
    {
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(testing.allocator);
        try w.appendSlice(testing.allocator, good[0..34]);
        try w.append(testing.allocator, 33);
        try w.appendNTimes(testing.allocator, 0, 33);
        try w.appendSlice(testing.allocator, good[35..]);
        try testing.expectError(error.DecodeError, parseClientHello(w.items));
    }
    // Empty cipher_suites: the suite's two octets cut out, length 0.
    @memcpy(m[0..35], good[0..35]);
    @memcpy(m[35..][0..2], &[_]u8{ 0, 0 });
    @memcpy(m[37..][0 .. good.len - 39], good[39..]);
    try testing.expectError(error.DecodeError, parseClientHello(m[0 .. good.len - 2]));
    @memcpy(m[0..good.len], good);
    m[36] = 3; // odd length
    try testing.expectError(error.DecodeError, parseClientHello(m[0..good.len]));
    @memcpy(m[0..good.len], good);
    m[39] = 0; // compression methods length 0
    try testing.expectError(error.DecodeError, parseClientHello(m[0 .. good.len - 1]));
    @memcpy(m[0..good.len], good);
    m[good.len] = 0;
    try testing.expectError(error.DecodeError, parseClientHello(m[0 .. good.len + 1]));
    // Truncated anywhere.
    for (0..good.len) |cut| {
        if (cut == good.len - 2) continue; // = no extension block: legal
        _ = parseClientHello(good[0..cut]) catch continue;
        return error.TruncatedHelloAccepted;
    }
}

test "duplicates (known or unknown) and pre_shared_key not last are illegal_parameter" {
    var b: [512]u8 = undefined;
    const sv = ext(43, &.{ 2, 3, 4 });
    try testing.expectError(error.IllegalParameter, parseClientHello(buildHello(&b, &(sv ++ sv))));
    const grease = ext(0x0a0a, "");
    try testing.expectError(error.IllegalParameter, parseClientHello(buildHello(&b, &(grease ++ sv ++ grease))));
    const psk = ext(41, &([_]u8{ 0, 7, 0, 1, 0xaa, 0, 0, 0, 0, 0, 33, 32 } ++ @as([32]u8, @splat(0x55))));
    try testing.expectError(error.IllegalParameter, parseClientHello(buildHello(&b, &(psk ++ sv))));
    const ch = try parseClientHello(buildHello(&b, &(sv ++ grease ++ psk)));
    try testing.expectEqual(@as(usize, 3), ch.extension_count);
    try testing.expect(ch.pre_shared_key != null);
    // Identities and binders out of step.
    const psk2 = ext(41, &([_]u8{ 0, 14, 0, 1, 0xaa, 0, 0, 0, 0, 0, 1, 0xbb, 0, 0, 0, 0, 0, 33, 32 } ++ @as([32]u8, @splat(0x55))));
    try testing.expectError(error.IllegalParameter, parseClientHello(buildHello(&b, &psk2)));
}

test "malformed known extensions are decode_error" {
    var b: [512]u8 = undefined;
    const cases = [_][]const u8{
        &ext(43, &.{ 3, 3, 4 }), // supported_versions odd
        &ext(43, &.{0}), // supported_versions empty
        &ext(43, &.{ 2, 3, 4, 0 }), // trailing octet in the extension
        &ext(10, &.{ 0, 0 }), // supported_groups empty
        &ext(13, &.{ 0, 1, 4 }), // signature_algorithms odd
        &ext(16, &.{ 0, 0 }), // ALPN empty list
        &ext(16, &.{ 0, 1, 0 }), // ALPN empty name
        &ext(16, &.{ 0, 3, 2, 'h' }), // ALPN name overruns
        &ext(51, &.{ 0, 4, 0, 0x1d, 0, 1 }), // key_share overruns
        &ext(51, &.{ 0, 3, 0, 0x1d, 0 }), // key_share truncated header
        &ext(44, &.{ 0, 0 }), // cookie empty
        &ext(45, &.{0}), // psk modes empty
        &ext(42, &.{0}), // early_data with a body
        &ext(41, &.{ 0, 0, 0, 0 }), // psk: empty lists
        &ext(41, &.{ 0, 6, 0, 0, 0, 0, 0, 0, 0, 2, 1, 0xff }), // psk: empty identity
        &ext(0, &.{ 0, 3, 0, 0, 0 }), // SNI host_name empty
        &ext(0, &.{ 0, 4, 0, 0, 2, 'a' }), // SNI overruns
        &ext(5, &.{ 1, 0, 0 }), // status_request ocsp truncated
        &ext(18, &.{0}), // signed_certificate_timestamp with a body
        &ext(11, &.{0}), // ec_point_formats empty
        &ext(27, &.{ 3, 0, 1, 0 }), // compress_certificate odd
        &ext(47, &.{ 0, 2, 0, 5 }), // certificate_authorities overruns
        &ext(0xff01, &.{1}), // renegotiation_info overruns
        &[_]u8{ 0, 43, 0, 9, 2, 3, 4 }, // extension overruns the block
    };
    for (cases, 0..) |c, i| {
        _ = parseClientHello(buildHello(&b, c)) catch |err| {
            testing.expectEqual(error.DecodeError, err) catch |e| {
                std.debug.print("case {d}\n", .{i});
                return e;
            };
            continue;
        };
        std.debug.print("case {d} accepted\n", .{i});
        return error.MalformedExtensionAccepted;
    }
}

test "well-formed odd cases are accepted" {
    var b: [512]u8 = undefined;
    // An empty key_share list (asks for a HelloRetryRequest).
    var ch = try parseClientHello(buildHello(&b, &ext(51, &.{ 0, 0 })));
    var ks = ch.keyShares().?;
    try testing.expectEqual(@as(?KeyShareEntry, null), ks.next());
    // status_request of another type: ignored, not an OCSP request.
    ch = try parseClientHello(buildHello(&b, &ext(5, &.{ 2, 0xde, 0xad })));
    try testing.expect(!ch.ocsp_requested);
    ch = try parseClientHello(buildHello(&b, &ext(5, &.{ 1, 0, 0, 0, 0 })));
    try testing.expect(ch.ocsp_requested);
    try testing.expect(!ch.sct_requested);
    ch = try parseClientHello(buildHello(&b, &ext(18, &.{})));
    try testing.expect(ch.sct_requested);
    // ALPN with two names.
    ch = try parseClientHello(buildHello(&b, &ext(16, &.{ 0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' })));
    var a = ch.alpn().?;
    try testing.expectEqualStrings("h2", a.next().?);
    try testing.expectEqualStrings("http/1.1", a.next().?);
    try testing.expectEqual(@as(?[]const u8, null), a.next());
}

test "SNI: a DNS name, an IP literal, invalid names, two host names, an unknown name type" {
    var b: [512]u8 = undefined;
    const Case = struct { data: []const u8, want: std.meta.Tag(ServerName) };
    const cases = [_]Case{
        .{ .data = &.{ 0, 14, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' }, .want = .dns_name },
        .{ .data = &.{ 0, 10, 0, 0, 7, '1', '.', '2', '.', '3', '.', '4' }, .want = .ip_address },
        .{ .data = &.{ 0, 6, 0, 0, 3, ':', ':', '1' }, .want = .ip_address },
        .{ .data = &.{ 0, 6, 0, 0, 3, 'a', ' ', 'b' }, .want = .invalid },
        .{ .data = &.{ 0, 6, 0, 0, 3, '1', '.', '2' }, .want = .invalid }, // all-numeric last label
        .{ .data = &.{ 0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b' }, .want = .invalid }, // two host names
        .{ .data = &.{ 0, 0 }, .want = .invalid }, // empty list
        .{ .data = &.{ 0, 8, 0, 0, 1, 'a', 9, 0xff, 0xff, 0xff }, .want = .dns_name }, // unknown type ends the list
    };
    for (cases) |c| {
        const e = try std.mem.concat(testing.allocator, u8, &.{ &.{ 0, 0 }, &.{ @intCast(c.data.len >> 8), @truncate(c.data.len) }, c.data });
        defer testing.allocator.free(e);
        const ch = try parseClientHello(buildHello(&b, e));
        try testing.expectEqual(c.want, std.meta.activeTag(ch.server_name.?));
    }
}

fn rep(comptime c: u8, comptime n: usize) [n]u8 {
    return @splat(c);
}

test "isDnsName" {
    for ([_][]const u8{ "a", "server", "example.com", "example.com.", "x-y.z_w", "1a.2b", "a.b1", "xn--bcher-kva.example" }) |n|
        try testing.expect(isDnsName(n));
    for ([_][]const u8{ "", ".", "a..b", "-a", "a-", "a.-b", "a.b-", "1.2.3", "a.123", "a b", "a/b", "é", "a." ++ rep('x', 64) }) |n|
        try testing.expect(!isDnsName(n));
    try testing.expect(isDnsName(&rep('x', 63)));
    try testing.expect(!isDnsName(&rep('x', 64)));
    const long = comptime blk: {
        var l: [253]u8 = undefined;
        for (&l, 0..) |*c, i| c.* = if (i % 10 == 9) '.' else 'a';
        break :blk l;
    };
    try testing.expect(isDnsName(&long));
    try testing.expect(!isDnsName(&long ++ "d"));
}

test "Opaque8Iter: a 255-octet element (an ALPN name, a binder) advances past itself" {
    // `1 + n` in u8 overflowed at 255: a panic in safe builds, and in
    // ReleaseFast a wrap to 0 that never advanced — an endless loop on one
    // ClientHello whose ALPN list or PSK binders held a 255-octet element
    // (found 2026-10-21 by the minOutputLen test with a 255-octet ALPN name).
    var raw: [1 + 255 + 1 + 2]u8 = undefined;
    raw[0] = 255;
    @memset(raw[1..256], 'a');
    raw[256] = 2;
    raw[257..259].* = "h2".*;
    var it: Opaque8Iter = .{ .rest = &raw };
    try testing.expectEqual(@as(usize, 255), it.next().?.len);
    try testing.expectEqualStrings("h2", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());
}
