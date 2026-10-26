// SPDX-License-Identifier: MIT

//! zig-libs tlsclient: the ClientHello, built at run time.
//!
//! std builds its ClientHello at comptime from one fixed shape. The options
//! this module grew (version bounds, group preferences, the second hello of
//! a HelloRetryRequest, OCSP/SCT requests, extended master secret, a PSK for
//! resumption) each change that shape, so the message is written here from
//! `Params` instead.
//!
//! Extension order: std's first -- supported_versions, signature_algorithms,
//! supported_groups, psk_key_exchange_modes, key_share, server_name -- then
//! the additions, and pre_shared_key last (RFC 8446 §4.2.11 requires it). With
//! std's groups and shares and every addition off, the bytes are std's (a
//! test compares them).

const std = @import("std");
const tls = std.crypto.tls;
const mem = std.mem;

/// Extension and message code points std's `tls` enums lack.
pub const ext_extended_master_secret: u16 = 23; // RFC 7627
pub const ext_renegotiation_info: u16 = 0xff01; // RFC 5746
pub const hs_certificate_status: u8 = 22; // RFC 6066 §8

/// The longest ClientHello this module writes (handshake message, without
/// the record header): every share at once is ~1.6 KiB, a ticket identity
/// and a cookie are capped below.
pub const max_len = 8 * 1024;
/// The longest session ticket offered back (RFC 8446 allows 2^16 - 1; real
/// tickets are a few hundred bytes).
pub const max_ticket_len = 2048;
/// The longest HelloRetryRequest cookie echoed.
pub const max_cookie_len = 2048;

/// std's signature_algorithms list, in std's order, plus
/// ecdsa_secp521r1_sha512 (zig-libs tlsclient, 2026-10-26: the P-521 server
/// keys Go's client verifies; std's list lacked it, so a P-521-only TLS 1.3
/// server had no scheme to sign with).
pub const signature_algorithms = [_]tls.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .ecdsa_secp521r1_sha512,
    .rsa_pkcs1_sha256,
    .rsa_pkcs1_sha384,
    .rsa_pkcs1_sha512,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pss_pss_sha256,
    .rsa_pss_pss_sha384,
    .rsa_pss_pss_sha512,
    .rsa_pkcs1_sha1,
    .ed25519,
};

/// One key_share entry.
pub const Share = struct {
    group: tls.NamedGroup,
    key: []const u8,
};

/// A resumption PSK offer: one identity (a ticket) and its binder's length
/// (the PRF hash length). The binder bytes are left zero; see `write`.
pub const Psk = struct {
    identity: []const u8,
    obfuscated_ticket_age: u32,
    binder_len: u8,
};

pub const Params = struct {
    random: *const [32]u8,
    session_id: *const [32]u8,
    /// The cipher_suites vector as std writes it (u16 length + suites).
    cipher_suites: []const u8,
    /// SNI host name; empty: no server_name extension.
    host: []const u8,
    /// The versions offered, newest first (supported_versions).
    versions: []const tls.ProtocolVersion,
    groups: []const tls.NamedGroup,
    shares: []const Share,
    /// A prebuilt ALPN extension (type, length, list), or "".
    alpn_ext: []const u8 = "",
    status_request: bool = false,
    signed_certificate_timestamp: bool = false,
    extended_master_secret: bool = false,
    renegotiation_info: bool = false,
    /// A HelloRetryRequest's cookie to echo (RFC 8446 §4.2.2), or "".
    cookie: []const u8 = "",
    psk: ?Psk = null,
};

pub const Error = error{NoSpaceLeft};

/// Write the ClientHello handshake message (type, u24 length, body) into
/// `buf`. With `p.psk`, the message ends with the PSK binders list, whose
/// one binder is zero-filled: the caller hashes everything before
/// `binders_len` bytes from the end (RFC 8446 §4.2.11.2, the truncated
/// ClientHello) and writes the binder into the last `binder_len` bytes.
pub fn write(buf: []u8, p: Params) Error![]u8 {
    var w: W = .{ .buf = buf };
    try w.byte(@backingInt(tls.HandshakeType.client_hello));
    const msg_len = try w.hole(3);
    try w.int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)); // legacy_version
    try w.bytes(p.random);
    try w.byte(32);
    try w.bytes(p.session_id);
    try w.bytes(p.cipher_suites);
    try w.bytes(&.{ 1, 0 }); // compression methods: null
    const exts_len = try w.hole(2);

    {
        const e = try w.ext(@backingInt(tls.ExtensionType.supported_versions));
        try w.byte(@intCast(2 * p.versions.len));
        for (p.versions) |v| try w.int(u16, @backingInt(v));
        w.close(e);
    }
    {
        const e = try w.ext(@backingInt(tls.ExtensionType.signature_algorithms));
        try w.int(u16, @intCast(2 * signature_algorithms.len));
        for (signature_algorithms) |s| try w.int(u16, @backingInt(s));
        w.close(e);
    }
    {
        const e = try w.ext(@backingInt(tls.ExtensionType.supported_groups));
        try w.int(u16, @intCast(2 * p.groups.len));
        for (p.groups) |g| try w.int(u16, @backingInt(g));
        w.close(e);
    }
    {
        const e = try w.ext(@backingInt(tls.ExtensionType.psk_key_exchange_modes));
        try w.bytes(&.{ 1, @backingInt(tls.PskKeyExchangeMode.psk_dhe_ke) });
        w.close(e);
    }
    // key_share is TLS 1.3's (RFC 8446 §4.2.8): absent from a TLS 1.2-only
    // hello, an empty list when 1.3 is offered without shares.
    if (mem.findScalar(tls.ProtocolVersion, p.versions, .tls_1_3) != null) {
        const e = try w.ext(@backingInt(tls.ExtensionType.key_share));
        const list = try w.hole(2);
        for (p.shares) |s| {
            try w.int(u16, @backingInt(s.group));
            try w.int(u16, @intCast(s.key.len));
            try w.bytes(s.key);
        }
        w.fill(list, 2);
        w.close(e);
    }
    if (p.host.len != 0) {
        const e = try w.ext(@backingInt(tls.ExtensionType.server_name));
        try w.int(u16, @intCast(1 + 2 + p.host.len)); // server_name_list
        try w.byte(0); // host_name
        try w.int(u16, @intCast(p.host.len));
        try w.bytes(p.host);
        w.close(e);
    }
    try w.bytes(p.alpn_ext);
    if (p.status_request) {
        // CertificateStatusRequest: ocsp(1), no responder ids, no extensions.
        const e = try w.ext(@backingInt(tls.ExtensionType.status_request));
        try w.bytes(&.{ 1, 0, 0, 0, 0 });
        w.close(e);
    }
    if (p.signed_certificate_timestamp) w.close(try w.ext(@backingInt(tls.ExtensionType.signed_certificate_timestamp)));
    if (p.extended_master_secret) w.close(try w.ext(ext_extended_master_secret));
    if (p.renegotiation_info) {
        const e = try w.ext(ext_renegotiation_info);
        try w.byte(0); // empty renegotiated_connection: initial handshake
        w.close(e);
    }
    if (p.cookie.len != 0) {
        const e = try w.ext(@backingInt(tls.ExtensionType.cookie));
        try w.int(u16, @intCast(p.cookie.len));
        try w.bytes(p.cookie);
        w.close(e);
    }
    if (p.psk) |psk| {
        const e = try w.ext(@backingInt(tls.ExtensionType.pre_shared_key));
        try w.int(u16, @intCast(2 + psk.identity.len + 4)); // identities
        try w.int(u16, @intCast(psk.identity.len));
        try w.bytes(psk.identity);
        try w.int(u32, psk.obfuscated_ticket_age);
        try w.int(u16, @as(u16, psk.binder_len) + 1); // binders
        try w.byte(psk.binder_len);
        try w.zeroes(psk.binder_len);
        w.close(e);
    }

    w.fill(exts_len, 2);
    w.fill(msg_len, 3);
    return buf[0..w.n];
}

/// Bytes the PSK binders list takes at the end of a hello written with `psk`.
pub fn bindersLen(psk: Psk) usize {
    return 2 + 1 + @as(usize, psk.binder_len);
}

const W = struct {
    buf: []u8,
    n: usize = 0,

    fn need(w: *W, k: usize) Error!void {
        if (w.buf.len - w.n < k) return error.NoSpaceLeft;
    }
    fn byte(w: *W, b: u8) Error!void {
        try w.need(1);
        w.buf[w.n] = b;
        w.n += 1;
    }
    fn bytes(w: *W, b: []const u8) Error!void {
        try w.need(b.len);
        @memcpy(w.buf[w.n..][0..b.len], b);
        w.n += b.len;
    }
    fn zeroes(w: *W, k: usize) Error!void {
        try w.need(k);
        @memset(w.buf[w.n..][0..k], 0);
        w.n += k;
    }
    fn int(w: *W, comptime T: type, v: T) Error!void {
        try w.need(@sizeOf(T));
        mem.writeInt(T, w.buf[w.n..][0..@sizeOf(T)], v, .big);
        w.n += @sizeOf(T);
    }
    /// Reserve a `k`-byte length field; returns its offset.
    fn hole(w: *W, k: usize) Error!usize {
        try w.need(k);
        const at = w.n;
        w.n += k;
        return at;
    }
    /// Fill the `k`-byte length field at `at` with the bytes written since.
    fn fill(w: *W, at: usize, k: usize) void {
        const len = w.n - at - k;
        switch (k) {
            2 => mem.writeInt(u16, w.buf[at..][0..2], @intCast(len), .big),
            3 => mem.writeInt(u24, w.buf[at..][0..3], @intCast(len), .big),
            else => unreachable,
        }
    }
    /// Start an extension: type, then a length hole.
    fn ext(w: *W, t: u16) Error!usize {
        try w.int(u16, t);
        return w.hole(2);
    }
    fn close(w: *W, at: usize) void {
        w.fill(at, 2);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "hello: lengths are consistent, PSK binders last and zero-filled" {
    var buf: [max_len]u8 = undefined;
    const r: [32]u8 = @splat(1);
    const sid: [32]u8 = @splat(2);
    const key: [32]u8 = @splat(3);
    const psk: Psk = .{ .identity = "ticket", .obfuscated_ticket_age = 7, .binder_len = 32 };
    const m = try write(&buf, .{
        .random = &r,
        .session_id = &sid,
        .cipher_suites = &.{ 0, 2, 0x13, 0x01 },
        .host = "example.test",
        .versions = &.{.tls_1_3},
        .groups = &.{.x25519},
        .shares = &.{.{ .group = .x25519, .key = &key }},
        .status_request = true,
        .signed_certificate_timestamp = true,
        .extended_master_secret = true,
        .renegotiation_info = true,
        .cookie = "c00k1e",
        .psk = psk,
    });
    try testing.expectEqual(@as(u8, 1), m[0]);
    try testing.expectEqual(m.len - 4, mem.readInt(u24, m[1..4], .big));
    // Walk the extensions: every length lands exactly, pre_shared_key last.
    var i: usize = 4 + 2 + 32 + 1 + 32 + 4 + 2;
    const exts_end = i + 2 + mem.readInt(u16, m[i..][0..2], .big);
    try testing.expectEqual(m.len, exts_end);
    i += 2;
    var last: u16 = 0;
    var count: usize = 0;
    while (i < exts_end) {
        last = mem.readInt(u16, m[i..][0..2], .big);
        i += 4 + mem.readInt(u16, m[i + 2 ..][0..2], .big);
        count += 1;
    }
    try testing.expectEqual(exts_end, i);
    try testing.expectEqual(@as(u16, @backingInt(tls.ExtensionType.pre_shared_key)), last);
    try testing.expectEqual(@as(usize, 12), count);
    try testing.expectEqualSlices(u8, &(@as([32]u8, @splat(0))), m[m.len - 32 ..]);
    try testing.expectEqual(@as(usize, 35), bindersLen(psk));
    try testing.expectEqual(@as(u8, 32), m[m.len - 33]);
}

test "hello: a buffer too small is NoSpaceLeft, never a partial write past it" {
    var buf: [64]u8 = undefined;
    const r: [32]u8 = @splat(1);
    try testing.expectError(error.NoSpaceLeft, write(&buf, .{
        .random = &r,
        .session_id = &r,
        .cipher_suites = &.{ 0, 2, 0x13, 0x01 },
        .host = "",
        .versions = &.{.tls_1_3},
        .groups = &.{.x25519},
        .shares = &.{},
    }));
}
