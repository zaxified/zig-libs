// SPDX-License-Identifier: MIT
// Copyright (c) Zig contributors -- a copy of Zig 0.16.0's
// lib/std/crypto/tls/Client.zig; see ../NOTICE. Changed by zig-libs: the
// std import, the server Certificate message handler, and two additions
// that are off by default -- ALPN (RFC 7301) and TLS 1.3 client
// certificates (RFC 8446 §4.4.2-4.4.3). Every change is marked
// "zig-libs tlsclient". Everything else is Zig's.

const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const std = @import("std");
const verify = @import("verify.zig");
const x509 = @import("x509");
const p256 = @import("p256");
const p384 = @import("p384");
const p521 = @import("p521");
const ct25519 = @import("ct25519");
const hello = @import("hello.zig");
const session = @import("session.zig");
const tlsresume = @import("tlsresume");
const keygen = @import("keygen.zig");
/// The in-repo RSA module, re-exported so a caller can name `rsa.KeyPair`
/// for `ClientAuth.PrivateKey.rsa`.
pub const rsa = @import("rsa");
// zig-libs tlsclient: dead-stack burn around the client-certificate signature.
const burn = @import("burn.zig");
const tls = std.crypto.tls;
const Client = @This();
const mem = std.mem;
const crypto = std.crypto;
const assert = std.debug.assert;
const Certificate = std.crypto.Certificate;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const max_ciphertext_len = tls.max_ciphertext_len;
const hmacExpandLabel = tls.hmacExpandLabel;
const hkdfExpandLabel = tls.hkdfExpandLabel;
const int = tls.int;
const array = tls.array;

/// The encrypted stream from the server to the client. Bytes are pulled from
/// here via `reader`.
///
/// Its buffer must hold at least `min_buffer_len` bytes (`init`:
/// `error.BufferTooSmall`).
input: *Reader,
/// Decrypted stream from the server to the client.
reader: Reader,

/// The encrypted stream from the client to the server. Bytes are pushed here
/// via `writer`.
///
/// Its buffer must hold at least `min_buffer_len` bytes, or grow to it on
/// rebase as `Writer.Allocating` does (`init`: `error.BufferTooSmall`).
output: *Writer,
/// The plaintext stream from the client to the server.
writer: Writer,

/// Populated when `error.TlsAlert` is returned.
alert: ?tls.Alert = null,
read_err: ?ReadError = null,
tls_version: tls.ProtocolVersion,
read_seq: u64,
write_seq: u64,
/// When this is true, the stream may still not be at the end because there
/// may be data in the input buffer.
received_close_notify: bool,
allow_truncation_attacks: bool,
application_cipher: tls.ApplicationCipher,

/// If non-null, ssl secrets are logged to a stream. Creating such a log file
/// allows other programs with access to that file to decrypt all traffic over
/// this connection.
ssl_key_log: ?*SslKeyLog,

// zig-libs tlsclient: ALPN. The protocol the server selected, borrowed from
// `Options.alpn_protocols` (null: none offered, or the server chose none).
alpn_protocol: ?[]const u8 = null,
// zig-libs tlsclient: the session view (Go `ConnectionState`).
/// The key-exchange group the handshake used.
negotiated_group: ?tls.NamedGroup = null,
/// Whether the server sent a HelloRetryRequest.
hello_retry_request: bool = false,
/// The negotiated cipher suite.
cipher_suite: tls.CipherSuite = @fromBackingInt(@intCast(0)),
/// The keying-material exporter's secret (`exportKeyingMaterial`).
exporter: Exporter = .none,
/// zig-libs tlsclient: TLS 1.3 resumption -- whether this session resumed,
/// and the cache entry its NewSessionTickets go to.
did_resume: bool = false,
session_cache: ?*SessionCache = null,
session_entry: ?*ClientSession = null,
session_generation: u64 = 0,
/// The wall clock at `init` (ms); a ticket's age counts from it.
handshake_time_ms: i64 = 0,
/// zig-libs tlsclient: a KeyUpdate of ours is due before the next record --
/// the server asked (update_requested) or `write_seq` reached
/// `key_update_after`.
key_update_pending: bool = false,

pub const ReadError = error{
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsBadLength,
    TlsBadRecordMac,
    TlsConnectionTruncated,
    TlsDecodeError,
    TlsRecordOverflow,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsSequenceOverflow,
};

pub const SslKeyLog = struct {
    client_key_seq: u64,
    server_key_seq: u64,
    client_random: [32]u8,
    writer: *Writer,

    fn clientCounter(key_log: *@This()) u64 {
        defer key_log.client_key_seq += 1;
        return key_log.client_key_seq;
    }

    fn serverCounter(key_log: *@This()) u64 {
        defer key_log.server_key_seq += 1;
        return key_log.server_key_seq;
    }
};

/// The `Reader` supplied to `init` requires a buffer capacity
/// at least this amount.
pub const min_buffer_len = tls.max_ciphertext_record_len;

/// zig-libs tlsclient: records sent under one TLS 1.3 key before the client
/// updates it on its own -- well inside RFC 8446 §5.5's AES-GCM limit of
/// 2^24.5 records.
pub const key_update_after: u64 = 1 << 23;

pub const Options = struct {
    /// How to perform host verification of server certificates.
    host: union(enum) {
        /// No host verification is performed, which prevents a trusted connection from
        /// being established.
        no_verification,
        /// Verify that the server certificate was issued for a given host.
        explicit: []const u8,
    },
    /// How to verify the authenticity of server certificates.
    ca: union(enum) {
        /// No ca verification is performed, which prevents a trusted connection from
        /// being established.
        no_verification,
        /// Verify that the server certificate is a valid self-signed certificate.
        /// This provides no authorization guarantees, as anyone can create a
        /// self-signed certificate.
        self_signed,
        /// Verify that the server certificate is authorized by a given ca bundle.
        bundle: struct {
            gpa: std.mem.Allocator,
            io: std.Io,
            lock: *std.Io.RwLock,
            bundle: *Certificate.Bundle,
        },
    },
    /// Plaintext buffered before it is sealed into records (any size).
    write_buffer: []u8,
    /// Decrypted plaintext: at least `tls.max_ciphertext_len` bytes, so the
    /// largest record fits (`init`: `error.BufferTooSmall`). A `peek`/`fill`
    /// of more than `read_buffer.len - tls.max_ciphertext_len` bytes may meet
    /// a record with no room left: `error.ReadFailed`, `read_err`
    /// `TlsRecordOverflow`.
    read_buffer: []u8,
    /// Cryptographically secure random bytes. The pointer is not captured; data is only
    /// read during `init`.
    entropy: *const [entropy_len]u8,
    /// Current time according to the wall clock / calendar.
    realtime_now: std.Io.Timestamp,

    /// If non-null, ssl secrets are logged to this stream. Creating such a log file allows
    /// other programs with access to that file to decrypt all traffic over this connection.
    ///
    /// Only the `writer` field is observed during the handshake (`init`).
    /// After that, the other fields are populated.
    ssl_key_log: ?*SslKeyLog = null,
    /// By default, reaching the end-of-stream when reading from the server will
    /// cause `error.TlsConnectionTruncated` to be returned, unless a close_notify
    /// message has been received. By setting this flag to `true`, instead, the
    /// end-of-stream will be forwarded to the application layer above TLS.
    ///
    /// This makes the application vulnerable to truncation attacks unless the
    /// application layer itself verifies that the amount of data received equals
    /// the amount of data expected, such as HTTP with the Content-Length header.
    allow_truncation_attacks: bool = false,
    /// Populated when `error.TlsAlert` is returned from `init`.
    alert: ?*tls.Alert = null,

    // zig-libs tlsclient: additions. Both default to off, and with the
    // defaults the handshake is byte-for-byte std's.

    /// ALPN (RFC 7301): the application protocols to offer, most preferred
    /// first (e.g. `&.{ "h2", "http/1.1" }`). Empty (the default): no
    /// extension is sent and a server's ALPN reply is ignored, as in std.
    /// Each name is 1..255 bytes; the list at most `max_alpn_len` bytes on
    /// the wire. The server's choice is `Client.alpn_protocol`; a choice not
    /// offered is `error.TlsIllegalParameter`. Borrowed for the connection.
    alpn_protocols: []const []const u8 = &.{},
    /// A client certificate for a server that sends a CertificateRequest
    /// (TLS 1.3 and 1.2). Null (the default): an empty Certificate is sent
    /// and the server decides, as Go's client does (std's, and this
    /// module's before 2026-10-26, failed with `error.TlsUnexpectedMessage`).
    /// Set: the chain is sent and signed for with `key`; when the request's
    /// signature_algorithms (or, in TLS 1.2, its certificate_types) do not
    /// fit `key`, an empty Certificate is sent (RFC 8446 §4.4.2.3) and the
    /// server decides.
    client_auth: ?ClientAuth = null,
    /// Choose the client certificate per request (Go `GetClientCertificate`):
    /// called with the request's signature schemes and acceptable CA names;
    /// null means "none" (an empty Certificate). Overrides `client_auth`.
    client_auth_select: ?ClientAuthSelect = null,

    // zig-libs tlsclient: Go-shaped options (S2 survey 2026-10-13). The
    // defaults are Go's `crypto/tls` client's.

    /// Lowest and highest protocol version, TLS 1.2 or 1.3 (Go `MinVersion`
    /// / `MaxVersion`). A server choosing outside them is
    /// `error.TlsIllegalParameter`.
    min_version: tls.ProtocolVersion = .tls_1_2,
    max_version: tls.ProtocolVersion = .tls_1_3,
    /// Key-exchange groups offered in supported_groups, most preferred first
    /// (Go `CurvePreferences`); each one of `supported_groups`. Borrowed
    /// during `init`.
    groups: []const tls.NamedGroup = &default_groups,
    /// The groups of `groups` that get a key share in the first ClientHello.
    /// A TLS 1.3 server that wants another of `groups` asks for it with a
    /// HelloRetryRequest, answered with a second ClientHello. Go's default is
    /// these two; std sent a share for every group (`std_groups`, 4 shares).
    key_share_groups: []const tls.NamedGroup = &default_key_share_groups,
    /// Ask for a stapled OCSP response (status_request, RFC 6066 §8) and for
    /// the certificate's SCTs (RFC 6962 §3.3.1), as Go does. Neither is
    /// verified (Go verifies neither); with `connection_info` the bytes are
    /// kept.
    request_ocsp: bool = true,
    request_scts: bool = true,
    /// TLS 1.2: offer the extended master secret (RFC 7627), as Go does; it
    /// is used when the server agrees, and the keying-material exporter needs
    /// it in TLS 1.2.
    extended_master_secret: bool = true,
    /// TLS 1.2: signal secure renegotiation (RFC 5746, an empty
    /// renegotiation_info), as Go does. This client never renegotiates.
    renegotiation_info: bool = true,
    /// Where the session view goes (Go `ConnectionState`): version, suite,
    /// group, the peer's certificates, OCSP response and SCTs. The bytes are
    /// copied into `ConnectionInfo.storage`. Null: not kept.
    connection_info: ?*ConnectionInfo = null,
    /// Called once the server is authenticated (its chain checked per `ca`,
    /// its signature verified), before the client Finished -- Go
    /// `VerifyConnection` (and `VerifyPeerCertificate`, the chain being in
    /// the view). An error aborts with `error.TlsConnectionRejected`.
    /// Requires `connection_info`.
    verify_connection: ?VerifyConnection = null,
    /// TLS 1.3 session resumption (Go `ClientSessionCache`, also opt-in
    /// there): tickets from this server name are kept here and offered back
    /// as a PSK (psk_dhe_ke: a fresh ECDHE still runs; no 0-RTT). Needs
    /// `host = .explicit` (the cache key). A resumed handshake has no
    /// Certificate message; the session view shows the chain kept with the
    /// ticket. Borrowed for the connection: the cache must outlive every
    /// `Client` made with it (NewSessionTickets are stored into it while
    /// reading), and clients on several threads need its `lock`.
    session_cache: ?*SessionCache = null,

    pub const entropy_len = 240;
};

// zig-libs tlsclient: the session view and the verification hook.

/// TLS 1.3 resumption (Go `ClientSessionCache`): pass a cache as
/// `Options.session_cache`; see `session.zig`.
pub const SessionCache = session.SessionCache;
pub const ClientSession = session.ClientSession;

/// The session as Go's `ConnectionState` shows it, filled during `init` when
/// passed as `Options.connection_info`. Byte fields are copies in `storage`,
/// so they outlive the handshake's buffers; a `storage` too small for them is
/// `error.ConnectionInfoTooSmall`. Real chains with OCSP and SCTs take a few
/// KiB; 16 KiB is ample.
pub const ConnectionInfo = struct {
    storage: []u8,
    used: usize = 0,
    version: tls.ProtocolVersion = .tls_1_3,
    cipher_suite: tls.CipherSuite = @fromBackingInt(@intCast(0)),
    negotiated_group: ?tls.NamedGroup = null,
    alpn_protocol: ?[]const u8 = null,
    hello_retry_request: bool = false,
    did_resume: bool = false,
    /// TLS 1.2: the server agreed to the extended master secret.
    extended_master_secret: bool = false,
    peer_certificates_buf: [verify.max_chain_len][]const u8 = undefined,
    peer_certificates_len: usize = 0,
    /// The stapled OCSP response (DER), or empty.
    ocsp_response: []const u8 = "",
    scts_buf: [max_scts][]const u8 = undefined,
    scts_len: usize = 0,

    pub const max_scts = 16;

    pub fn init(storage: []u8) ConnectionInfo {
        return .{ .storage = storage };
    }

    /// The server's certificates as sent, leaf first (DER).
    pub fn peerCertificates(ci: *const ConnectionInfo) []const []const u8 {
        return ci.peer_certificates_buf[0..ci.peer_certificates_len];
    }

    /// The SignedCertificateTimestamps, each one SCT as RFC 6962 encodes it.
    pub fn signedCertificateTimestamps(ci: *const ConnectionInfo) []const []const u8 {
        return ci.scts_buf[0..ci.scts_len];
    }

    fn keep(ci: *ConnectionInfo, bytes: []const u8) error{ConnectionInfoTooSmall}![]const u8 {
        if (ci.storage.len - ci.used < bytes.len) return error.ConnectionInfoTooSmall;
        const out = ci.storage[ci.used..][0..bytes.len];
        @memcpy(out, bytes);
        ci.used += bytes.len;
        return out;
    }

    fn reset(ci: *ConnectionInfo) void {
        ci.* = .{ .storage = ci.storage };
    }
};

/// `Options.verify_connection`: `verify(context, info)`; an error refuses
/// the server.
pub const VerifyConnection = struct {
    context: ?*anyopaque = null,
    verify: *const fn (context: ?*anyopaque, info: *const ConnectionInfo) anyerror!void,
};

/// The keying-material exporter's state (RFC 8446 §7.5; RFC 5705 for TLS
/// 1.2, available only with the extended master secret, as in Go).
pub const Exporter = union(enum) {
    none,
    tls13: struct { hash: HashKind, secret: [64]u8 },
    tls12: struct { hash: HashKind, master: [48]u8, randoms: [64]u8 },
};
pub const HashKind = session.HashKind;

fn hashKind(comptime digest_len: usize) HashKind {
    return switch (digest_len) {
        32 => .sha256,
        48 => .sha384,
        64 => .sha512,
        else => @compileError("hash"),
    };
}

fn HashOf(comptime k: HashKind) type {
    return switch (k) {
        .sha256 => crypto.hash.sha2.Sha256,
        .sha384 => crypto.hash.sha2.Sha384,
        .sha512 => crypto.hash.sha2.Sha512,
    };
}

pub const ExportError = error{
    /// TLS 1.2 without the extended master secret (Go refuses it too).
    ExporterUnavailable,
    /// A TLS 1.2 label the PRF itself uses (RFC 5705 §4).
    ExporterLabelReserved,
    /// Longer than the KDF can give, or a label/context over its field.
    ExporterLengthInvalid,
};

/// Keying material exported from the session into `out` (Go
/// `ConnectionState.ExportKeyingMaterial`). TLS 1.3: RFC 8446 §7.5, where
/// no context and an empty one are the same. TLS 1.2: RFC 5705, only with
/// the extended master secret.
pub fn exportKeyingMaterial(c: *const Client, label: []const u8, context: ?[]const u8, out: []u8) ExportError!void {
    switch (c.exporter) {
        .none => return error.ExporterUnavailable,
        .tls13 => |*e| switch (e.hash) {
            inline else => |k| try tls13Export(HashOf(k), e.secret[0..HashOf(k).digest_length], label, context orelse "", out),
        },
        .tls12 => |*e| {
            for ([_][]const u8{ "client finished", "server finished", "master secret", "key expansion", "extended master secret" }) |r|
                if (mem.eql(u8, label, r)) return error.ExporterLabelReserved;
            switch (e.hash) {
                inline .sha256, .sha384 => |k| try tls12Export(HashOf(k), &e.master, &e.randoms, label, context, out),
                .sha512 => unreachable, // no TLS 1.2 suite here uses SHA-512
            }
        },
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1) with a run-time length.
fn expandLabelRt(comptime H: type, prk: *const [H.digest_length]u8, label: []const u8, context: []const u8, out: []u8) ExportError!void {
    const Hkdf = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(H));
    if (out.len > 255 * H.digest_length or label.len > 255 - 6 or context.len > 255) return error.ExporterLengthInvalid;
    var info: [2 + 1 + 255 + 1 + 255]u8 = undefined;
    var n: usize = 0;
    mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
    info[2] = @intCast(6 + label.len);
    n = 3;
    @memcpy(info[n..][0..6], "tls13 ");
    n += 6;
    @memcpy(info[n..][0..label.len], label);
    n += label.len;
    info[n] = @intCast(context.len);
    n += 1;
    @memcpy(info[n..][0..context.len], context);
    n += context.len;
    Hkdf.expand(out, info[0..n], prk.*);
}

fn tls13Export(comptime H: type, secret: *const [H.digest_length]u8, label: []const u8, context: []const u8, out: []u8) ExportError!void {
    var empty: [H.digest_length]u8 = undefined;
    H.hash("", &empty, .{});
    var derived: [H.digest_length]u8 = undefined;
    defer crypto.secureZero(u8, &derived);
    try expandLabelRt(H, secret, label, &empty, &derived);
    var ctx_hash: [H.digest_length]u8 = undefined;
    H.hash(context, &ctx_hash, .{});
    try expandLabelRt(H, &derived, "exporter", &ctx_hash, out);
}

/// RFC 5705 §4: PRF(master, label, client_random ‖ server_random [‖ u16
/// context length ‖ context]) with the suite's P_hash (RFC 5246 §5).
fn tls12Export(comptime H: type, master: *const [48]u8, randoms: *const [64]u8, label: []const u8, context: ?[]const u8, out: []u8) ExportError!void {
    const Hmac = crypto.auth.hmac.Hmac(H);
    if (context) |ctx| if (ctx.len > 0xffff) return error.ExporterLengthInvalid;
    var ctx_len: [2]u8 = undefined;
    if (context) |ctx| mem.writeInt(u16, &ctx_len, @intCast(ctx.len), .big);
    const seed = [_][]const u8{ label, randoms, if (context != null) &ctx_len else "", context orelse "" };
    var a: [Hmac.mac_length]u8 = undefined; // A(1) = HMAC(secret, seed)
    defer crypto.secureZero(u8, &a);
    {
        var h = Hmac.init(master);
        for (seed) |part| h.update(part);
        h.final(&a);
    }
    var off: usize = 0;
    while (off < out.len) {
        var block: [Hmac.mac_length]u8 = undefined;
        defer crypto.secureZero(u8, &block);
        var h = Hmac.init(master);
        h.update(&a);
        for (seed) |part| h.update(part);
        h.final(&block);
        const k = @min(block.len, out.len - off);
        @memcpy(out[off..][0..k], block[0..k]);
        off += k;
        Hmac.create(&a, &a, master);
    }
}

fn fillInfo(ci: *ConnectionInfo, version: tls.ProtocolVersion, suite: tls.CipherSuite, group: ?tls.NamedGroup, alpn: ?[]const u8, hrr: bool, ems: bool) void {
    ci.version = version;
    ci.cipher_suite = suite;
    ci.negotiated_group = group;
    ci.alpn_protocol = alpn;
    ci.hello_retry_request = hrr;
    ci.extended_master_secret = ems;
}

/// CertificateStatus (RFC 6066 §8): status_type ocsp(1), then the response
/// as opaque<1..2^24-1>, nothing after.
fn parseCertificateStatus(body: []const u8) error{TlsDecodeError}![]const u8 {
    if (body.len < 4 or body[0] != 1) return error.TlsDecodeError;
    const len = mem.readInt(u24, body[1..4], .big);
    if (len == 0 or len != body.len - 4) return error.TlsDecodeError;
    return body[4..];
}

/// SignedCertificateTimestampList (RFC 6962 §3.3): u16 total, then SCTs as
/// opaque<1..2^16-1>; each kept in `ci`.
fn keepScts(ci: *ConnectionInfo, list: []const u8) error{ TlsDecodeError, ConnectionInfoTooSmall }!void {
    if (list.len < 2 or mem.readInt(u16, list[0..2], .big) != list.len - 2) return error.TlsDecodeError;
    var i: usize = 2;
    while (i < list.len) {
        if (list.len - i < 2) return error.TlsDecodeError;
        const n = mem.readInt(u16, list[i..][0..2], .big);
        i += 2;
        if (n == 0 or list.len - i < n) return error.TlsDecodeError;
        if (ci.scts_len == ConnectionInfo.max_scts) return error.ConnectionInfoTooSmall;
        ci.scts_buf[ci.scts_len] = try ci.keep(list[i..][0..n]);
        ci.scts_len += 1;
        i += n;
    }
}

/// The leaf's CertificateEntry extensions in TLS 1.3: status_request holds a
/// CertificateStatus, signed_certificate_timestamp an SCT list.
fn leafEntryExtensions(ci: *ConnectionInfo, exts: tls.Decoder, want_ocsp: bool, want_scts: bool) !void {
    var d = exts;
    while (!d.eof()) {
        try d.ensure(4);
        const et = d.decode(tls.ExtensionType);
        const n = d.decode(u16);
        const ed = try d.sub(n);
        switch (et) {
            .status_request => if (want_ocsp) {
                ci.ocsp_response = try ci.keep(try parseCertificateStatus(ed.rest()));
            },
            .signed_certificate_timestamp => if (want_scts) try keepScts(ci, ed.rest()),
            else => {},
        }
    }
}

// zig-libs tlsclient: ALPN and client-certificate types.

/// Longest ALPN extension payload offered (the protocol_name_list).
pub const max_alpn_len = 512;
/// Most bytes of client Certificate + CertificateVerify messages.
pub const max_client_auth_len = 16 * 1024;

pub const ClientAuth = struct {
    /// DER certificates, leaf first. Borrowed during `init`.
    certificate_chain: []const []const u8,
    /// The leaf's private key, borrowed for the connection: the caller owns
    /// (and wipes) it. A pointer, so `Options` copies never carry the key.
    key: *const PrivateKey,

    pub const PrivateKey = union(enum) {
        /// P-256 scalar, big-endian (SEC1). Signs `ecdsa_secp256r1_sha256`.
        ecdsa_secp256r1_sha256: [32]u8,
        /// P-384 scalar, big-endian. Signs `ecdsa_secp384r1_sha384`.
        ecdsa_secp384r1_sha384: [48]u8,
        /// Ed25519 seed (RFC 8032 private key). Signs `ed25519` -- TLS 1.3
        /// only: a TLS 1.2 CertificateVerify signs a hash of the messages,
        /// which PureEdDSA cannot.
        ed25519: [32]u8,
        /// An RSA key pair (the `rsa` module's), borrowed. TLS 1.3 signs
        /// RSA-PSS (rsa_pss_rsae_*); TLS 1.2 PKCS#1 v1.5 or PSS -- the first
        /// of the server's schemes that fits.
        rsa: *const rsa.KeyPair,

        /// The TLS 1.3 scheme a key signs with by default.
        pub fn scheme(k: *const PrivateKey) tls.SignatureScheme {
            return switch (k.*) {
                .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
                .ed25519 => .ed25519,
                .rsa => .rsa_pss_rsae_sha256,
            };
        }

        /// secret-api-ok: reads only the union's tag (which key TYPE this is), never the key bytes.
        /// Whether this key can sign `s` in `version` (RFC 8446 §4.2.3 binds
        /// ECDSA curves to schemes in TLS 1.3; TLS 1.2 schemes name the hash
        /// only).
        pub fn fits(k: *const PrivateKey, s: tls.SignatureScheme, version: tls.ProtocolVersion) bool {
            const ecdsa_any = s == .ecdsa_secp256r1_sha256 or s == .ecdsa_secp384r1_sha384 or s == .ecdsa_secp521r1_sha512;
            const pss = s == .rsa_pss_rsae_sha256 or s == .rsa_pss_rsae_sha384 or s == .rsa_pss_rsae_sha512;
            const pkcs1 = s == .rsa_pkcs1_sha256 or s == .rsa_pkcs1_sha384 or s == .rsa_pkcs1_sha512;
            return switch (k.*) {
                .ecdsa_secp256r1_sha256 => if (version == .tls_1_3) s == .ecdsa_secp256r1_sha256 else ecdsa_any,
                .ecdsa_secp384r1_sha384 => if (version == .tls_1_3) s == .ecdsa_secp384r1_sha384 else ecdsa_any,
                .ed25519 => version == .tls_1_3 and s == .ed25519,
                .rsa => pss or (version == .tls_1_2 and pkcs1),
            };
        }
    };
};

/// What a CertificateRequest asked for (Go `CertificateRequestInfo`).
pub const CertificateRequestInfo = struct {
    version: tls.ProtocolVersion,
    signature_schemes: []const tls.SignatureScheme,
    /// The DER DistinguishedNames of the CAs the server accepts (empty:
    /// any). Valid during the callback only.
    certificate_authorities: []const []const u8,
};

/// `Options.client_auth_select`.
pub const ClientAuthSelect = struct {
    context: ?*anyopaque = null,
    select: *const fn (context: ?*anyopaque, info: *const CertificateRequestInfo) ?ClientAuth,
};

/// The longest signature `signCertificateVerify` writes (RSA-4096).
pub const max_signature_len = 512;

pub const InitError = error{
    InsufficientEntropy,
    DiskQuota,
    LockViolation,
    NotOpenForWriting,
    /// The alert description will be stored in `alert`.
    TlsAlert,
    TlsUnexpectedMessage,
    TlsIllegalParameter,
    TlsDecryptFailure,
    TlsRecordOverflow,
    TlsBadRecordMac,
    CertificateFieldHasInvalidLength,
    CertificateHostMismatch,
    CertificatePublicKeyInvalid,
    CertificateExpired,
    CertificateFieldHasWrongDataType,
    CertificateIssuerMismatch,
    CertificateNotYetValid,
    CertificateSignatureAlgorithmMismatch,
    CertificateSignatureAlgorithmUnsupported,
    CertificateSignatureInvalid,
    CertificateSignatureInvalidLength,
    CertificateSignatureNamedCurveUnsupported,
    CertificateSignatureUnsupportedBitCount,
    TlsCertificateNotVerified,
    TlsBadSignatureScheme,
    TlsBadRsaSignatureBitCount,
    InvalidEncoding,
    IdentityElement,
    SignatureVerificationFailed,
    TlsDecryptError,
    TlsConnectionTruncated,
    TlsDecodeError,
    UnsupportedCertificateVersion,
    CertificateTimeInvalid,
    CertificateHasUnrecognizedObjectId,
    CertificateHasInvalidBitString,
    MessageTooLong,
    NegativeIntoUnsigned,
    TargetTooSmall,
    BufferTooSmall,
    InvalidSignature,
    NotSquare,
    NonCanonical,
    WeakPublicKey,
    // zig-libs tlsclient: additions, reachable only through the new options.
    /// An empty or over-255-byte name, or a list over `max_alpn_len`.
    AlpnProtocolsInvalid,
    /// The client chain does not fit `max_client_auth_len`, or is empty.
    ClientCertificateTooLarge,
    /// `ClientAuth.key` is not a valid key for its curve.
    ClientKeyInvalid,
    /// A CertificateRequest listing more schemes or CA names than this
    /// client keeps (`CertRequest.max_schemes`, `max_cas`).
    TlsCertificateRequestTooLarge,
    /// `min_version` above `max_version`, or either not TLS 1.2 / 1.3.
    VersionsInvalid,
    /// `groups` empty, a group not in `supported_groups` or listed twice, or
    /// a `key_share_groups` entry not in `groups`.
    GroupsInvalid,
    /// `host` over 255 bytes (RFC 6066 §3: a HostName is at most 2^8 - 1
    /// in practice, DNS names 253): it would not fit the ClientHello.
    HostNameInvalid,
    /// `connection_info.storage` cannot hold the peer's certificates, OCSP
    /// response and SCTs.
    ConnectionInfoTooSmall,
    /// `verify_connection` without `connection_info`.
    ConnectionInfoRequired,
    /// `verify_connection` refused the server.
    TlsConnectionRejected,
    /// `realtime_now` past what an i64 of milliseconds holds (about 292
    /// million years either side of 1970).
    RealtimeInvalid,
} || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable;

/// Initiates a TLS handshake and establishes a TLSv1.2 or TLSv1.3 session.
///
/// `host` is only borrowed during this function call.
///
/// `input` and `output` need buffer capacity of at least `min_buffer_len`
/// (see the fields); a smaller one is `error.BufferTooSmall`.
///
/// Stack: the handshake runs about 296 KiB deep and the dead-stack burn then
/// zeroes 384 KiB below the caller (`burn.init_burn`), so the calling thread
/// needs roughly 400 KiB of free stack; a smaller one (a fibre, a thread
/// spawned with a small `stack_size`) overflows it.
///
/// std's shape, kept for drop-in use. The returned `Client` holds the
/// application traffic secrets and keys, and returning it by value leaves a
/// copy in this function's dead frame and in the caller's temporaries; use
/// `initInto` to have the handshake write it straight to its final place.
pub fn init(input: *Reader, output: *Writer, options: Options) InitError!Client {
    // zig-libs tlsclient: dead-stack burn. The ECDHE secrets and the key
    // schedule live in `initBody`'s frame and in std's callee frames (X25519,
    // ML-KEM, P-256/P-384, HKDF); the body runs one frame down and the burn
    // zeroes everything it dirtied (see `burn.init_burn`). `options` is copied
    // into the argument tuple: pointers and public values only.
    return burn.run(burn.init_burn, InitError!Client, initBody, .{ input, output, options });
}

/// `init`, with the established session written to `out` (zig-libs
/// tlsclient). The application traffic secrets and keys are copied only
/// inside the burned call tree, so no copy is left on the dead stack, in this
/// frame or the caller's. `out` is left untouched on error.
pub fn initInto(out: *Client, input: *Reader, output: *Writer, options: Options) InitError!void {
    return burn.run(burn.init_burn, InitError!void, initIntoBody, .{ out, input, output, options });
}

fn initIntoBody(out: *Client, input: *Reader, output: *Writer, options: Options) InitError!void {
    out.* = try initBody(input, output, options);
}

fn initBody(input: *Reader, output: *Writer, options: Options) InitError!Client {
    // zig-libs tlsclient: std asserted the input capacity (UB in
    // ReleaseFast) and met a too-small output only at the first record
    // (no-panic sweep 2026-10-28).
    if (input.buffer.len < min_buffer_len or outputTooSmall(output)) return error.BufferTooSmall;
    // A record's plaintext is decrypted into `read_buffer`: one that cannot
    // hold the largest failed every big enough record with TlsRecordOverflow,
    // an empty one also tripped std Reader asserts (sweep 2026-10-28, F6).
    if (options.read_buffer.len < max_ciphertext_len) return error.BufferTooSmall;
    const host = switch (options.host) {
        .no_verification => "",
        .explicit => |host| host,
    };
    // zig-libs tlsclient: a caller-supplied name too long for the hello
    // reached `catch unreachable` / an `@intCast` (review F5, 2026-10-26).
    if (host.len > 255) return error.HostNameInvalid;

    const client_hello_rand = options.entropy[0..32].*;
    var key_seq: u64 = 0;
    var server_hello_rand: [32]u8 = undefined;
    const legacy_session_id = options.entropy[32..64].*;

    // zig-libs tlsclient: the ClientHello is built at run time (hello.zig)
    // from the options; std's comptime shape is `std_groups` with every addition off.
    try checkVersions(options.min_version, options.max_version);
    try checkGroups(options.groups, options.key_share_groups);
    if (options.verify_connection != null and options.connection_info == null) return error.ConnectionInfoRequired;
    const info: ?*ConnectionInfo = options.connection_info;
    if (info) |ci| ci.reset();
    const offer_12 = options.min_version == .tls_1_2;
    var key_share = KeyShare.init(options.entropy[64..240]);
    var versions_buf: [2]tls.ProtocolVersion = undefined;
    const versions = offeredVersions(&versions_buf, options.min_version, options.max_version);
    var alpn_ext_buf: [4 + 2 + max_alpn_len]u8 = undefined;
    const alpn_ext = try alpnExtension(&alpn_ext_buf, options.alpn_protocols);
    // zig-libs tlsclient: an IP literal is not a server name -- RFC 6066 §3
    // forbids it in SNI (Go sends none); it is checked against iPAddress SANs.
    const host_is_ip = if (x509.hostname.parseHost(host)) |h| h != .dns else false;
    var hello_params: hello.Params = .{
        .random = &client_hello_rand,
        .session_id = &legacy_session_id,
        .cipher_suites = &cipher_suites,
        .host = if (host_is_ip) "" else host,
        .versions = versions,
        .groups = options.groups,
        .shares = &.{},
        .alpn_ext = alpn_ext,
        .status_request = options.request_ocsp,
        .signed_certificate_timestamp = options.request_scts,
        .extended_master_secret = options.extended_master_secret and offer_12,
        .renegotiation_info = options.renegotiation_info and offer_12,
    };
    // zig-libs tlsclient: TLS 1.3 resumption -- a fresh ticket for this
    // host is offered as a PSK (copied out under the cache lock).
    // zig-libs tlsclient: a caller's clock outside i64 milliseconds failed
    // this cast, and std's `Timestamp.toSeconds` in the chain checks
    // (no-panic sweep 2026-10-28).
    const now_ms: i64 = std.math.cast(i64, @divFloor(options.realtime_now.nanoseconds, std.time.ns_per_ms)) orelse return error.RealtimeInvalid;
    var offer: ?ResumeOffer = null;
    if (options.session_cache) |cache| if (host.len != 0 and options.max_version == .tls_1_3) {
        cache.acquire();
        defer cache.release();
        // zig-libs tlsclient: a session is resumed only under the
        // verification it was made with, or with none now -- one made with
        // `.no_verification` or `.self_signed` is not resumed under a bundle
        // (Go: a session without verified chains is not resumed by a verifying
        // config). A cache shared by different bundles is still one trust
        // domain (review F2, 2026-10-26; see SessionCache).
        if (cache.find(host)) |e| if (e.fresh(now_ms) and resumableUnder(e, options.ca)) {
            offer = .{ .entry = e, .generation = e.generation, .hash = e.hash, .psk = e.psk, .ticket_len = e.ticket_len, .age = tlsresume.replay.obfuscateAge(@intCast(now_ms - e.received_ms), e.ticket_age_add) };
            @memcpy(offer.?.ticket_buf[0..e.ticket_len], e.ticket());
        };
    };
    defer if (offer) |*o| crypto.secureZero(u8, &o.psk);
    if (offer) |*o| hello_params.psk = .{ .identity = o.ticket(), .obfuscated_ticket_age = o.age, .binder_len = @intCast(o.hashLen()) };
    var shares_buf: [supported_groups.len]hello.Share = undefined;
    // In TLS 1.2 only, no key_share is sent (RFC 8446 §4.2.8 is TLS 1.3's).
    const share_groups = if (options.max_version == .tls_1_3) options.key_share_groups else &.{};
    for (share_groups, 0..) |g, i| {
        key_share.ensure(g) catch return error.InsufficientEntropy; // only an all-zero seed fails
        shares_buf[i] = .{ .group = g, .key = key_share.publicKey(g) };
    }
    hello_params.shares = shares_buf[0..share_groups.len];
    var hello_buf: [hello.max_len]u8 = undefined;
    var hello_msg: []const u8 = hello.write(&hello_buf, hello_params) catch unreachable; // bounded: max_len covers every share + host + ALPN + ticket
    // RFC 8446 §4.2.11.2: the binder over the ClientHello truncated before
    // the binders list.
    if (offer) |*o| switch (o.hash) {
        inline else => |k| fillBinder(HashOf(k), hello_buf[0..hello_msg.len], &o.psk, &HashOf(k).init(.{})),
    };
    try writeHelloRecord(output, .tls_1_0, hello_msg);
    // zig-libs tlsclient: client authentication -- RSA-PSS salts and the
    // `rsa` module's blinding come from a CSPRNG keyed from the secret part
    // of the entropy; TLS 1.2's CertificateVerify needs the messages' hashes.
    const auth_configured = options.client_auth != null or options.client_auth_select != null;
    var auth_csprng = std.Random.DefaultCsprng.init(crypto.kdf.hkdf.HkdfSha256.extract("zig-libs tlsclient client auth", options.entropy[64..240]));
    defer crypto.secureZero(u8, mem.asBytes(&auth_csprng));
    var cv12: ?Cv12Hashes = if (auth_configured and offer_12) .{} else null;
    if (cv12) |*h| h.update(hello_msg);
    // zig-libs tlsclient: HelloRetryRequest state (RFC 8446 §4.1.4).
    var hrr_seen = false;
    var hrr_suite: tls.CipherSuite = undefined;
    var hrr_group: ?tls.NamedGroup = null;
    var cookie_buf: [hello.max_cookie_len]u8 = undefined;
    // zig-libs tlsclient: client authentication -- the server's
    // CertificateRequest, when one came.
    var cert_request: ?CertRequest = null;

    // zig-libs tlsclient: defined until the ServerHello sets it (std left it
    // undefined and compared it in several message handlers before then; a
    // version no ServerHello can negotiate here keeps those checks honest).
    var tls_version: tls.ProtocolVersion = .tls_1_0;
    var chain: Certificate.Chain = if (Certificate.Chain != void) .empty;
    defer if (Certificate.Chain != void) chain.deinit();
    // These are used for two purposes:
    // * Detect whether a certificate is the first one presented, in which case
    //   we need to verify the host name.
    var cert_index: usize = 0;
    // * Flip back and forth between the two cleartext buffers in order to keep
    //   the previous certificate in memory so that it can be verified by the
    //   next one.
    var cert_buf_index: usize = 0;
    var write_seq: u64 = 0;
    var read_seq: u64 = 0;
    var prev_cert: Certificate.Parsed = undefined;
    const CipherState = enum {
        /// No cipher is in use
        cleartext,
        /// Handshake cipher is in use
        handshake,
        /// Application cipher is in use
        application,
    };
    var pending_cipher_state: CipherState = .cleartext;
    var cipher_state = pending_cipher_state;
    const HandshakeState = enum {
        /// In this state we expect only a server hello message.
        hello,
        /// In this state we expect only an encrypted_extensions message.
        encrypted_extensions,
        /// In this state we expect certificate handshake messages.
        certificate,
        /// In this state we expect certificate or certificate_verify messages.
        /// certificate messages are ignored since the trust chain is already
        /// established.
        trust_chain_established,
        /// In this state, we expect only the server_hello_done handshake message.
        server_hello_done,
        /// In this state, we expect only the finished handshake message.
        finished,
    };
    var handshake_state: HandshakeState = .hello;
    // zig-libs tlsclient: ALPN -- the server's choice, one of ours.
    var alpn_selected: ?[]const u8 = null;
    var handshake_cipher: tls.HandshakeCipher = undefined;
    var main_cert_pub_key: CertificatePublicKey = undefined;
    var tls12_negotiated_group: ?tls.NamedGroup = null;
    // zig-libs tlsclient: session view.
    var negotiated_group: ?tls.NamedGroup = null;
    var negotiated_suite: tls.CipherSuite = undefined;
    // zig-libs tlsclient: TLS 1.2 ServerHello answers (RFC 6066, 7627).
    var ocsp_promised = false;
    var ems_negotiated = false;
    var tls12_master: [48]u8 = undefined;
    defer crypto.secureZero(u8, &tls12_master);
    var exporter: Exporter = .none;
    var session_entry: ?*ClientSession = null;
    var session_generation: u64 = 0;
    // zig-libs tlsclient: resumption state.
    var psk_accepted = false;
    var saved_chain: [verify.max_chain_len][]const u8 = undefined;
    var saved_chain_len: usize = 0;
    var leaf_not_after: i64 = std.math.maxInt(i64);
    const now_sec = options.realtime_now.toSeconds();

    var cleartext_fragment_start: usize = 0;
    var cleartext_fragment_end: usize = 0;
    var cleartext_bufs: [2][tls.max_ciphertext_inner_record_len]u8 = undefined;
    fragment: while (true) {
        // Ensure the input buffer pointer is stable in this scope.
        input.rebase(tls.max_ciphertext_record_len) catch |err| switch (err) {
            error.EndOfStream => {}, // We have assurance the remainder of stream can be buffered.
            error.ReadFailed => |e| return e,
        };
        const record_header = input.peek(tls.record_header_len) catch |err| switch (err) {
            error.EndOfStream => return error.TlsConnectionTruncated,
            error.ReadFailed => |e| return e,
        };
        const record_ct = input.takeEnumNonexhaustive(tls.ContentType, .big) catch unreachable; // already peeked
        input.toss(2); // legacy_version
        const record_len = input.takeInt(u16, .big) catch unreachable; // already peeked
        if (record_len > tls.max_ciphertext_len) return error.TlsRecordOverflow;
        const record_buffer = input.take(record_len) catch |err| switch (err) {
            error.EndOfStream => return error.TlsConnectionTruncated,
            error.ReadFailed => return error.ReadFailed,
        };
        var record_decoder: tls.Decoder = .fromTheirSlice(record_buffer);
        var ctd, const ct = content: switch (cipher_state) {
            .cleartext => .{ record_decoder, record_ct },
            .handshake => {
                assert(tls_version == .tls_1_3);
                // zig-libs tlsclient: the middlebox-compatibility CCS stays
                // cleartext (RFC 8446 §5, D.4) and is ignored below.
                if (record_ct == .change_cipher_spec) break :content .{ record_decoder, record_ct };
                if (record_ct != .application_data) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                const cleartext_buf = &cleartext_bufs[cert_buf_index % 2];
                const record_start = cleartext_fragment_end;
                switch (handshake_cipher) {
                    inline else => |*p| {
                        const pv = &p.version.tls_1_3;
                        const P = @TypeOf(p.*).A;
                        if (record_len < P.AEAD.tag_length) return error.TlsRecordOverflow;
                        const ciphertext = record_decoder.slice(record_len - P.AEAD.tag_length);
                        const cleartext_fragment_buf = cleartext_buf[cleartext_fragment_end..];
                        if (ciphertext.len > cleartext_fragment_buf.len) return error.TlsRecordOverflow;
                        const cleartext = cleartext_fragment_buf[0..ciphertext.len];
                        const auth_tag = record_decoder.array(P.AEAD.tag_length).*;
                        const nonce = nonce: {
                            const V = @Vector(P.AEAD.nonce_length, u8);
                            const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                            const operand: V = pad ++ @as([8]u8, @bitCast(@byteSwap(read_seq)));
                            break :nonce @as(V, pv.server_handshake_iv) ^ operand;
                        };
                        P.AEAD.decrypt(cleartext, ciphertext, auth_tag, record_header, nonce, pv.server_handshake_key) catch
                            return error.TlsBadRecordMac;
                        // TODO use scalar, non-slice version
                        const inner = mem.trimEnd(u8, cleartext, "\x00");
                        // zig-libs tlsclient: RFC 8446 §5.4 -- an all-zero
                        // plaintext has no content type; std underflowed
                        // `cleartext_fragment_end` below.
                        if (inner.len == 0) return error.TlsUnexpectedMessage;
                        cleartext_fragment_end += inner.len;
                    },
                }
                read_seq += 1;
                cleartext_fragment_end -= 1;
                const ct: tls.ContentType = @fromBackingInt(@intCast(cleartext_buf[cleartext_fragment_end]));
                // zig-libs tlsclient: an alert under the handshake key (a
                // server refusing after its ServerHello, RFC 8446 §6) is
                // `TlsAlert` with its description; std called it an
                // unexpected message. Only this record's octets: a partial
                // handshake message may precede them in the buffer.
                if (ct == .alert) {
                    const a = cleartext_buf[record_start..cleartext_fragment_end];
                    cleartext_fragment_end = record_start;
                    break :content .{ tls.Decoder.fromTheirSlice(@constCast(a)), ct };
                }
                if (ct != .handshake) return error.TlsUnexpectedMessage;
                break :content .{ tls.Decoder.fromTheirSlice(@constCast(cleartext_buf[cleartext_fragment_start..cleartext_fragment_end])), ct };
            },
            .application => {
                assert(tls_version == .tls_1_2);
                if (record_ct != .handshake) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                const cleartext_buf = &cleartext_bufs[cert_buf_index % 2];
                switch (handshake_cipher) {
                    inline else => |*p| {
                        const pv = &p.version.tls_1_2;
                        const P = @TypeOf(p.*).A;
                        if (record_len < P.record_iv_length + P.mac_length) return error.TlsRecordOverflow;
                        const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                        const cleartext_fragment_buf = cleartext_buf[cleartext_fragment_end..];
                        if (message_len > cleartext_fragment_buf.len) return error.TlsRecordOverflow;
                        const cleartext = cleartext_fragment_buf[0..message_len];
                        const ad = mem.toBytes(big(read_seq)) ++
                            record_header[0 .. 1 + 2] ++
                            mem.toBytes(big(message_len));
                        const record_iv = record_decoder.array(P.record_iv_length).*;
                        const masked_read_seq = read_seq &
                            comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                        const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                            const V = @Vector(P.AEAD.nonce_length, u8);
                            const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                            const operand: V = pad ++ @as([8]u8, @bitCast(@byteSwap(masked_read_seq)));
                            break :nonce @as(V, pv.app_cipher.server_write_IV ++ record_iv) ^ operand;
                        };
                        const ciphertext = record_decoder.slice(message_len);
                        const auth_tag = record_decoder.array(P.mac_length);
                        P.AEAD.decrypt(cleartext, ciphertext, auth_tag.*, ad, nonce, pv.app_cipher.server_write_key) catch return error.TlsBadRecordMac;
                        cleartext_fragment_end += message_len;
                    },
                }
                read_seq += 1;
                break :content .{ tls.Decoder.fromTheirSlice(cleartext_buf[cleartext_fragment_start..cleartext_fragment_end]), record_ct };
            },
        };
        switch (ct) {
            .alert => {
                ctd.ensure(2) catch continue :fragment;
                if (options.alert) |a| a.* = .{
                    .level = ctd.decode(tls.Alert.Level),
                    .description = ctd.decode(tls.Alert.Description),
                };
                return error.TlsAlert;
            },
            .change_cipher_spec => {
                ctd.ensure(1) catch continue :fragment;
                if (ctd.decode(tls.ChangeCipherSpecType) != .change_cipher_spec) return error.TlsIllegalParameter;
                cipher_state = pending_cipher_state;
            },
            .handshake => while (true) {
                ctd.ensure(4) catch continue :fragment;
                const handshake_type = ctd.decode(tls.HandshakeType);
                const handshake_len = ctd.decode(u24);
                var hsd = ctd.sub(handshake_len) catch continue :fragment;
                const wrapped_handshake = ctd.buf[ctd.idx - handshake_len - 4 .. ctd.idx];
                // zig-libs tlsclient: TLS 1.2 handshake messages are cleartext
                // up to the server's Finished; TLS 1.3 never reads these hashes.
                if (cv12) |*h| if (cipher_state == .cleartext) h.update(wrapped_handshake);
                switch (handshake_type) {
                    .server_hello => {
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .hello) return error.TlsUnexpectedMessage;
                        try hsd.ensure(2 + 32 + 1);
                        const legacy_version = hsd.decode(u16);
                        @memcpy(&server_hello_rand, hsd.array(32));
                        // zig-libs tlsclient: a HelloRetryRequest (RFC 8446
                        // §4.1.4) is answered with a second ClientHello; std
                        // aborted on any.
                        const is_hrr = mem.eql(u8, &server_hello_rand, &tls.hello_retry_request_sequence);
                        if (is_hrr and hrr_seen) return error.TlsUnexpectedMessage; // a second HRR
                        const legacy_session_id_echo_len = hsd.decode(u8);
                        // zig-libs tlsclient: widened -- std summed in u8, so an echo length of
                        // 253..255 overflowed (a remote panic in safe modes, a short check
                        // in ReleaseFast). Found by TLSCLIENT_FUZZ, 2026-10-13.
                        try hsd.ensure(@as(usize, legacy_session_id_echo_len) + 2 + 1);
                        const legacy_session_id_echo = hsd.slice(legacy_session_id_echo_len);
                        const cipher_suite_tag = hsd.decode(tls.CipherSuite);
                        hsd.skip(1); // legacy_compression_method
                        var supported_version: ?u16 = null;
                        // zig-libs tlsclient: ALPN.
                        var alpn_seen = false;
                        // zig-libs tlsclient: HRR fields, and the ServerHello's group.
                        var hrr_selected: ?tls.NamedGroup = null;
                        var hrr_cookie: ?[]const u8 = null;
                        var sh_group: ?tls.NamedGroup = null;
                        if (!hsd.eof()) {
                            try hsd.ensure(2);
                            const extensions_size = hsd.decode(u16);
                            var all_extd = try hsd.sub(extensions_size);
                            while (!all_extd.eof()) {
                                try all_extd.ensure(2 + 2);
                                const et = all_extd.decode(tls.ExtensionType);
                                const ext_size = all_extd.decode(u16);
                                var extd = try all_extd.sub(ext_size);
                                switch (et) {
                                    .supported_versions => {
                                        if (supported_version) |_| return error.TlsIllegalParameter;
                                        try extd.ensure(2);
                                        supported_version = extd.decode(u16);
                                    },
                                    .key_share => if (is_hrr) {
                                        // HRR: only the selected group.
                                        if (hrr_selected != null) return error.TlsIllegalParameter;
                                        try extd.ensure(2);
                                        hrr_selected = extd.decode(tls.NamedGroup);
                                    } else {
                                        if (key_share.getSharedSecret()) |_| return error.TlsIllegalParameter;
                                        try extd.ensure(4);
                                        const named_group = extd.decode(tls.NamedGroup);
                                        const key_size = extd.decode(u16);
                                        try extd.ensure(key_size);
                                        // After an HRR the server must use the group it asked for.
                                        if (hrr_group) |g| if (g != named_group) return error.TlsIllegalParameter;
                                        // zig-libs tlsclient: otherwise one we sent a share for
                                        // (RFC 8446 §4.2.8) -- the X25519 key pair also exists for
                                        // the hybrid share, so `exchange` alone accepted an
                                        // unoffered X25519 (review F4, 2026-10-26).
                                        if (hrr_group == null and mem.findScalar(tls.NamedGroup, share_groups, named_group) == null)
                                            return error.TlsIllegalParameter;
                                        try key_share.exchange(named_group, extd.slice(key_size));
                                        sh_group = named_group;
                                    },
                                    .pre_shared_key => if (!is_hrr) {
                                        // RFC 8446 §4.2.11: the one identity we offered.
                                        if (offer == null or psk_accepted) return error.TlsIllegalParameter;
                                        try extd.ensure(2);
                                        if (extd.decode(u16) != 0) return error.TlsIllegalParameter;
                                        psk_accepted = true;
                                    } else return error.TlsIllegalParameter,
                                    .cookie => if (is_hrr) {
                                        if (hrr_cookie != null) return error.TlsIllegalParameter;
                                        try extd.ensure(2);
                                        const len = extd.decode(u16);
                                        if (len == 0 or len > hello.max_cookie_len) return error.TlsIllegalParameter;
                                        try extd.ensure(len);
                                        hrr_cookie = extd.slice(len);
                                    } else return error.TlsIllegalParameter,
                                    // zig-libs tlsclient: ALPN (TLS 1.2 answers in ServerHello).
                                    .application_layer_protocol_negotiation => if (options.alpn_protocols.len != 0) {
                                        if (is_hrr) return error.TlsIllegalParameter;
                                        if (alpn_seen) return error.TlsIllegalParameter;
                                        alpn_seen = true;
                                        alpn_selected = try alpnSelected(options.alpn_protocols, extd.rest());
                                    },
                                    // zig-libs tlsclient: TLS 1.2 answers to what we asked for
                                    // (a TLS 1.3 server sends these elsewhere; ignored here).
                                    .status_request => if (!is_hrr and options.request_ocsp) {
                                        if (ext_size != 0) return error.TlsDecodeError;
                                        ocsp_promised = true;
                                    },
                                    .signed_certificate_timestamp => if (!is_hrr and options.request_scts) {
                                        if (info) |ci| try keepScts(ci, extd.rest());
                                    },
                                    else => switch (@backingInt(et)) {
                                        hello.ext_extended_master_secret => if (!is_hrr and options.extended_master_secret) {
                                            if (ext_size != 0) return error.TlsDecodeError;
                                            ems_negotiated = true;
                                        },
                                        // RFC 5746 §3.4: on an initial handshake it must be empty.
                                        hello.ext_renegotiation_info => if (!is_hrr and options.renegotiation_info) {
                                            if (ext_size != 1 or extd.rest()[0] != 0) return error.TlsIllegalParameter;
                                        },
                                        else => {},
                                    },
                                }
                            }
                        }

                        tls_version = @fromBackingInt(@intCast(supported_version orelse legacy_version));
                        // zig-libs tlsclient: the version must be one we offered.
                        if (!versionOffered(versions, tls_version)) return error.TlsIllegalParameter;
                        switch (tls_version) {
                            .tls_1_3 => if (!mem.eql(u8, legacy_session_id_echo, &legacy_session_id)) return error.TlsIllegalParameter,
                            // RFC 8446 §4.1.3: a client that offered TLS 1.3
                            // refuses either downgrade sentinel; one that did
                            // not (max_version 1.2) only the TLS 1.1 one.
                            .tls_1_2 => if (mem.eql(u8, server_hello_rand[24..31], "DOWNGRD") and
                                (server_hello_rand[31] == 0x00 or
                                    (server_hello_rand[31] == 0x01 and options.max_version == .tls_1_3))) return error.TlsIllegalParameter,
                            else => return error.TlsIllegalParameter,
                        }

                        if (psk_accepted and (tls_version != .tls_1_3 or hashKindOf(cipher_suite_tag) != offer.?.hash)) return error.TlsIllegalParameter;
                        if (is_hrr) {
                            // zig-libs tlsclient: RFC 8446 §4.1.4.
                            if (tls_version != .tls_1_3) return error.TlsIllegalParameter;
                            switch (cipher_suite_tag) {
                                .AES_128_GCM_SHA256, .AES_256_GCM_SHA384, .CHACHA20_POLY1305_SHA256, .AEGIS_256_SHA512, .AEGIS_128L_SHA256 => {},
                                else => return error.TlsIllegalParameter,
                            }
                            if (hrr_selected) |g| {
                                // A group we offered, holding no share yet.
                                if (mem.findScalar(tls.NamedGroup, options.groups, g) == null) return error.TlsIllegalParameter;
                                for (hello_params.shares) |sh| if (sh.group == g) return error.TlsIllegalParameter;
                            } else if (hrr_cookie == null) return error.TlsIllegalParameter; // "would not result in any change"
                            try initHandshakeCipher(&handshake_cipher, cipher_suite_tag);
                            switch (handshake_cipher) {
                                inline else => |*p| {
                                    // Transcript: message_hash(Hash(ClientHello1)), HRR.
                                    const H = @TypeOf(p.transcript_hash);
                                    var h1: [H.digest_length]u8 = undefined;
                                    H.hash(hello_msg, &h1, .{});
                                    p.transcript_hash.update(&.{ @backingInt(tls.HandshakeType.message_hash), 0, 0, H.digest_length });
                                    p.transcript_hash.update(&h1);
                                    p.transcript_hash.update(wrapped_handshake);
                                },
                            }
                            if (hrr_selected) |g| {
                                key_share.ensure(g) catch return error.InsufficientEntropy;
                                shares_buf[0] = .{ .group = g, .key = key_share.publicKey(g) };
                                hello_params.shares = shares_buf[0..1];
                                hrr_group = g;
                            }
                            if (hrr_cookie) |c| {
                                @memcpy(cookie_buf[0..c.len], c);
                                hello_params.cookie = cookie_buf[0..c.len];
                            }
                            // A PSK whose hash is not the HRR suite's is dropped
                            // (RFC 8446 §4.1.4); one that fits is re-bound.
                            if (offer) |*o| if (hashKindOf(cipher_suite_tag) != o.hash) {
                                crypto.secureZero(u8, &o.psk);
                                offer = null;
                                hello_params.psk = null;
                            };
                            hello_msg = hello.write(&hello_buf, hello_params) catch unreachable; // bounded as the first
                            if (offer) |*o| switch (handshake_cipher) {
                                inline else => |*p| fillBinder(@TypeOf(p.transcript_hash), hello_buf[0..hello_msg.len], &o.psk, &p.transcript_hash),
                            };
                            switch (handshake_cipher) {
                                inline else => |*p| p.transcript_hash.update(hello_msg),
                            }
                            try writeHelloRecord(output, .tls_1_2, hello_msg);
                            hrr_seen = true;
                            hrr_suite = cipher_suite_tag;
                        } else {
                            if (hrr_seen) {
                                // The ServerHello after an HRR keeps its suite and version.
                                if (tls_version != .tls_1_3 or cipher_suite_tag != hrr_suite) return error.TlsIllegalParameter;
                            } else {
                                switch (cipher_suite_tag) {
                                    .AES_128_GCM_SHA256,
                                    .AES_256_GCM_SHA384,
                                    .CHACHA20_POLY1305_SHA256,
                                    .AEGIS_256_SHA512,
                                    .AEGIS_128L_SHA256,
                                    .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                    .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                    .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                    .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                    .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                    .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                    => {},
                                    else => return error.TlsIllegalParameter,
                                }
                                try initHandshakeCipher(&handshake_cipher, cipher_suite_tag);
                                switch (handshake_cipher) {
                                    inline else => |*p| p.transcript_hash.update(hello_msg),
                                }
                            }
                            switch (handshake_cipher) {
                                inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                            }
                            negotiated_group = sh_group;
                            negotiated_suite = cipher_suite_tag;
                            if (tls_version == .tls_1_3) {
                                ocsp_promised = false;
                                ems_negotiated = false;
                            }
                        }
                        if (!is_hrr) switch (tls_version) {
                            .tls_1_3 => {
                                switch (cipher_suite_tag) {
                                    inline .AES_128_GCM_SHA256,
                                    .AES_256_GCM_SHA384,
                                    .CHACHA20_POLY1305_SHA256,
                                    .AEGIS_256_SHA512,
                                    .AEGIS_128L_SHA256,
                                    => |tag| {
                                        const sk = key_share.getSharedSecret() orelse return error.TlsIllegalParameter;
                                        const p = &@field(handshake_cipher, @tagName(tag.with()));
                                        const P = @TypeOf(p.*).A;
                                        const hello_hash = p.transcript_hash.peek();
                                        const zeroes = @as([P.Hash.digest_length]u8, @splat(0));
                                        // zig-libs tlsclient: a resumption PSK keys the
                                        // early secret (RFC 8446 §7.1).
                                        const early_secret = if (psk_accepted)
                                            P.Hkdf.extract(&zeroes, offer.?.psk[0..P.Hash.digest_length])
                                        else
                                            P.Hkdf.extract(&[1]u8{0}, &zeroes);
                                        const empty_hash = tls.emptyHash(P.Hash);
                                        p.version = .{ .tls_1_3 = undefined };
                                        const pv = &p.version.tls_1_3;
                                        const hs_derived_secret = hkdfExpandLabel(P.Hkdf, early_secret, "derived", &empty_hash, P.Hash.digest_length);
                                        pv.handshake_secret = P.Hkdf.extract(&hs_derived_secret, sk);
                                        const ap_derived_secret = hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "derived", &empty_hash, P.Hash.digest_length);
                                        pv.master_secret = P.Hkdf.extract(&ap_derived_secret, &zeroes);
                                        const client_secret = hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "c hs traffic", &hello_hash, P.Hash.digest_length);
                                        const server_secret = hkdfExpandLabel(P.Hkdf, pv.handshake_secret, "s hs traffic", &hello_hash, P.Hash.digest_length);
                                        if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                            .client_random = &client_hello_rand,
                                        }, .{
                                            .SERVER_HANDSHAKE_TRAFFIC_SECRET = &server_secret,
                                            .CLIENT_HANDSHAKE_TRAFFIC_SECRET = &client_secret,
                                        });
                                        pv.client_finished_key = hkdfExpandLabel(P.Hkdf, client_secret, "finished", "", P.Hmac.key_length);
                                        pv.server_finished_key = hkdfExpandLabel(P.Hkdf, server_secret, "finished", "", P.Hmac.key_length);
                                        pv.client_handshake_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length);
                                        pv.server_handshake_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length);
                                        pv.client_handshake_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length);
                                        pv.server_handshake_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length);
                                    },
                                    else => return error.TlsIllegalParameter,
                                }
                                pending_cipher_state = .handshake;
                                // zig-libs tlsclient: TLS 1.3 encrypts from the
                                // record after ServerHello whether or not a
                                // ChangeCipherSpec came (RFC 8446 §5: CCS is
                                // ignored). std waited for one, and after an HRR
                                // the server's only CCS precedes this ServerHello.
                                cipher_state = .handshake;
                                handshake_state = .encrypted_extensions;
                            },
                            .tls_1_2 => switch (cipher_suite_tag) {
                                .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                                => handshake_state = .certificate,
                                else => return error.TlsIllegalParameter,
                            },
                            else => return error.TlsIllegalParameter,
                        };
                    },
                    .encrypted_extensions => {
                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                        if (handshake_state != .encrypted_extensions) return error.TlsUnexpectedMessage;
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        try hsd.ensure(2);
                        const total_ext_size = hsd.decode(u16);
                        var all_extd = try hsd.sub(total_ext_size);
                        // zig-libs tlsclient: ALPN (TLS 1.3 answers in
                        // EncryptedExtensions); std's loop read nothing.
                        if (try encryptedExtensionsAlpn(&all_extd, options.alpn_protocols)) |sel| {
                            if (alpn_selected != null) return error.TlsIllegalParameter;
                            alpn_selected = sel;
                        }
                        handshake_state = .certificate;
                        // zig-libs tlsclient: a resumed handshake authenticates
                        // by the PSK -- no Certificate, CertificateVerify or
                        // CertificateRequest follow (RFC 8446 §2.2). The view
                        // shows the chain kept with the ticket; the hook runs.
                        if (psk_accepted) {
                            handshake_state = .finished;
                            if (info) |ci| {
                                try copyKeptChain(ci, options.session_cache.?, offer.?.entry, offer.?.generation);
                                fillInfo(ci, tls_version, negotiated_suite, negotiated_group, alpn_selected, hrr_seen, false);
                                ci.did_resume = true;
                                if (options.verify_connection) |vc| vc.verify(vc.context, ci) catch return error.TlsConnectionRejected;
                            }
                        }
                    },
                    .certificate => cert: {
                        if (cipher_state == .application) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .certificate => {},
                            .trust_chain_established => break :cert,
                            else => return error.TlsUnexpectedMessage,
                        }
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }

                        switch (tls_version) {
                            .tls_1_3 => {
                                try hsd.ensure(1 + 3);
                                const cert_req_ctx_len = hsd.decode(u8);
                                if (cert_req_ctx_len != 0) return error.TlsIllegalParameter;
                            },
                            .tls_1_2 => try hsd.ensure(3),
                            else => unreachable,
                        }
                        const certs_size = hsd.decode(u24);
                        const certs = try hsd.sub(certs_size);

                        var peer_chain: [verify.max_chain_len][]const u8 = undefined;
                        var peer_chain_len: usize = 0;
                        var certs_decoder = certs;
                        while (!certs_decoder.eof()) {
                            try certs_decoder.ensure(3);
                            const cert_size = certs_decoder.decode(u24);
                            const certd = try certs_decoder.sub(cert_size);

                            if (tls_version == .tls_1_3) {
                                try certs_decoder.ensure(2);
                                const total_ext_size = certs_decoder.decode(u16);
                                const all_extd = try certs_decoder.sub(total_ext_size);
                                // zig-libs tlsclient: the leaf's OCSP response and
                                // SCTs ride in its entry (RFC 8446 §4.4.2.1).
                                if (cert_index == 0) if (info) |ci| try leafEntryExtensions(ci, all_extd, options.request_ocsp, options.request_scts);
                            }

                            // zig-libs tlsclient: every certificate is proven
                            // well-formed before std's parser sees it, and the
                            // chain is judged whole after this loop -- see
                            // verify.zig. (std: parse bare, verify link by link.)
                            const der = certd.rest();
                            try verify.checkWellFormed(der);
                            if (peer_chain_len == verify.max_chain_len) return error.TlsCertificateNotVerified;
                            peer_chain[peer_chain_len] = der;
                            peer_chain_len += 1;

                            if (cert_index == 0) {
                                const subject = try (Certificate{ .buffer = der, .index = 0 }).parse();
                                // Verify the host on the first certificate.
                                // zig-libs tlsclient: Go's rules via `x509.hostname`
                                // (RFC 9525): SAN only -- no commonName fallback,
                                // which std's `verifyHostName` still had -- and IP
                                // hosts against iPAddress entries, which std could
                                // not match at all.
                                switch (options.host) {
                                    .no_verification => {},
                                    .explicit => x509.hostname.verify(der, host) catch |e| return switch (e) {
                                        error.CertificateHostMismatch => error.CertificateHostMismatch,
                                        else => error.TlsCertificateNotVerified,
                                    },
                                }

                                // Keep track of the public key for the
                                // certificate_verify message later.
                                try main_cert_pub_key.init(subject.pub_key_algo, subject.pubKey());
                                prev_cert = subject;
                            }
                            cert_index += 1;
                        }

                        // An empty list: nothing to trust (std left the state
                        // at .certificate and failed on the next message).
                        if (peer_chain_len == 0) return error.TlsCertificateNotVerified;
                        // zig-libs tlsclient: resumption keeps the chain and the
                        // leaf's expiry; the slices stay valid until `init`
                        // returns (the record buffers flip only per Certificate).
                        @memcpy(saved_chain[0..peer_chain_len], peer_chain[0..peer_chain_len]);
                        saved_chain_len = peer_chain_len;
                        leaf_not_after = std.math.cast(i64, prev_cert.validity.not_after) orelse std.math.maxInt(i64);
                        // zig-libs tlsclient: the session view keeps the chain.
                        if (info) |ci| for (peer_chain[0..peer_chain_len]) |der| {
                            ci.peer_certificates_buf[ci.peer_certificates_len] = try ci.keep(der);
                            ci.peer_certificates_len += 1;
                        };
                        switch (options.ca) {
                            .no_verification => handshake_state = .trust_chain_established,
                            .self_signed => {
                                try prev_cert.verify(prev_cert, now_sec);
                                handshake_state = .trust_chain_established;
                            },
                            .bundle => |ca| {
                                try ca.lock.lockShared(ca.io);
                                defer ca.lock.unlockShared(ca.io);
                                try verify.verifyAgainstBundle(peer_chain[0..peer_chain_len], ca.bundle, now_sec);
                                handshake_state = .trust_chain_established;
                            },
                        }

                        if (Certificate.Chain != void) {
                            certs_decoder = certs;
                            while (!certs_decoder.eof()) {
                                try certs_decoder.ensure(3);
                                const cert_size = certs_decoder.decode(u24);
                                const certd = try certs_decoder.sub(cert_size);
                                chain.addCert(certd.rest()) catch |err| switch (err) {
                                    error.Unexpected => return error.TlsCertificateNotVerified,
                                };
                                if (tls_version == .tls_1_3) {
                                    try certs_decoder.ensure(2);
                                    const total_ext_size = certs_decoder.decode(u16);
                                    const all_extd = try certs_decoder.sub(total_ext_size);
                                    _ = all_extd;
                                }
                            }
                        }

                        cert_buf_index += 1;
                    },
                    // zig-libs tlsclient: client authentication. Without a
                    // credential the answer is an empty Certificate (`choose`
                    // picks none), as Go's client sends -- std (and this
                    // client until 2026-10-26) failed the handshake with
                    // TlsUnexpectedMessage, so a server that only REQUESTS a
                    // certificate was unreachable (`tools/interop.zig`).
                    .certificate_request => {
                        if (cert_request != null) return error.TlsUnexpectedMessage;
                        switch (tls_version) {
                            .tls_1_3 => if (cipher_state != .handshake or handshake_state != .certificate) return error.TlsUnexpectedMessage,
                            // TLS 1.2: after ServerKeyExchange, before ServerHelloDone.
                            .tls_1_2 => if (cipher_state != .cleartext or handshake_state != .server_hello_done) return error.TlsUnexpectedMessage,
                            else => return error.TlsUnexpectedMessage, // before any ServerHello
                        }
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        var cas: [CertRequest.max_cas][]const u8 = undefined;
                        var cas_len: usize = 0;
                        var req = if (tls_version == .tls_1_3)
                            try parseCertRequest(&hsd, &cas, &cas_len)
                        else
                            try parseCertRequest12(&hsd, &cas, &cas_len);
                        req.choose(&options, tls_version, cas[0..cas_len]);
                        cert_request = req;
                    },
                    // zig-libs tlsclient: TLS 1.2 stapled OCSP (RFC 6066 §8),
                    // only after the server promised it in ServerHello.
                    @as(tls.HandshakeType, @fromBackingInt(@intCast(hello.hs_certificate_status))) => {
                        if (tls_version != .tls_1_2 or !ocsp_promised) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .trust_chain_established) return error.TlsUnexpectedMessage;
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        const ocsp = try parseCertificateStatus(hsd.rest());
                        if (info) |ci| ci.ocsp_response = try ci.keep(ocsp);
                        ocsp_promised = false; // once
                    },
                    .server_key_exchange => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .trust_chain_established => {},
                            .certificate => try tryDownloadRootCert(&chain, &options),
                            else => return error.TlsUnexpectedMessage,
                        }

                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        try hsd.ensure(1 + 2 + 1);
                        const curve_type = hsd.decode(u8);
                        if (curve_type != 0x03) return error.TlsIllegalParameter; // named_curve
                        const named_group = hsd.decode(tls.NamedGroup);
                        tls12_negotiated_group = named_group;
                        negotiated_group = named_group;
                        const key_size = hsd.decode(u8);
                        try hsd.ensure(key_size);
                        const server_pub_key = hsd.slice(key_size);
                        // zig-libs tlsclient: the suite names the certificate's
                        // key type (RFC 5246 §7.4.2, RFC 8422 §5.3).
                        const ecdsa_suite = switch (negotiated_suite) {
                            .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                            .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                            .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                            => true,
                            else => false,
                        };
                        const key_ok = if (ecdsa_suite)
                            main_cert_pub_key.algo == .X9_62_id_ecPublicKey or main_cert_pub_key.algo == .curveEd25519
                        else
                            main_cert_pub_key.algo == .rsaEncryption or main_cert_pub_key.algo == .rsassa_pss;
                        if (!key_ok) return error.TlsBadSignatureScheme;
                        try main_cert_pub_key.verifySignature(.tls_1_2, &hsd, &.{ &client_hello_rand, &server_hello_rand, hsd.buf[0..hsd.idx] });
                        // zig-libs tlsclient: one of our groups (and not the
                        // TLS 1.3-only hybrid); its key pair is made now.
                        if (named_group == .x25519_ml_kem768 or
                            mem.findScalar(tls.NamedGroup, options.groups, named_group) == null) return error.TlsIllegalParameter;
                        key_share.ensure(named_group) catch return error.InsufficientEntropy;
                        try key_share.exchange(named_group, server_pub_key);
                        handshake_state = .server_hello_done;
                    },
                    .server_hello_done => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .server_hello_done) return error.TlsUnexpectedMessage;
                        // zig-libs tlsclient: the server is authenticated
                        // (chain + ServerKeyExchange signature): the hook runs
                        // before anything of ours that depends on it is sent.
                        if (info) |ci| {
                            fillInfo(ci, tls_version, negotiated_suite, negotiated_group, alpn_selected, hrr_seen, ems_negotiated);
                            if (options.verify_connection) |vc| vc.verify(vc.context, ci) catch return error.TlsConnectionRejected;
                        }

                        // zig-libs tlsclient: the group's key, made at ServerKeyExchange.
                        const group = tls12_negotiated_group orelse return error.TlsUnexpectedMessage;
                        if (!key_share.has(group)) return error.TlsIllegalParameter;
                        const public_key_bytes: []const u8 = key_share.publicKey(group);

                        const client_key_exchange_prefix = .{@backingInt(tls.ContentType.handshake)} ++
                            int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                            int(u16, @intCast(public_key_bytes.len + 5)) ++ // record length
                            .{@backingInt(tls.HandshakeType.client_key_exchange)} ++
                            int(u24, @intCast(public_key_bytes.len + 1)) ++ // handshake message length
                            .{@as(u8, @intCast(public_key_bytes.len))}; // public key length
                        const client_change_cipher_spec_msg = .{@backingInt(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const pre_master_secret = key_share.getSharedSecret().?;
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                const P = @TypeOf(p.*).A;
                                p.transcript_hash.update(wrapped_handshake);
                                // zig-libs tlsclient: TLS 1.2 client authentication
                                // (RFC 5246 §7.4.6, §7.4.8): Certificate before
                                // ClientKeyExchange, CertificateVerify after it.
                                var cert12_buf: [max_client_auth_len]u8 = undefined;
                                const cert12: []const u8 = if (cert_request) |*req| try clientCertificate12(&cert12_buf, req) else "";
                                p.transcript_hash.update(cert12);
                                if (cv12) |*h| h.update(cert12);
                                p.transcript_hash.update(client_key_exchange_prefix[tls.record_header_len..]);
                                p.transcript_hash.update(public_key_bytes);
                                if (cv12) |*h| {
                                    h.update(client_key_exchange_prefix[tls.record_header_len..]);
                                    h.update(public_key_bytes);
                                }
                                // zig-libs tlsclient: RFC 7627 §4 -- with the
                                // extended master secret the seed is the session
                                // hash through ClientKeyExchange.
                                const master_secret = if (ems_negotiated)
                                    hmacExpandLabel(P.Hmac, pre_master_secret, &.{
                                        "extended master secret",
                                        &p.transcript_hash.peek(),
                                    }, 48)
                                else
                                    hmacExpandLabel(P.Hmac, pre_master_secret, &.{
                                        "master secret",
                                        &client_hello_rand,
                                        &server_hello_rand,
                                    }, 48);
                                if (ems_negotiated) {
                                    tls12_master = master_secret;
                                    exporter = .{ .tls12 = .{
                                        .hash = hashKind(P.Hmac.mac_length),
                                        .master = master_secret,
                                        .randoms = client_hello_rand ++ server_hello_rand,
                                    } };
                                }
                                if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                    .client_random = &client_hello_rand,
                                }, .{
                                    .CLIENT_RANDOM = &master_secret,
                                });
                                const key_block = hmacExpandLabel(
                                    P.Hmac,
                                    &master_secret,
                                    &.{ "key expansion", &server_hello_rand, &client_hello_rand },
                                    @sizeOf(P.Tls_1_2),
                                );
                                var cv12_buf: [8 + max_signature_len]u8 = undefined;
                                const cv12_msg: []const u8 = if (cert_request) |*req| cv: {
                                    if (!req.scheme_ok) break :cv "";
                                    var dig: [64]u8 = undefined;
                                    const dlen = cv12.?.digest(req.scheme, &dig);
                                    var sig_buf: [max_signature_len]u8 = undefined;
                                    const sig = try signCertificateVerify(&sig_buf, req.auth.?.key, req.scheme, .{ .digest = dig[0..dlen] }, auth_csprng.random());
                                    var cw: Writer = .fixed(&cv12_buf);
                                    try writeCertificateVerify(&cw, req.scheme, sig);
                                    break :cv cw.buffered();
                                } else "";
                                p.transcript_hash.update(cv12_msg);
                                const client_verify_cleartext = .{@backingInt(tls.HandshakeType.finished)} ++
                                    array(u24, u8, hmacExpandLabel(
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "client finished", &p.transcript_hash.peek() },
                                        P.verify_data_length,
                                    ));
                                p.transcript_hash.update(&client_verify_cleartext);
                                p.version = .{ .tls_1_2 = .{
                                    .expected_server_verify_data = hmacExpandLabel(
                                        P.Hmac,
                                        &master_secret,
                                        &.{ "server finished", &p.transcript_hash.finalResult() },
                                        P.verify_data_length,
                                    ),
                                    .app_cipher = mem.bytesToValue(P.Tls_1_2, &key_block),
                                } };
                                const pv = &p.version.tls_1_2;
                                const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                                    const V = @Vector(P.AEAD.nonce_length, u8);
                                    const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                                    const operand: V = pad ++ @as([8]u8, @bitCast(@byteSwap(write_seq)));
                                    break :nonce @as(V, pv.app_cipher.client_write_IV ++ pv.app_cipher.client_salt) ^ operand;
                                };
                                var client_verify_msg = .{@backingInt(tls.ContentType.handshake)} ++
                                    int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                                    array(u16, u8, nonce[P.fixed_iv_length..].* ++
                                        @as([client_verify_cleartext.len + P.mac_length]u8, undefined));
                                P.AEAD.encrypt(
                                    client_verify_msg[client_verify_msg.len - P.mac_length -
                                        client_verify_cleartext.len ..][0..client_verify_cleartext.len],
                                    client_verify_msg[client_verify_msg.len - P.mac_length ..][0..P.mac_length],
                                    &client_verify_cleartext,
                                    mem.toBytes(big(write_seq)) ++ client_verify_msg[0 .. 1 + 2] ++ int(u16, client_verify_cleartext.len),
                                    nonce,
                                    pv.app_cipher.client_write_key,
                                );
                                if (cert12.len != 0) try writePlainHandshake(output, cert12);
                                var cke_vec = [_][]const u8{ &client_key_exchange_prefix, public_key_bytes };
                                try output.writeVecAll(&cke_vec);
                                if (cv12_msg.len != 0) try writePlainHandshake(output, cv12_msg);
                                var fin_vec = [_][]const u8{ &client_change_cipher_spec_msg, &client_verify_msg };
                                try output.writeVecAll(&fin_vec);
                                try output.flush();
                            },
                        }
                        write_seq += 1;
                        pending_cipher_state = .application;
                        handshake_state = .finished;
                    },
                    .certificate_verify => {
                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                        switch (handshake_state) {
                            .trust_chain_established => {},
                            .certificate => try tryDownloadRootCert(&chain, &options),
                            else => return error.TlsUnexpectedMessage,
                        }
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                try main_cert_pub_key.verifySignature(.tls_1_3, &hsd, &.{
                                    strRepeat(" ", 64) ++ "TLS 1.3, server CertificateVerify\x00",
                                    &p.transcript_hash.peek(),
                                });
                                p.transcript_hash.update(wrapped_handshake);
                            },
                        }
                        handshake_state = .finished;
                        // zig-libs tlsclient: authenticated -- the hook.
                        if (info) |ci| {
                            fillInfo(ci, tls_version, negotiated_suite, negotiated_group, alpn_selected, hrr_seen, false);
                            if (options.verify_connection) |vc| vc.verify(vc.context, ci) catch return error.TlsConnectionRejected;
                        }
                    },
                    .finished => {
                        if (cipher_state == .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .finished) return error.TlsUnexpectedMessage;
                        // This message is to trick buggy proxies into behaving correctly.
                        const client_change_cipher_spec_msg = .{@backingInt(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const app_cipher = app_cipher: switch (handshake_cipher) {
                            inline else => |*p, tag| switch (tls_version) {
                                .tls_1_3 => {
                                    const pv = &p.version.tls_1_3;
                                    const P = @TypeOf(p.*).A;
                                    try hsd.ensure(P.Hmac.mac_length);
                                    const finished_digest = p.transcript_hash.peek();
                                    p.transcript_hash.update(wrapped_handshake);
                                    const expected_server_verify_data = tls.hmac(P.Hmac, &finished_digest, pv.server_finished_key);
                                    if (!std.crypto.timing_safe.eql([P.Hmac.mac_length]u8, expected_server_verify_data, hsd.array(P.Hmac.mac_length).*)) return error.TlsDecryptError;
                                    // zig-libs tlsclient: `peek`, not std's
                                    // `finalResult` (the same digest) -- client
                                    // authentication extends the transcript.
                                    const handshake_hash = p.transcript_hash.peek();
                                    // zig-libs tlsclient: client authentication.
                                    // The application secrets stay on the
                                    // transcript through the server Finished;
                                    // the client Finished covers our
                                    // Certificate and CertificateVerify too.
                                    var auth_buf: [max_client_auth_len]u8 = undefined;
                                    const auth_msgs: []const u8 = if (cert_request) |*req|
                                        try clientAuthMessages(&auth_buf, req, &p.transcript_hash, auth_csprng.random())
                                    else
                                        "";
                                    const verify_data = tls.hmac(P.Hmac, &p.transcript_hash.peek(), pv.client_finished_key);
                                    const out_cleartext = .{@backingInt(tls.HandshakeType.finished)} ++
                                        array(u24, u8, verify_data) ++
                                        .{@backingInt(tls.ContentType.handshake)};

                                    const wrapped_len = out_cleartext.len + P.AEAD.tag_length;

                                    var finished_msg = .{@backingInt(tls.ContentType.application_data)} ++
                                        int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                                        array(u16, u8, @as([wrapped_len]u8, undefined));

                                    const ad = finished_msg[0..tls.record_header_len];
                                    const ciphertext = finished_msg[tls.record_header_len..][0..out_cleartext.len];
                                    const auth_tag = finished_msg[finished_msg.len - P.AEAD.tag_length ..];
                                    const nonce = pv.client_handshake_iv;
                                    P.AEAD.encrypt(ciphertext, auth_tag, &out_cleartext, ad, nonce, pv.client_handshake_key);

                                    if (auth_msgs.len == 0) {
                                        var all_msgs_vec: [2][]const u8 = .{
                                            &client_change_cipher_spec_msg,
                                            &finished_msg,
                                        };
                                        try output.writeVecAll(&all_msgs_vec);
                                        try output.flush();
                                    } else {
                                        // zig-libs tlsclient: client authentication --
                                        // Certificate, CertificateVerify and Finished
                                        // under the handshake key, sequence 0, 1, ….
                                        try output.writeAll(&client_change_cipher_spec_msg);
                                        try writeHandshakeRecords(P, output, &.{ auth_msgs, out_cleartext[0 .. out_cleartext.len - 1] }, pv.client_handshake_key, pv.client_handshake_iv);
                                        try output.flush();
                                    }

                                    // zig-libs tlsclient: RFC 8446 §7.5 exporter_master_secret.
                                    {
                                        const exp = hkdfExpandLabel(P.Hkdf, pv.master_secret, "exp master", &handshake_hash, P.Hash.digest_length);
                                        exporter = .{ .tls13 = .{ .hash = hashKind(P.Hash.digest_length), .secret = undefined } };
                                        @memcpy(exporter.tls13.secret[0..exp.len], &exp);
                                    }
                                    // zig-libs tlsclient: the resumption master secret
                                    // (RFC 8446 §7.1, transcript through the client
                                    // Finished) goes into the cache entry the
                                    // NewSessionTickets will fill.
                                    if (options.session_cache) |cache| if (host.len != 0) {
                                        var t = p.transcript_hash;
                                        t.update(out_cleartext[0 .. out_cleartext.len - 1]);
                                        var res = hkdfExpandLabel(P.Hkdf, pv.master_secret, "res master", &t.peek(), P.Hash.digest_length);
                                        defer crypto.secureZero(u8, &res);
                                        cache.acquire();
                                        defer cache.release();
                                        const reuse = psk_accepted and offer.?.entry.generation == offer.?.generation;
                                        // zig-libs tlsclient: a new generation on reuse too: this
                                        // connection's secret replaces the entry's, so tickets an
                                        // older connection on the same entry receives later would
                                        // be derived from the wrong secret (review F3, 2026-10-26).
                                        if (cache.reserve(host)) |e| {
                                            e.hash = hashKind(P.Hash.digest_length);
                                            @memcpy(e.resumption_secret[0..res.len], &res);
                                            if (!reuse) {
                                                // A full handshake: the old ticket (another secret) is gone.
                                                e.usable = false;
                                                e.ticket_len = 0;
                                                e.leaf_not_after_s = leaf_not_after;
                                                e.verification = verificationOf(options.ca);
                                                if (!psk_accepted) _ = e.setChain(saved_chain[0..saved_chain_len]);
                                            }
                                            session_entry = e;
                                            session_generation = e.generation;
                                        }
                                    };
                                    const client_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "c ap traffic", &handshake_hash, P.Hash.digest_length);
                                    const server_secret = hkdfExpandLabel(P.Hkdf, pv.master_secret, "s ap traffic", &handshake_hash, P.Hash.digest_length);
                                    if (options.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                        .counter = key_seq,
                                        .client_random = &client_hello_rand,
                                    }, .{
                                        .SERVER_TRAFFIC_SECRET = &server_secret,
                                        .CLIENT_TRAFFIC_SECRET = &client_secret,
                                    });
                                    key_seq += 1;
                                    break :app_cipher @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_3 = .{
                                        .client_secret = client_secret,
                                        .server_secret = server_secret,
                                        .client_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length),
                                        .server_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length),
                                        .client_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length),
                                        .server_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length),
                                    } });
                                },
                                .tls_1_2 => {
                                    const pv = &p.version.tls_1_2;
                                    const P = @TypeOf(p.*).A;
                                    try hsd.ensure(P.verify_data_length);
                                    if (!std.crypto.timing_safe.eql([P.verify_data_length]u8, pv.expected_server_verify_data, hsd.array(P.verify_data_length).*)) return error.TlsDecryptError;
                                    break :app_cipher @unionInit(tls.ApplicationCipher, @tagName(tag), .{ .tls_1_2 = pv.app_cipher });
                                },
                                else => unreachable,
                            },
                        };
                        if (info) |ci| {
                            fillInfo(ci, tls_version, negotiated_suite, negotiated_group, alpn_selected, hrr_seen, ems_negotiated);
                            ci.did_resume = psk_accepted;
                        }
                        if (options.ssl_key_log) |ssl_key_log| ssl_key_log.* = .{
                            .client_key_seq = key_seq,
                            .server_key_seq = key_seq,
                            .client_random = client_hello_rand,
                            .writer = ssl_key_log.writer,
                        };
                        return .{
                            .input = input,
                            .reader = .{
                                .buffer = options.read_buffer,
                                .vtable = &.{
                                    .stream = stream,
                                    .readVec = readVec,
                                },
                                .seek = 0,
                                .end = 0,
                            },
                            .output = output,
                            .writer = .{
                                .buffer = options.write_buffer,
                                .vtable = &.{
                                    .drain = drain,
                                    .flush = flush,
                                },
                            },
                            .tls_version = tls_version,
                            .read_seq = switch (tls_version) {
                                .tls_1_3 => 0,
                                .tls_1_2 => read_seq,
                                else => unreachable,
                            },
                            .write_seq = switch (tls_version) {
                                .tls_1_3 => 0,
                                .tls_1_2 => write_seq,
                                else => unreachable,
                            },
                            .received_close_notify = false,
                            .allow_truncation_attacks = options.allow_truncation_attacks,
                            .application_cipher = app_cipher,
                            .ssl_key_log = options.ssl_key_log,
                            .alpn_protocol = alpn_selected, // zig-libs tlsclient: ALPN
                            .negotiated_group = negotiated_group,
                            .hello_retry_request = hrr_seen,
                            .cipher_suite = negotiated_suite,
                            .exporter = exporter,
                            .did_resume = psk_accepted,
                            .session_cache = options.session_cache,
                            .session_entry = session_entry,
                            .session_generation = session_generation,
                            .handshake_time_ms = now_ms,
                        };
                    },
                    else => return error.TlsUnexpectedMessage,
                }
                if (ctd.eof()) break;
                cleartext_fragment_start = ctd.idx;
            },
            else => return error.TlsUnexpectedMessage,
        }
        cleartext_fragment_start = 0;
        cleartext_fragment_end = 0;
    }
}

// ── zig-libs tlsclient: ClientHello helpers ──────────────────────────────

fn checkVersions(min: tls.ProtocolVersion, max: tls.ProtocolVersion) error{VersionsInvalid}!void {
    const ok = (min == .tls_1_2 or min == .tls_1_3) and (max == .tls_1_2 or max == .tls_1_3);
    if (!ok or @backingInt(min) > @backingInt(max)) return error.VersionsInvalid;
}

fn checkGroups(groups: []const tls.NamedGroup, shares: []const tls.NamedGroup) error{GroupsInvalid}!void {
    if (groups.len == 0 or groups.len > supported_groups.len) return error.GroupsInvalid;
    for (groups, 0..) |g, i| {
        if (!groupSupported(g)) return error.GroupsInvalid;
        if (mem.findScalar(tls.NamedGroup, groups[0..i], g) != null) return error.GroupsInvalid;
    }
    for (shares, 0..) |g, i| {
        if (mem.findScalar(tls.NamedGroup, groups, g) == null) return error.GroupsInvalid;
        if (mem.findScalar(tls.NamedGroup, shares[0..i], g) != null) return error.GroupsInvalid;
    }
}

/// supported_versions, newest first.
fn offeredVersions(buf: *[2]tls.ProtocolVersion, min: tls.ProtocolVersion, max: tls.ProtocolVersion) []const tls.ProtocolVersion {
    var n: usize = 0;
    if (max == .tls_1_3) {
        buf[n] = .tls_1_3;
        n += 1;
    }
    if (min == .tls_1_2) {
        buf[n] = .tls_1_2;
        n += 1;
    }
    return buf[0..n];
}

fn versionOffered(versions: []const tls.ProtocolVersion, v: tls.ProtocolVersion) bool {
    return mem.findScalar(tls.ProtocolVersion, versions, v) != null;
}

/// One handshake record holding `msg`. RFC 8446 §5.1: legacy_record_version
/// 0x0301 is allowed for the first ClientHello only; std uses it there.
fn writeHelloRecord(output: *Writer, record_version: tls.ProtocolVersion, msg: []const u8) Writer.Error!void {
    const header = [_]u8{@backingInt(tls.ContentType.handshake)} ++ int(u16, @backingInt(record_version));
    var len: [2]u8 = undefined;
    mem.writeInt(u16, &len, @intCast(msg.len), .big);
    var iovecs = [_][]const u8{ &header, &len, msg };
    try output.writeVecAll(&iovecs);
    try output.flush();
}

/// A fresh transcript for `suite` (std's ServerHello code, factored out so
/// a HelloRetryRequest can start it).
fn initHandshakeCipher(hc: *tls.HandshakeCipher, suite: tls.CipherSuite) error{TlsIllegalParameter}!void {
    switch (suite) {
        inline .AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
        .AEGIS_256_SHA512,
        .AEGIS_128L_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        => |tag| hc.* = @unionInit(tls.HandshakeCipher, @tagName(tag.with()), .{
            .transcript_hash = .init(.{}),
            .version = undefined,
        }),
        else => return error.TlsIllegalParameter,
    }
}

// ── zig-libs tlsclient: TLS 1.3 resumption helpers ───────────────────────

/// A cached ticket copied out for one handshake.
const ResumeOffer = struct {
    entry: *ClientSession,
    generation: u64,
    hash: HashKind,
    psk: [64]u8,
    ticket_buf: [session.max_ticket_len]u8 = undefined,
    ticket_len: u16,
    age: u32,

    fn ticket(o: *const ResumeOffer) []const u8 {
        return o.ticket_buf[0..o.ticket_len];
    }
    fn hashLen(o: *const ResumeOffer) usize {
        return switch (o.hash) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

fn hashKindOf(suite: tls.CipherSuite) HashKind {
    return switch (suite) {
        .AES_256_GCM_SHA384 => .sha384,
        .AEGIS_256_SHA512 => .sha512,
        else => .sha256,
    };
}

/// Write the PSK binder (RFC 8446 §4.2.11.2) into the last `H.digest_length`
/// bytes of `msg`: HMAC under the "res binder" finished key over `prefix`
/// (the transcript so far: empty, or message_hash + HelloRetryRequest)
/// continued with `msg` minus its binders list.
fn fillBinder(comptime H: type, msg: []u8, psk: *const [64]u8, prefix: *const H) void {
    const Hmac = crypto.auth.hmac.Hmac(H);
    const Hkdf = crypto.kdf.hkdf.Hkdf(Hmac);
    const n = H.digest_length;
    var t = prefix.*;
    t.update(msg[0 .. msg.len - (2 + 1 + n)]);
    const th = t.finalResult();
    var early: [n]u8 = undefined;
    defer crypto.secureZero(u8, &early);
    tlsresume.psk.earlySecret(Hkdf, &early, psk[0..n]);
    var empty: [n]u8 = undefined;
    H.hash("", &empty, .{});
    var bk: [n]u8 = undefined;
    defer crypto.secureZero(u8, &bk);
    tlsresume.psk.binderKey(Hkdf, &bk, &early, &empty);
    tlsresume.psk.computeBinder(Hkdf, Hmac, msg[msg.len - n ..][0..n], &bk, &th);
}

/// A resumed session's view: the certificates kept with the ticket.
fn copyKeptChain(ci: *ConnectionInfo, cache: *SessionCache, entry: *ClientSession, generation: u64) error{ConnectionInfoTooSmall}!void {
    cache.acquire();
    defer cache.release();
    if (entry.generation != generation) return; // taken by another connection meanwhile
    var buf: [session.max_chain_len][]const u8 = undefined;
    for (entry.chain(&buf)) |der| {
        if (ci.peer_certificates_len == verify.max_chain_len) break;
        ci.peer_certificates_buf[ci.peer_certificates_len] = try ci.keep(der);
        ci.peer_certificates_len += 1;
    }
}

/// Whether `e`, made under its own verification, may be resumed by a
/// connection verifying with `ca` (review F2, 2026-10-26).
fn resumableUnder(e: *const ClientSession, ca: @FieldType(Options, "ca")) bool {
    return ca == .no_verification or e.verification == verificationOf(ca);
}

test "resumableUnder: a session made without verification is not resumed under a bundle (Go's rule)" {
    var lock: std.Io.RwLock = .init;
    var bundle: Certificate.Bundle = .empty;
    const with_bundle: @FieldType(Options, "ca") = .{ .bundle = .{ .gpa = std.testing.allocator, .io = std.testing.io, .lock = &lock, .bundle = &bundle } };
    var e: ClientSession = .{};
    e.verification = .no_verification;
    try std.testing.expect(!resumableUnder(&e, with_bundle));
    try std.testing.expect(!resumableUnder(&e, .self_signed));
    try std.testing.expect(resumableUnder(&e, .no_verification));
    e.verification = .self_signed;
    try std.testing.expect(!resumableUnder(&e, with_bundle));
    try std.testing.expect(resumableUnder(&e, .self_signed));
    e.verification = .bundle;
    try std.testing.expect(resumableUnder(&e, with_bundle));
    try std.testing.expect(!resumableUnder(&e, .self_signed));
    try std.testing.expect(resumableUnder(&e, .no_verification));
}

fn verificationOf(ca: @FieldType(Options, "ca")) session.Verification {
    return switch (ca) {
        .no_verification => .no_verification,
        .self_signed => .self_signed,
        .bundle => .bundle,
    };
}

/// A NewSessionTicket (RFC 8446 §4.6.1) into the cache entry this
/// connection reserved, with its PSK derived; ignored without one, or when
/// the entry has been taken over since, or the ticket is unusable here.
fn storeTicket(c: *Client, msg: []const u8) void {
    const cache = c.session_cache orelse return;
    const entry = c.session_entry orelse return;
    var exts: [8]tlsresume.ticket.Extension = undefined;
    const t = tlsresume.ticket.NewSessionTicket.decode(msg, &exts) catch return;
    if (t.ticket_lifetime == 0 or t.ticket.len > session.max_ticket_len) return;
    cache.acquire();
    defer cache.release();
    if (entry.generation != c.session_generation) return;
    switch (entry.hash) {
        inline else => |k| {
            const H = HashOf(k);
            const Hkdf = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.Hmac(H));
            tlsresume.psk.derivePsk(Hkdf, H.digest_length, entry.psk[0..H.digest_length], entry.resumption_secret[0..H.digest_length], t.ticket_nonce);
        },
    }
    @memcpy(entry.ticket_buf[0..t.ticket.len], t.ticket);
    entry.ticket_len = @intCast(t.ticket.len);
    entry.ticket_age_add = t.ticket_age_add;
    entry.ticket_lifetime_s = @min(t.ticket_lifetime, session.max_lifetime_s);
    entry.received_ms = c.handshake_time_ms;
    entry.usable = true;
}

// ── zig-libs tlsclient: ALPN and client-certificate helpers ──────────────

/// The ALPN extension (type, length, protocol_name_list) for `protocols`,
/// or "" when there are none.
fn alpnExtension(buf: *[4 + 2 + max_alpn_len]u8, protocols: []const []const u8) error{AlpnProtocolsInvalid}![]const u8 {
    if (protocols.len == 0) return "";
    var n: usize = 6;
    for (protocols) |p| {
        if (p.len == 0 or p.len > 255 or n + 1 + p.len > buf.len) return error.AlpnProtocolsInvalid;
        buf[n] = @intCast(p.len);
        @memcpy(buf[n + 1 ..][0..p.len], p);
        n += 1 + p.len;
    }
    mem.writeInt(u16, buf[0..2], @backingInt(tls.ExtensionType.application_layer_protocol_negotiation), .big);
    mem.writeInt(u16, buf[2..4], @intCast(n - 4), .big);
    mem.writeInt(u16, buf[4..6], @intCast(n - 6), .big);
    return buf[0..n];
}

/// The ALPN choice in an EncryptedExtensions block (null: none, or none
/// offered -- then a server's answer is ignored, as std ignores it). The
/// extension twice is `TlsIllegalParameter` (RFC 8446 §4.2).
fn encryptedExtensionsAlpn(all_extd: *tls.Decoder, offered: []const []const u8) !?[]const u8 {
    var selected: ?[]const u8 = null;
    while (!all_extd.eof()) {
        try all_extd.ensure(4);
        const et = all_extd.decode(tls.ExtensionType);
        const ext_size = all_extd.decode(u16);
        const extd = try all_extd.sub(ext_size);
        if (et != .application_layer_protocol_negotiation or offered.len == 0) continue;
        if (selected != null) return error.TlsIllegalParameter;
        selected = try alpnSelected(offered, extd.rest());
    }
    return selected;
}

/// The server's ALPN answer (RFC 7301 §3.1: a protocol_name_list holding
/// exactly one name) resolved to the offered entry it names. Anything else
/// -- a list of zero or several names, trailing bytes, a name we did not
/// offer -- is `TlsIllegalParameter` (§3.2's illegal_parameter).
fn alpnSelected(offered: []const []const u8, ext: []const u8) error{TlsIllegalParameter}![]const u8 {
    if (ext.len < 3) return error.TlsIllegalParameter;
    const list_len = mem.readInt(u16, ext[0..2], .big);
    if (list_len != ext.len - 2) return error.TlsIllegalParameter;
    // An empty name cannot match: every offered one is 1..255 bytes.
    if (3 + @as(usize, ext[2]) != ext.len) return error.TlsIllegalParameter;
    const name = ext[3..];
    for (offered) |o| if (mem.eql(u8, o, name)) return o;
    return error.TlsIllegalParameter;
}

/// A CertificateRequest as received (TLS 1.3 §4.3.2 or TLS 1.2 RFC 5246
/// §7.4.4) and what this client answers with.
const CertRequest = struct {
    context: [255]u8 = undefined,
    context_len: u8 = 0,
    schemes: [max_schemes]tls.SignatureScheme = undefined,
    schemes_len: usize = 0,
    /// TLS 1.2 certificate_types: rsa_sign(1) / ecdsa_sign(64) listed.
    rsa_ok: bool = true,
    ecdsa_ok: bool = true,
    // The answer (`choose`): the credential and the scheme it signs with.
    auth: ?ClientAuth = null,
    scheme_ok: bool = false,
    scheme: tls.SignatureScheme = .ed25519,

    const max_schemes = 64;
    const max_cas = 64;

    fn offered(req: *const CertRequest) []const tls.SignatureScheme {
        return req.schemes[0..req.schemes_len];
    }

    /// Pick the credential (the callback's, else `client_auth`) and the
    /// first of the server's schemes it fits; no fit: an empty Certificate.
    fn choose(req: *CertRequest, options: *const Options, version: tls.ProtocolVersion, cas: []const []const u8) void {
        req.auth = if (options.client_auth_select) |sel| blk: {
            const info: CertificateRequestInfo = .{ .version = version, .signature_schemes = req.offered(), .certificate_authorities = cas };
            break :blk sel.select(sel.context, &info);
        } else options.client_auth;
        const auth = req.auth orelse return;
        if (auth.certificate_chain.len == 0) return;
        if (version == .tls_1_2) {
            const type_ok = switch (auth.key.*) {
                .rsa => req.rsa_ok,
                .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => req.ecdsa_ok,
                .ed25519 => false,
            };
            if (!type_ok) return;
        }
        for (req.offered()) |s| if (auth.key.fits(s, version)) {
            req.scheme = s;
            req.scheme_ok = true;
            return;
        };
    }
};

fn readSchemes(req: *CertRequest, d: *tls.Decoder) !void {
    try d.ensure(2);
    const list_len = d.decode(u16);
    if (list_len % 2 != 0 or list_len == 0) return error.TlsDecodeError;
    try d.ensure(list_len);
    var i: usize = 0;
    while (i < list_len) : (i += 2) {
        const sc = d.decode(tls.SignatureScheme);
        if (req.schemes_len == CertRequest.max_schemes) return error.TlsCertificateRequestTooLarge;
        req.schemes[req.schemes_len] = sc;
        req.schemes_len += 1;
    }
}

/// certificate_authorities: DistinguishedName<1..2^16-1> each, in a
/// u16-length list (RFC 8446 §4.2.4, RFC 5246 §7.4.4).
fn readCas(cas: *[CertRequest.max_cas][]const u8, d: *tls.Decoder) !usize {
    try d.ensure(2);
    const total = d.decode(u16);
    var ld = try d.sub(total);
    var n: usize = 0;
    while (!ld.eof()) {
        try ld.ensure(2);
        const len = ld.decode(u16);
        if (len == 0) return error.TlsDecodeError;
        try ld.ensure(len);
        if (n == CertRequest.max_cas) return error.TlsCertificateRequestTooLarge;
        cas[n] = ld.slice(len);
        n += 1;
    }
    return n;
}

/// A TLS 1.3 CertificateRequest (RFC 8446 §4.3.2): the context, the
/// signature_algorithms (mandatory, once) and certificate_authorities.
fn parseCertRequest(hsd: *tls.Decoder, cas: *[CertRequest.max_cas][]const u8, cas_len: *usize) !CertRequest {
    var req: CertRequest = .{};
    try hsd.ensure(1);
    req.context_len = hsd.decode(u8);
    try hsd.ensure(@as(usize, req.context_len) + 2);
    @memcpy(req.context[0..req.context_len], hsd.slice(req.context_len));
    const ext_len = hsd.decode(u16);
    var all_extd = try hsd.sub(ext_len);
    var seen = false;
    cas_len.* = 0;
    while (!all_extd.eof()) {
        try all_extd.ensure(4);
        const et = all_extd.decode(tls.ExtensionType);
        const size = all_extd.decode(u16);
        var extd = try all_extd.sub(size);
        switch (et) {
            .signature_algorithms => {
                if (seen) return error.TlsIllegalParameter;
                seen = true;
                try readSchemes(&req, &extd);
            },
            .certificate_authorities => cas_len.* = try readCas(cas, &extd),
            else => {},
        }
    }
    if (!seen) return error.TlsIllegalParameter;
    return req;
}

/// A TLS 1.2 CertificateRequest (RFC 5246 §7.4.4): certificate_types,
/// supported_signature_algorithms, certificate_authorities.
fn parseCertRequest12(hsd: *tls.Decoder, cas: *[CertRequest.max_cas][]const u8, cas_len: *usize) !CertRequest {
    var req: CertRequest = .{ .rsa_ok = false, .ecdsa_ok = false };
    try hsd.ensure(1);
    const types_len = hsd.decode(u8);
    if (types_len == 0) return error.TlsDecodeError;
    try hsd.ensure(types_len);
    for (hsd.slice(types_len)) |t| switch (t) {
        1 => req.rsa_ok = true, // rsa_sign
        64 => req.ecdsa_ok = true, // ecdsa_sign
        else => {},
    };
    try readSchemes(&req, hsd);
    cas_len.* = try readCas(cas, hsd);
    if (!hsd.eof()) return error.TlsDecodeError;
    return req;
}

/// The client's Certificate (and, when a scheme fits, a CertificateVerify)
/// into `buf`, each mixed into `transcript` as written. RFC 8446 §4.4.2.3:
/// with no acceptable certificate the client sends an empty Certificate and
/// no CertificateVerify -- the server then decides (openssl `-verify`
/// proceeds, `-Verify` aborts with certificate_required).
fn clientAuthMessages(buf: *[max_client_auth_len]u8, req: *const CertRequest, transcript: anytype, random: std.Random) ![]const u8 {
    var w: Writer = .fixed(buf);
    const send_chain = req.scheme_ok;
    const chain: []const []const u8 = if (send_chain) req.auth.?.certificate_chain else &.{};
    // Certificate (§4.4.2).
    var list_len: usize = 0;
    for (chain) |der| {
        if (der.len == 0) return error.ClientCertificateTooLarge;
        list_len += 3 + der.len + 2;
    }
    const cert_body = 1 + @as(usize, req.context_len) + 3 + list_len;
    if (4 + cert_body > buf.len) return error.ClientCertificateTooLarge;
    w.writeByte(@backingInt(tls.HandshakeType.certificate)) catch unreachable;
    w.writeInt(u24, @intCast(cert_body), .big) catch unreachable;
    w.writeByte(req.context_len) catch unreachable;
    w.writeAll(req.context[0..req.context_len]) catch unreachable;
    w.writeInt(u24, @intCast(list_len), .big) catch unreachable;
    for (chain) |der| {
        w.writeInt(u24, @intCast(der.len), .big) catch unreachable;
        w.writeAll(der) catch unreachable;
        w.writeInt(u16, 0, .big) catch unreachable; // no CertificateEntry extensions
    }
    transcript.update(w.buffered());
    if (!send_chain) return w.buffered();

    // CertificateVerify (§4.4.3): the signature covers 64 spaces, the
    // context string, a zero byte and the transcript hash through our
    // Certificate.
    const cv_start = w.end;
    const content = strRepeat(" ", 64) ++ "TLS 1.3, client CertificateVerify\x00";
    var msg: [content.len + 64]u8 = undefined;
    const th = transcript.peek();
    @memcpy(msg[0..content.len], content);
    @memcpy(msg[content.len..][0..th.len], &th);
    const signed = msg[0 .. content.len + th.len];
    var sig_buf: [max_signature_len]u8 = undefined;
    const sig = try signCertificateVerify(&sig_buf, req.auth.?.key, req.scheme, .{ .message = signed }, random);
    try writeCertificateVerify(&w, req.scheme, sig);
    transcript.update(w.buffered()[cv_start..]);
    return w.buffered();
}

fn writeCertificateVerify(w: *Writer, scheme: tls.SignatureScheme, sig: []const u8) error{ClientCertificateTooLarge}!void {
    if (w.buffer.len - w.end < 4 + 4 + sig.len) return error.ClientCertificateTooLarge;
    w.writeByte(@backingInt(tls.HandshakeType.certificate_verify)) catch unreachable;
    w.writeInt(u24, @intCast(4 + sig.len), .big) catch unreachable;
    w.writeInt(u16, @backingInt(scheme), .big) catch unreachable;
    w.writeInt(u16, @intCast(sig.len), .big) catch unreachable;
    w.writeAll(sig) catch unreachable;
}

/// TLS 1.2 client Certificate (RFC 5246 §7.4.6): the chain, or an empty
/// list when nothing fits.
fn clientCertificate12(buf: *[max_client_auth_len]u8, req: *const CertRequest) error{ClientCertificateTooLarge}![]const u8 {
    const chain: []const []const u8 = if (req.scheme_ok) req.auth.?.certificate_chain else &.{};
    var list_len: usize = 0;
    for (chain) |der| {
        if (der.len == 0) return error.ClientCertificateTooLarge;
        list_len += 3 + der.len;
    }
    if (4 + 3 + list_len > buf.len) return error.ClientCertificateTooLarge;
    var w: Writer = .fixed(buf);
    w.writeByte(@backingInt(tls.HandshakeType.certificate)) catch unreachable;
    w.writeInt(u24, @intCast(3 + list_len), .big) catch unreachable;
    w.writeInt(u24, @intCast(list_len), .big) catch unreachable;
    for (chain) |der| {
        w.writeInt(u24, @intCast(der.len), .big) catch unreachable;
        w.writeAll(der) catch unreachable;
    }
    return w.buffered();
}

/// Running SHA-2 hashes of the TLS 1.2 handshake messages, kept only when
/// client authentication is configured: the TLS 1.2 CertificateVerify signs
/// `handshake_messages` with its scheme's hash (RFC 5246 §7.4.8), which need
/// not be the suite's.
const Cv12Hashes = struct {
    s256: crypto.hash.sha2.Sha256 = .init(.{}),
    s384: crypto.hash.sha2.Sha384 = .init(.{}),
    s512: crypto.hash.sha2.Sha512 = .init(.{}),

    fn update(h: *Cv12Hashes, bytes: []const u8) void {
        h.s256.update(bytes);
        h.s384.update(bytes);
        h.s512.update(bytes);
    }

    /// The digest for `scheme`'s hash into `out`; its length.
    fn digest(h: *const Cv12Hashes, scheme: tls.SignatureScheme, out: *[64]u8) usize {
        switch (schemeHash(scheme)) {
            inline else => |k| {
                var c = @field(h, switch (k) {
                    .sha256 => "s256",
                    .sha384 => "s384",
                    .sha512 => "s512",
                });
                const d = c.finalResult();
                @memcpy(out[0..d.len], &d);
                return d.len;
            },
        }
    }
};

fn schemeHash(s: tls.SignatureScheme) HashKind {
    return switch (s) {
        .ecdsa_secp384r1_sha384, .rsa_pkcs1_sha384, .rsa_pss_rsae_sha384 => .sha384,
        .ecdsa_secp521r1_sha512, .rsa_pkcs1_sha512, .rsa_pss_rsae_sha512 => .sha512,
        else => .sha256,
    };
}

/// What a CertificateVerify signature covers: the TLS 1.3 content as a
/// message, or the TLS 1.2 handshake-messages hash already taken.
pub const SignInput = union(enum) {
    message: []const u8,
    digest: []const u8,
};

/// Sign with the client key in `scheme`. ECDSA is RFC 6979 deterministic (no
/// noise), DER-encoded as TLS wants; Ed25519 is RFC 8032; RSA-PSS draws its
/// salt (and the `rsa` module its blinding) from `random`. The body runs one
/// frame down and the stack it dirtied is zeroed after it: the
/// `secureZero`s below wipe this frame's copies, but std's signers leave the
/// key and the nonce in their own frames (2026-10-09 stack probe). `pub`
/// for `stackprobe_test.zig`.
pub fn signCertificateVerify(out: *[max_signature_len]u8, key: *const ClientAuth.PrivateKey, scheme: tls.SignatureScheme, input: SignInput, random: std.Random) error{ClientKeyInvalid}![]const u8 {
    return burn.run(burn.sign_burn, error{ClientKeyInvalid}![]const u8, signCertificateVerifyBody, .{ out, key, scheme, input, random });
}

fn signCertificateVerifyBody(out: *[max_signature_len]u8, key: *const ClientAuth.PrivateKey, scheme: tls.SignatureScheme, input: SignInput, random: std.Random) error{ClientKeyInvalid}![]const u8 {
    switch (key.*) {
        inline .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => |*raw, tag| switch (schemeHash(scheme)) {
            inline else => |hk| {
                const H = HashOf(hk);
                const E = if (tag == .ecdsa_secp256r1_sha256) crypto.sign.ecdsa.Ecdsa(crypto.ecc.P256, H) else p384.Ecdsa(H);
                var sk = E.SecretKey.fromBytes(raw.*) catch return error.ClientKeyInvalid;
                defer crypto.secureZero(u8, mem.asBytes(&sk));
                var kp = E.KeyPair.fromSecretKey(sk) catch return error.ClientKeyInvalid;
                defer crypto.secureZero(u8, mem.asBytes(&kp));
                const sig = switch (input) {
                    .message => |m| kp.sign(m, null),
                    .digest => |d| blk: {
                        if (d.len != H.digest_length) return error.ClientKeyInvalid;
                        break :blk kp.signPrehashed(d[0..H.digest_length].*, null);
                    },
                } catch return error.ClientKeyInvalid;
                var der: [E.Signature.der_encoded_length_max]u8 = undefined;
                const d = sig.toDer(&der);
                @memcpy(out[0..d.len], d);
                return out[0..d.len];
            },
        },
        .ed25519 => |*seed| {
            const m = switch (input) {
                .message => |m| m,
                .digest => return error.ClientKeyInvalid, // PureEdDSA signs messages
            };
            var kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed.*) catch return error.ClientKeyInvalid;
            defer crypto.secureZero(u8, mem.asBytes(&kp));
            const sig = (kp.sign(m, null) catch return error.ClientKeyInvalid).toBytes();
            @memcpy(out[0..64], &sig);
            return out[0..64];
        },
        .rsa => |kp| switch (schemeHash(scheme)) {
            inline else => |hk| {
                const H = HashOf(hk);
                const pss = scheme == .rsa_pss_rsae_sha256 or scheme == .rsa_pss_rsae_sha384 or scheme == .rsa_pss_rsae_sha512;
                const r = switch (input) {
                    .message => |m| if (pss)
                        rsa.signPss(&kp.secret_key, H, random, m, H.digest_length, out)
                    else
                        rsa.signPkcs1v15(&kp.secret_key, H, m, out),
                    .digest => |d| blk: {
                        if (d.len != H.digest_length) return error.ClientKeyInvalid;
                        break :blk if (pss)
                            rsa.signPssPrehashed(&kp.secret_key, H, random, d[0..H.digest_length], H.digest_length, out)
                        else
                            rsa.signPkcs1v15Prehashed(&kp.secret_key, H, d[0..H.digest_length], out);
                    },
                };
                return r catch error.ClientKeyInvalid;
            },
        },
    }
}

/// TLS 1.2 cleartext handshake records holding `msg`, fragmented at 2^14
/// bytes (RFC 5246 §6.2.1).
fn writePlainHandshake(output: *Writer, msg: []const u8) Writer.Error!void {
    var off: usize = 0;
    while (off < msg.len) {
        const n = @min(msg.len - off, tls.max_ciphertext_inner_record_len);
        const header = [_]u8{@backingInt(tls.ContentType.handshake)} ++ int(u16, @backingInt(tls.ProtocolVersion.tls_1_2));
        var len: [2]u8 = undefined;
        mem.writeInt(u16, &len, @intCast(n), .big);
        var vec = [_][]const u8{ &header, &len, msg[off..][0..n] };
        try output.writeVecAll(&vec);
        off += n;
    }
}

/// Encrypt the concatenated handshake `parts` into TLS 1.3 records of at
/// most 2^14 plaintext bytes each, sequence numbers from 0 (RFC 8446 §5.2).
fn writeHandshakeRecords(comptime P: type, output: *Writer, parts: []const []const u8, key: [P.AEAD.key_length]u8, iv: [P.AEAD.nonce_length]u8) Writer.Error!void {
    var all: [max_client_auth_len + 4 + 64]u8 = undefined;
    var n: usize = 0;
    for (parts) |part| {
        @memcpy(all[n..][0..part.len], part);
        n += part.len;
    }
    var seq: u64 = 0;
    var off: usize = 0;
    while (off < n) : (seq += 1) {
        const chunk = all[off..@min(n, off + tls.max_ciphertext_inner_record_len - 1)];
        off += chunk.len;
        var inner: [tls.max_ciphertext_inner_record_len]u8 = undefined;
        @memcpy(inner[0..chunk.len], chunk);
        inner[chunk.len] = @backingInt(tls.ContentType.handshake);
        const pt = inner[0 .. chunk.len + 1];
        var rec: [@as(usize, tls.record_header_len) + tls.max_ciphertext_inner_record_len + P.AEAD.tag_length]u8 = undefined;
        rec[0] = @backingInt(tls.ContentType.application_data);
        mem.writeInt(u16, rec[1..3], @backingInt(tls.ProtocolVersion.tls_1_2), .big);
        mem.writeInt(u16, rec[3..5], @intCast(pt.len + P.AEAD.tag_length), .big);
        const nonce = nonce: {
            const V = @Vector(P.AEAD.nonce_length, u8);
            const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
            const operand: V = pad ++ @as([8]u8, @bitCast(@byteSwap(seq)));
            break :nonce @as(V, iv) ^ operand;
        };
        P.AEAD.encrypt(rec[5..][0..pt.len], rec[5 + pt.len ..][0..P.AEAD.tag_length], pt, rec[0..5], nonce, key);
        try output.writeAll(rec[0 .. 5 + pt.len + P.AEAD.tag_length]);
    }
    crypto.secureZero(u8, all[0..n]);
}

/// zig-libs tlsclient: room in `output` for at least one full record. std's
/// `writableSliceGreedy` asserts the capacity after a rebase that cannot grow
/// the buffer (`defaultRebase`, e.g. a socket writer), so an `output` with a
/// buffer under `min_buffer_len` was a panic, UB in ReleaseFast; it is
/// `error.WriteFailed` here (`init` refuses it up front as BufferTooSmall).
fn outputSlice(output: *Writer) Writer.Error![]u8 {
    if (outputTooSmall(output)) return error.WriteFailed;
    return output.writableSliceGreedy(min_buffer_len);
}

/// An `output` whose buffer can never hold a full record: too small and not
/// grown by its rebase (a growing writer, `Writer.Allocating`, is fine).
fn outputTooSmall(output: *const Writer) bool {
    return output.buffer.len < min_buffer_len and output.vtable.rebase == &Writer.defaultRebase;
}

fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try outputSlice(output);
    var ciphertext_end: usize = 0;
    var total_clear: usize = 0;
    done: {
        {
            const buf = w.buffered();
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        for (data[0 .. data.len - 1]) |buf| {
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
        const buf = data[data.len - 1];
        for (0..splat) |_| {
            const prepared = prepareCiphertextRecord(c, ciphertext_buf[ciphertext_end..], buf, .application_data);
            total_clear += prepared.cleartext_len;
            ciphertext_end += prepared.ciphertext_end;
            if (prepared.cleartext_len < buf.len) break :done;
        }
    }
    output.advance(ciphertext_end);
    return w.consume(total_clear);
}

fn flush(w: *Writer) Writer.Error!void {
    // zig-libs tlsclient: every buffered byte, record by record. std sealed
    // what fit `output`'s free space once and then cleared the buffer, so a
    // `write_buffer` larger than that lost the rest without an error (no-panic
    // sweep 2026-10-28).
    while (w.end != 0) _ = try drain(w, &.{""}, 1);
}

/// Sends a `close_notify` alert, which is necessary for the server to
/// distinguish between a properly finished TLS session, or a truncation
/// attack.
pub fn end(c: *Client) Writer.Error!void {
    try flush(&c.writer);
    const output = c.output;
    const ciphertext_buf = try outputSlice(output);
    const prepared = prepareCiphertextRecord(c, ciphertext_buf, &tls.close_notify_alert, .alert);
    output.advance(prepared.ciphertext_end);
}

fn prepareCiphertextRecord(
    c: *Client,
    ciphertext_buf: []u8,
    bytes: []const u8,
    inner_content_type: tls.ContentType,
) struct {
    ciphertext_end: usize,
    cleartext_len: usize,
} {
    // Due to the trailing inner content type byte in the ciphertext, we need
    // an additional buffer for storing the cleartext into before encrypting.
    var cleartext_buf: [max_ciphertext_len]u8 = undefined;
    var ciphertext_end: usize = 0;
    var bytes_i: usize = 0;
    switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.AEAD.tag_length + 1;
                while (true) {
                    const encrypted_content_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    );
                    if (encrypted_content_len == 0) return .{
                        .ciphertext_end = ciphertext_end,
                        .cleartext_len = bytes_i,
                    };
                    // zig-libs tlsclient: a due KeyUpdate goes first, under
                    // the current key; the record after it uses the next.
                    if (c.write_seq >= key_update_after) c.key_update_pending = true;
                    if (c.key_update_pending) {
                        const ku_len = tls.record_header_len + 4 + 1 + 1 + P.AEAD.tag_length;
                        if (ciphertext_buf.len - ciphertext_end < ku_len + overhead_len + 1) return .{
                            .ciphertext_end = ciphertext_end,
                            .cleartext_len = bytes_i,
                        };
                        ciphertext_end += sealRecord13(P, pv, c.write_seq, ciphertext_buf[ciphertext_end..], &.{ @backingInt(tls.HandshakeType.key_update), 0, 0, 1, @backingInt(tls.KeyUpdateRequest.update_not_requested) }, .handshake);
                        const client_secret = hkdfExpandLabel(P.Hkdf, pv.client_secret, "traffic upd", "", P.Hash.digest_length);
                        if (c.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                            .counter = key_log.clientCounter(),
                            .client_random = &key_log.client_random,
                        }, .{
                            .CLIENT_TRAFFIC_SECRET = &client_secret,
                        });
                        pv.client_secret = client_secret;
                        pv.client_key = hkdfExpandLabel(P.Hkdf, client_secret, "key", "", P.AEAD.key_length);
                        pv.client_iv = hkdfExpandLabel(P.Hkdf, client_secret, "iv", "", P.AEAD.nonce_length);
                        c.write_seq = 0;
                        c.key_update_pending = false;
                        continue; // re-size the content against the space left
                    }

                    @memcpy(cleartext_buf[0..encrypted_content_len], bytes[bytes_i..][0..encrypted_content_len]);
                    cleartext_buf[encrypted_content_len] = @backingInt(inner_content_type);
                    bytes_i += encrypted_content_len;
                    const ciphertext_len = encrypted_content_len + 1;
                    const cleartext = cleartext_buf[0..ciphertext_len];

                    const ad = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ad.* = .{@backingInt(tls.ContentType.application_data)} ++
                        int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, ciphertext_len + P.AEAD.tag_length);
                    ciphertext_end += ad.len;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..ciphertext_len];
                    ciphertext_end += ciphertext_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                    ciphertext_end += auth_tag.len;
                    const nonce = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                        const operand: V = pad ++ mem.toBytes(big(c.write_seq));
                        break :nonce @as(V, pv.client_iv) ^ operand;
                    };
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_key);
                    c.write_seq += 1; // zig-libs tlsclient: a KeyUpdate is due at key_update_after (above)
                }
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                const overhead_len = tls.record_header_len + P.record_iv_length + P.mac_length;
                while (true) {
                    const message_len: u16 = @min(
                        bytes.len - bytes_i,
                        tls.max_ciphertext_inner_record_len,
                        ciphertext_buf.len -| (overhead_len + ciphertext_end),
                    );
                    if (message_len == 0) return .{
                        .ciphertext_end = ciphertext_end,
                        .cleartext_len = bytes_i,
                    };

                    @memcpy(cleartext_buf[0..message_len], bytes[bytes_i..][0..message_len]);
                    bytes_i += message_len;
                    const cleartext = cleartext_buf[0..message_len];

                    const record_header = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ciphertext_end += tls.record_header_len;
                    record_header.* = .{@backingInt(inner_content_type)} ++
                        int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, P.record_iv_length + message_len + P.mac_length);
                    const ad = mem.toBytes(big(c.write_seq)) ++ record_header[0 .. 1 + 2] ++ int(u16, message_len);
                    const record_iv = ciphertext_buf[ciphertext_end..][0..P.record_iv_length];
                    ciphertext_end += P.record_iv_length;
                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                        const operand: V = pad ++ @as([8]u8, @bitCast(@byteSwap(c.write_seq)));
                        break :nonce @as(V, pv.client_write_IV ++ pv.client_salt) ^ operand;
                    };
                    record_iv.* = nonce[P.fixed_iv_length..].*;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..message_len];
                    ciphertext_end += message_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.mac_length];
                    ciphertext_end += P.mac_length;
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_write_key);
                    c.write_seq += 1; // TLS 1.2 has no key update; 2^64 records are out of reach
                }
            },
            else => unreachable,
        },
    }
}

/// zig-libs tlsclient: one TLS 1.3 record holding `content` of type `ct`,
/// sealed with sequence number `seq`; returns the bytes written.
fn sealRecord13(comptime P: type, pv: anytype, seq: u64, out: []u8, content: []const u8, ct: tls.ContentType) usize {
    var clear: [16]u8 = undefined;
    @memcpy(clear[0..content.len], content);
    clear[content.len] = @backingInt(ct);
    const clen = content.len + 1;
    const ad = out[0..tls.record_header_len];
    ad.* = .{@backingInt(tls.ContentType.application_data)} ++
        int(u16, @backingInt(tls.ProtocolVersion.tls_1_2)) ++
        int(u16, @intCast(clen + P.AEAD.tag_length));
    const nonce = nonce: {
        const V = @Vector(P.AEAD.nonce_length, u8);
        const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
        const operand: V = pad ++ mem.toBytes(big(seq));
        break :nonce @as(V, pv.client_iv) ^ operand;
    };
    P.AEAD.encrypt(out[ad.len..][0..clen], out[ad.len + clen ..][0..P.AEAD.tag_length], clear[0..clen], ad, nonce, pv.client_key);
    return ad.len + clen + P.AEAD.tag_length;
}

pub fn eof(c: Client) bool {
    return c.received_close_notify;
}

fn stream(r: *Reader, w: *Writer, limit: std.Io.Limit) Reader.StreamError!usize {
    // This function writes exclusively to the buffer.
    _ = w;
    _ = limit;
    const c: *Client = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readVec(r: *Reader, data: [][]u8) Reader.Error!usize {
    // This function writes exclusively to the buffer.
    _ = data;
    const c: *Client = @alignCast(@fieldParentPtr("reader", r));
    return readIndirect(c);
}

fn readIndirect(c: *Client) Reader.Error!usize {
    const r = &c.reader;
    if (c.eof()) return error.EndOfStream;
    const input = c.input;
    // If at least one full encrypted record is not buffered, read once.
    const record_header = input.peek(tls.record_header_len) catch |err| switch (err) {
        error.EndOfStream => {
            // This is either a truncation attack, a bug in the server, or an
            // intentional omission of the close_notify message due to truncation
            // detection handled above the TLS layer.
            if (c.allow_truncation_attacks) {
                c.received_close_notify = true;
                return error.EndOfStream;
            } else {
                return failRead(c, error.TlsConnectionTruncated);
            }
        },
        error.ReadFailed => return error.ReadFailed,
    };
    const ct: tls.ContentType = @fromBackingInt(@intCast(record_header[0]));
    const legacy_version = mem.readInt(u16, record_header[1..][0..2], .big);
    _ = legacy_version;
    const record_len = mem.readInt(u16, record_header[3..][0..2], .big);
    if (record_len > max_ciphertext_len) return failRead(c, error.TlsRecordOverflow);
    const record_end = 5 + record_len;
    if (record_end > input.buffered().len) {
        input.fillMore() catch |err| switch (err) {
            error.EndOfStream => return failRead(c, error.TlsConnectionTruncated),
            error.ReadFailed => return error.ReadFailed,
        };
        if (record_end > input.buffered().len) return 0;
    }

    const cleartext_len, const inner_ct: tls.ContentType = cleartext: switch (c.application_cipher) {
        inline else => |*p| switch (c.tls_version) {
            .tls_1_3 => {
                const pv = &p.tls_1_3;
                const P = @TypeOf(p.*);
                // zig-libs tlsclient: std subtracted unchecked -- a record
                // shorter than the tag underflowed (TLSCLIENT_FUZZ, 2026-10-13).
                if (record_len < P.AEAD.tag_length) return failRead(c, error.TlsBadLength);
                const ad = input.take(tls.record_header_len) catch unreachable; // already peeked
                const ciphertext_len = record_len - P.AEAD.tag_length;
                const ciphertext = input.take(ciphertext_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.AEAD.tag_length) catch unreachable).*; // already peeked
                const nonce = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                    const operand: V = pad ++ mem.toBytes(big(c.read_seq));
                    break :nonce @as(V, pv.server_iv) ^ operand;
                };
                if (!rebase(r, ciphertext.len)) return failRead(c, error.TlsRecordOverflow);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_key) catch
                    return failRead(c, error.TlsBadRecordMac);
                // TODO use scalar, non-slice version
                const msg = mem.trimEnd(u8, cleartext, "\x00");
                // zig-libs tlsclient: RFC 8446 §5.4 -- no non-zero octet (no
                // content type) is unexpected_message; std indexed msg[-1].
                if (msg.len == 0) return failRead(c, error.TlsUnexpectedMessage);
                break :cleartext .{ msg.len - 1, @fromBackingInt(@intCast(msg[msg.len - 1])) };
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
                // zig-libs tlsclient: checked, as the handshake path already was.
                if (record_len < P.record_iv_length + P.mac_length) return failRead(c, error.TlsBadLength);
                const message_len: u16 = record_len - P.record_iv_length - P.mac_length;
                const ad_header = input.take(tls.record_header_len) catch unreachable; // already peeked
                const ad = mem.toBytes(big(c.read_seq)) ++
                    ad_header[0 .. 1 + 2] ++
                    mem.toBytes(big(message_len));
                const record_iv = (input.takeArray(P.record_iv_length) catch unreachable).*; // already peeked
                const masked_read_seq = c.read_seq &
                    comptime std.math.shl(u64, std.math.maxInt(u64), 8 * P.record_iv_length);
                const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
                    const operand: V = pad ++ @as([8]u8, @bitCast(@byteSwap(masked_read_seq)));
                    break :nonce @as(V, pv.server_write_IV ++ record_iv) ^ operand;
                };
                const ciphertext = input.take(message_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.mac_length) catch unreachable).*; // already peeked
                if (!rebase(r, ciphertext.len)) return failRead(c, error.TlsRecordOverflow);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_write_key) catch
                    return failRead(c, error.TlsBadRecordMac);
                break :cleartext .{ cleartext.len, ct };
            },
            else => unreachable,
        },
    };
    const cleartext = r.buffer[r.end..][0..cleartext_len];
    c.read_seq = std.math.add(u64, c.read_seq, 1) catch return failRead(c, error.TlsSequenceOverflow);
    switch (inner_ct) {
        .alert => {
            if (cleartext.len != 2) return failRead(c, error.TlsDecodeError);
            const alert: tls.Alert = .{
                .level = @fromBackingInt(@intCast(cleartext[0])),
                .description = @fromBackingInt(@intCast(cleartext[1])),
            };
            switch (alert.description) {
                .close_notify => {
                    c.received_close_notify = true;
                    return 0;
                },
                .user_canceled => {
                    // TODO: handle server-side closures
                    return failRead(c, error.TlsUnexpectedMessage);
                },
                else => {
                    c.alert = alert;
                    return failRead(c, error.TlsAlert);
                },
            }
        },
        .handshake => {
            var ct_i: usize = 0;
            while (true) {
                // zig-libs tlsclient: a handshake message needs its 4-octet
                // header; std indexed an empty or short fragment unchecked
                // (RFC 8446 §6.2: decode_error).
                if (cleartext.len - ct_i < 4) return failRead(c, error.TlsDecodeError);
                const handshake_type: tls.HandshakeType = @fromBackingInt(@intCast(cleartext[ct_i]));
                ct_i += 1;
                const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
                ct_i += 3;
                const next_handshake_i = ct_i + handshake_len;
                if (next_handshake_i > cleartext.len) return failRead(c, error.TlsBadLength);
                const handshake = cleartext[ct_i..next_handshake_i];
                switch (handshake_type) {
                    // zig-libs tlsclient: kept for resumption when a cache is
                    // configured (std ignored them).
                    .new_session_ticket => c.storeTicket(handshake),
                    .key_update => {
                        // zig-libs tlsclient: RFC 8446 §4.6.3 -- KeyUpdate exists in
                        // TLS 1.3 only (std touched the inactive `tls_1_3` union field
                        // on a 1.2 connection: unexpected_message) and its body is
                        // exactly one octet (decode_error; std 0.17 has this check).
                        // Both before any key or sequence number is switched.
                        if (c.tls_version != .tls_1_3) return failRead(c, error.TlsUnexpectedMessage);
                        if (handshake.len != 1) return failRead(c, error.TlsDecodeError);
                        // zig-libs tlsclient: RFC 8446 §5.1 -- handshake messages
                        // MUST NOT span a key change, so a KeyUpdate ends its
                        // record (unexpected_message; Go refuses it too). It
                        // also bounds the work: a 16 KiB record held ~3,270
                        // KeyUpdates, three HKDF expansions each (sweep F8).
                        if (next_handshake_i != cleartext.len) return failRead(c, error.TlsUnexpectedMessage);
                        switch (c.application_cipher) {
                            inline else => |*p| {
                                const pv = &p.tls_1_3;
                                const P = @TypeOf(p.*);
                                const server_secret = hkdfExpandLabel(P.Hkdf, pv.server_secret, "traffic upd", "", P.Hash.digest_length);
                                if (c.ssl_key_log) |key_log| logSecrets(key_log.writer, .{
                                    .counter = key_log.serverCounter(),
                                    .client_random = &key_log.client_random,
                                }, .{
                                    .SERVER_TRAFFIC_SECRET = &server_secret,
                                });
                                pv.server_secret = server_secret;
                                pv.server_key = hkdfExpandLabel(P.Hkdf, server_secret, "key", "", P.AEAD.key_length);
                                pv.server_iv = hkdfExpandLabel(P.Hkdf, server_secret, "iv", "", P.AEAD.nonce_length);
                            },
                        }
                        c.read_seq = 0;

                        switch (@as(tls.KeyUpdateRequest, @fromBackingInt(@intCast(handshake[0])))) {
                            // zig-libs tlsclient: RFC 8446 §4.6.3 -- answer with a
                            // KeyUpdate of our own before our next record, and
                            // switch keys only then. std switched at once and sent
                            // nothing, so the server kept our old key and refused
                            // our next record (bad_record_mac).
                            .update_requested => c.key_update_pending = true,
                            .update_not_requested => {},
                            _ => return failRead(c, error.TlsIllegalParameter),
                        }
                    },
                    else => return failRead(c, error.TlsUnexpectedMessage),
                }
                ct_i = next_handshake_i;
                if (ct_i >= cleartext.len) break;
            }
            return 0;
        },
        .application_data => {
            r.end += cleartext.len;
            return 0;
        },
        else => return failRead(c, error.TlsUnexpectedMessage),
    }
}

/// Room for `capacity` octets after the plaintext the caller still has
/// buffered. zig-libs tlsclient: false when there is none, and the caller
/// fails the read (record_overflow). std asserted it: a `peek`/`fill` of
/// more than is buffered, with over `min_buffer_len - capacity` octets still
/// buffered, met by a full-size record, panicked in safe builds and wrote
/// the plaintext past `read_buffer` in ReleaseFast (audit 2026-10-19).
fn rebase(r: *Reader, capacity: usize) bool {
    if (r.buffer.len - r.end >= capacity) return true;
    const data = r.buffer[r.seek..r.end];
    if (r.buffer.len - data.len < capacity) return false;
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    return true;
}

fn failRead(c: *Client, err: ReadError) error{ReadFailed} {
    c.read_err = err;
    return error.ReadFailed;
}

fn logSecrets(w: *Writer, context: anytype, secrets: anytype) void {
    inline for (@typeInfo(@TypeOf(secrets)).@"struct".field_names) |field_name| w.print("{s}" ++
        (if (@hasField(@TypeOf(context), "counter")) "_{d}" else "") ++ " {x} {x}\n", .{field_name} ++
        (if (@hasField(@TypeOf(context), "counter")) .{context.counter} else .{}) ++ .{
        context.client_random,
        @field(secrets, field_name),
    }) catch {};
}

fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

/// zig-libs tlsclient: the groups this client can do ECDHE/KEM with, and Go's
/// default preferences for them (Go `CurvePreferences`): every group listed,
/// key shares for the two Go sends; the others are reached through a
/// HelloRetryRequest.
pub const supported_groups = [_]tls.NamedGroup{ .x25519_ml_kem768, .x25519, .secp256r1, .secp384r1, .secp521r1 };
pub const default_groups = supported_groups;
pub const default_key_share_groups = [_]tls.NamedGroup{ .x25519_ml_kem768, .x25519 };
/// std's ClientHello shape: these groups, a share for each.
pub const std_groups = [_]tls.NamedGroup{ .x25519_ml_kem768, .secp256r1, .secp384r1, .x25519 };

fn groupSupported(g: tls.NamedGroup) bool {
    return mem.findScalar(tls.NamedGroup, &supported_groups, g) != null;
}

const KeyShare = struct {
    ml_kem768_kp: crypto.kem.ml_kem.MLKem768.KeyPair,
    secp256r1_kp: crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    secp384r1_kp: p384.EcdsaP384Sha384.KeyPair,
    secp521r1_kp: p521.EcdsaP521Sha512.KeyPair,
    /// zig-libs tlsclient: `ct25519`'s X25519 (std's bytes and shape): the
    /// public key from a fixed-base comb, the shared secret on a MULX/ADX
    /// ladder -- std's two Montgomery ladders were ~18 % of the client's CPU.
    x25519_kp: ct25519.X25519.KeyPair,
    /// zig-libs tlsclient: each share's wire encoding, made once at
    /// generation. The ClientHello (and a TLS 1.2 ClientKeyExchange) used to
    /// re-encode the NIST keys, a field inversion each -- on std's slow P-256
    /// `divstep` for P-256.
    hybrid_pub: [crypto.kem.ml_kem.MLKem768.PublicKey.encoded_length + crypto.dh.X25519.public_length]u8,
    secp256r1_sec1: [65]u8,
    secp384r1_sec1: [97]u8,
    secp521r1_sec1: [133]u8,
    /// zig-libs tlsclient: which key pairs exist. A pair is generated when a
    /// share is offered or a server picks its group (HelloRetryRequest, TLS
    /// 1.2 ServerKeyExchange), so a handshake pays only for what it uses.
    have_ml_kem: bool = false,
    have_x25519: bool = false,
    have_p256: bool = false,
    have_p384: bool = false,
    have_p521: bool = false,
    /// `Options.entropy[64..240]`; read only during `init`.
    seed: *const [176]u8,
    sk_buf: [sk_max_len]u8,
    sk_len: std.math.IntFittingRange(0, sk_max_len),

    const sk_max_len = @max(
        crypto.dh.X25519.shared_length + crypto.kem.ml_kem.MLKem768.shared_length,
        crypto.ecc.P256.scalar.encoded_length,
        crypto.ecc.P384.scalar.encoded_length,
        66, // P-521 x
        crypto.dh.X25519.shared_length,
    );

    fn init(seed: *const [176]u8) KeyShare {
        return .{
            .ml_kem768_kp = undefined,
            .secp256r1_kp = undefined,
            .secp384r1_kp = undefined,
            .secp521r1_kp = undefined,
            .x25519_kp = undefined,
            .hybrid_pub = undefined,
            .secp256r1_sec1 = undefined,
            .secp384r1_sec1 = undefined,
            .secp521r1_sec1 = undefined,
            .seed = seed,
            .sk_buf = undefined,
            .sk_len = 0,
        };
    }

    /// Generate the key pair(s) `group` needs, once. The seeds are std's
    /// (ML-KEM 0..64, P-256 64..96, P-384 96..144, X25519 144..176), so a
    /// std-shaped hello carries std's keys; P-521, which std lacks, takes an
    /// HKDF expansion of the whole seed.
    fn ensure(ks: *KeyShare, group: tls.NamedGroup) error{ IdentityElement, TlsIllegalParameter }!void {
        switch (group) {
            .x25519_ml_kem768 => {
                try ks.ensure(.x25519);
                if (ks.have_ml_kem) return;
                ks.ml_kem768_kp = try .generateDeterministic(ks.seed[0..64].*);
                ks.hybrid_pub = ks.ml_kem768_kp.public_key.toBytes() ++ ks.x25519_kp.public_key;
                ks.have_ml_kem = true;
            },
            .x25519 => if (!ks.have_x25519) {
                try ct25519.X25519.KeyPair.generateDeterministicInto(&ks.x25519_kp, ks.seed[144..176]);
                ks.have_x25519 = true;
            },
            // zig-libs tlsclient: std's key pairs, byte for byte, with the
            // public keys from fixed-base combs (keygen.zig: p256's, p384's) —
            // std's `basePoint.mul` for these two was ~2/3 of the client's CPU.
            .secp256r1 => if (!ks.have_p256) {
                ks.secp256r1_kp = try keygen.keyPairP256(ks.seed[64..96].*, &ks.secp256r1_sec1);
                ks.have_p256 = true;
            },
            .secp384r1 => if (!ks.have_p384) {
                ks.secp384r1_kp = try keygen.keyPairP384(ks.seed[96..144].*);
                ks.secp384r1_sec1 = ks.secp384r1_kp.public_key.toUncompressedSec1();
                ks.have_p384 = true;
            },
            .secp521r1 => if (!ks.have_p521) {
                const Hkdf = crypto.kdf.hkdf.HkdfSha512;
                var prk = Hkdf.extract("zig-libs tlsclient P-521 key share", ks.seed);
                defer crypto.secureZero(u8, &prk);
                var s: [p521.EcdsaP521Sha512.KeyPair.seed_length]u8 = undefined;
                defer crypto.secureZero(u8, &s);
                Hkdf.expand(&s, "", prk);
                p521.EcdsaP521Sha512.KeyPair.generateDeterministicInto(&ks.secp521r1_kp, &s) catch return error.IdentityElement;
                ks.secp521r1_sec1 = ks.secp521r1_kp.public_key.toUncompressedSec1();
                ks.have_p521 = true;
            },
            else => return error.TlsIllegalParameter,
        }
    }

    fn has(ks: *const KeyShare, group: tls.NamedGroup) bool {
        return switch (group) {
            .x25519_ml_kem768 => ks.have_ml_kem,
            .x25519 => ks.have_x25519,
            .secp256r1 => ks.have_p256,
            .secp384r1 => ks.have_p384,
            .secp521r1 => ks.have_p521,
            else => false,
        };
    }

    /// The key_share / ClientKeyExchange bytes of a generated group.
    fn publicKey(ks: *const KeyShare, group: tls.NamedGroup) []const u8 {
        assert(ks.has(group));
        return switch (group) {
            .x25519_ml_kem768 => &ks.hybrid_pub,
            .x25519 => &ks.x25519_kp.public_key,
            .secp256r1 => &ks.secp256r1_sec1,
            .secp384r1 => &ks.secp384r1_sec1,
            .secp521r1 => &ks.secp521r1_sec1,
            else => unreachable,
        };
    }

    fn exchange(
        ks: *KeyShare,
        named_group: tls.NamedGroup,
        server_pub_key: []const u8,
    ) error{ TlsIllegalParameter, TlsDecryptFailure }!void {
        // zig-libs tlsclient: a group we hold no key for (no share offered,
        // none generated) is the server's error.
        if (!ks.has(named_group)) return error.TlsIllegalParameter;
        switch (named_group) {
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = ks.ml_kem768_kp.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = ct25519.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(ks.sk_buf[0..hsk.len], &hsk);
                @memcpy(ks.sk_buf[hsk.len..][0..xsk.len], &xsk);
                ks.sk_len = hsk.len + xsk.len;
            },
            .secp256r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                // zig-libs tlsclient: `mul`, not std's `mulPublic` — that one is
                // variable-time ("for a *PUBLIC* scalar") and this scalar is our
                // ephemeral ECDHE secret.
                const mul = pk.p.mul(ks.secp256r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            .secp384r1 => {
                // zig-libs tlsclient: the `p384` module's ECDH — constant time
                // in our ephemeral secret, burned, shared x into `sk_buf`
                // directly. Refuses what std's `fromSec1` + `mul` refused (an
                // off-curve or identity point, an identity product).
                p384.ecdhInto(ks.sk_buf[0..48], &ks.secp384r1_kp.secret_key.bytes, server_pub_key) catch
                    return error.TlsDecryptFailure;
                ks.sk_len = 48;
            },
            .secp521r1 => {
                // zig-libs tlsclient: P-521 (std has none) through `p521`.
                p521.ecdhInto(ks.sk_buf[0..66], &ks.secp521r1_kp.secret_key.bytes, server_pub_key) catch
                    return error.TlsDecryptFailure;
                ks.sk_len = 66;
            },
            .x25519 => {
                const ksl = crypto.dh.X25519.public_length;
                if (server_pub_key.len != ksl) return error.TlsIllegalParameter;
                const sk = ct25519.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[0..ksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            else => return error.TlsIllegalParameter,
        }
    }

    fn getSharedSecret(ks: *const KeyShare) ?[]const u8 {
        return if (ks.sk_len > 0) ks.sk_buf[0..ks.sk_len] else null;
    }
};

fn SchemeEcdsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ecdsa_secp256r1_sha256 => crypto.sign.ecdsa.EcdsaP256Sha256,
        .ecdsa_secp384r1_sha384 => crypto.sign.ecdsa.EcdsaP384Sha384,
        else => @compileError("bad scheme"),
    };
}

fn SchemeRsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
        .rsa_pkcs1_sha1,
        => Certificate.rsa.PKCS1v1_5Signature,
        .rsa_pss_rsae_sha256,
        .rsa_pss_rsae_sha384,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha256,
        .rsa_pss_pss_sha384,
        .rsa_pss_pss_sha512,
        => Certificate.rsa.PSSSignature,
        else => @compileError("bad scheme"),
    };
}

fn SchemeEddsa(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .ed25519 => crypto.sign.Ed25519,
        else => @compileError("bad scheme"),
    };
}

fn SchemeHash(comptime scheme: tls.SignatureScheme) type {
    return switch (scheme) {
        .rsa_pkcs1_sha256,
        .ecdsa_secp256r1_sha256,
        .rsa_pss_rsae_sha256,
        .rsa_pss_pss_sha256,
        => crypto.hash.sha2.Sha256,
        .rsa_pkcs1_sha384,
        .ecdsa_secp384r1_sha384,
        .rsa_pss_rsae_sha384,
        .rsa_pss_pss_sha384,
        => crypto.hash.sha2.Sha384,
        .rsa_pkcs1_sha512,
        .ecdsa_secp521r1_sha512,
        .rsa_pss_rsae_sha512,
        .rsa_pss_pss_sha512,
        => crypto.hash.sha2.Sha512,
        .rsa_pkcs1_sha1,
        .ecdsa_sha1,
        => crypto.hash.Sha1,
        else => @compileError("bad scheme"),
    };
}

/// The curve of an ECDSA server key, by its SEC1 encoding's length
/// (uncompressed or compressed); the three TLS curves differ in all four.
const EcCurve = enum {
    p256,
    p384,
    p521,

    fn ofSec1(sec1: []const u8) ?EcCurve {
        return switch (sec1.len) {
            65, 33 => .p256,
            97, 49 => .p384,
            133, 67 => .p521,
            else => null,
        };
    }

    fn ofScheme(comptime scheme: tls.SignatureScheme) EcCurve {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256 => .p256,
            .ecdsa_secp384r1_sha384 => .p384,
            .ecdsa_secp521r1_sha512 => .p521,
            else => @compileError("bad scheme"),
        };
    }
};

const CertificatePublicKey = struct {
    algo: Certificate.AlgorithmCategory,
    buf: [600]u8,
    len: u16,

    fn init(
        cert_pub_key: *CertificatePublicKey,
        algo: Certificate.AlgorithmCategory,
        pub_key: []const u8,
    ) error{CertificatePublicKeyInvalid}!void {
        if (pub_key.len > cert_pub_key.buf.len) return error.CertificatePublicKeyInvalid;
        cert_pub_key.algo = algo;
        @memcpy(cert_pub_key.buf[0..pub_key.len], pub_key);
        cert_pub_key.len = @intCast(pub_key.len);
    }

    const VerifyError = error{ TlsDecodeError, TlsBadSignatureScheme, InvalidEncoding } ||
        // ecdsa
        crypto.errors.EncodingError ||
        crypto.errors.NotSquareError ||
        crypto.errors.NonCanonicalError ||
        SchemeEcdsa(.ecdsa_secp256r1_sha256).Signature.VerifyError ||
        SchemeEcdsa(.ecdsa_secp384r1_sha384).Signature.VerifyError ||
        p384.Ecdsa(crypto.hash.sha2.Sha512).Signature.VerifyError ||
        p521.Ecdsa(crypto.hash.sha2.Sha512).Signature.VerifyError ||
        // rsa
        error{TlsBadRsaSignatureBitCount} ||
        Certificate.rsa.PublicKey.ParseDerError ||
        Certificate.rsa.PublicKey.FromBytesError ||
        Certificate.rsa.PSSSignature.VerifyError ||
        Certificate.rsa.PKCS1v1_5Signature.VerifyError ||
        // eddsa
        SchemeEddsa(.ed25519).Signature.VerifyError;

    /// The longest signed content `verifySignature` accepts: TLS 1.2's two
    /// randoms plus ECDHE params with a 255-byte point (4 + 255) is 323.
    const max_signed_len = 512;

    fn verifySignature(
        cert_pub_key: *const CertificatePublicKey,
        version: tls.ProtocolVersion,
        sigd: *tls.Decoder,
        msg: []const []const u8,
    ) VerifyError!void {
        const pub_key = cert_pub_key.buf[0..cert_pub_key.len];

        try sigd.ensure(2 + 2);
        const scheme = sigd.decode(tls.SignatureScheme);
        const sig_len = sigd.decode(u16);
        try sigd.ensure(sig_len);
        const encoded_sig = sigd.slice(sig_len);

        // zig-libs tlsclient: Go's policy (and RFC 8446 §4.2.3 for 1.3): no
        // PKCS#1 v1.5 or SHA-1 handshake signature in TLS 1.3, no SHA-1 in
        // TLS 1.2 (Go 1.25+, RFC 9155). std accepted both (review F1).
        switch (scheme) {
            .rsa_pkcs1_sha1, .ecdsa_sha1 => return error.TlsBadSignatureScheme,
            .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 => if (version == .tls_1_3) return error.TlsBadSignatureScheme,
            else => {},
        }
        if (cert_pub_key.algo != @as(Certificate.AlgorithmCategory, switch (scheme) {
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .ecdsa_secp521r1_sha512,
            => .X9_62_id_ecPublicKey,
            .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pkcs1_sha1,
            => .rsaEncryption,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            => .rsassa_pss,
            // zig-libs tlsclient: std had the Ed25519 verifier below but never
            // reached it -- this mapping lacked the scheme, so an Ed25519
            // server certificate was TlsBadSignatureScheme.
            .ed25519 => .curveEd25519,
            else => return error.TlsBadSignatureScheme,
        })) return error.TlsBadSignatureScheme;

        // zig-libs tlsclient: the signed content is short (TLS 1.3: 64 + 34 +
        // a transcript hash; TLS 1.2: two randoms + the ECDHE params), so it
        // is gathered here once for the verifiers that take one message.
        var signed_buf: [max_signed_len]u8 = undefined;
        var signed_len: usize = 0;
        for (msg) |part| {
            if (part.len > signed_buf.len - signed_len) return error.TlsDecodeError;
            @memcpy(signed_buf[signed_len..][0..part.len], part);
            signed_len += part.len;
        }
        const signed = signed_buf[0..signed_len];

        switch (scheme) {
            // zig-libs tlsclient: ECDSA through the `p256`, `p384` and `p521`
            // modules (std's portable verifiers cost ~6× Go's per handshake;
            // std has no P-521). The curve is the KEY's. In TLS 1.3 the scheme
            // names curve and hash together and must match the key (RFC 8446
            // §4.2.3); in TLS 1.2 it names only the hash, and an ECDSA key of
            // any curve signs with it (RFC 5246 §7.4.1.4.1, RFC 8422 §5.10) --
            // std read every TLS 1.2 ECDSA signature as the scheme's curve, so
            // a P-384 or P-521 server certificate failed with InvalidEncoding
            // (Go's server signs ServerKeyExchange with ecdsa_secp256r1_sha256
            // from a P-384 key; found by `tools/interop.zig`, 2026-10-26).
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .ecdsa_secp521r1_sha512,
            => |comptime_scheme| {
                const H = SchemeHash(comptime_scheme);
                const curve = EcCurve.ofSec1(pub_key) orelse return error.InvalidEncoding;
                if (version == .tls_1_3 and curve != comptime EcCurve.ofScheme(comptime_scheme)) return error.TlsBadSignatureScheme;
                var digest: [H.digest_length]u8 = undefined;
                H.hash(signed, &digest, .{});
                switch (curve) {
                    // Signature and key decoded by std, as before p256 took
                    // the equation; p256 truncates a longer digest to the
                    // leftmost 256 bits (FIPS 186-5 §6.4.2).
                    .p256 => {
                        const Ecdsa = SchemeEcdsa(.ecdsa_secp256r1_sha256);
                        const sig = try Ecdsa.Signature.fromDer(encoded_sig);
                        _ = try Ecdsa.PublicKey.fromSec1(pub_key);
                        if (!p256.sign.ecdsaVerifyDigest(pub_key, &digest, sig.toBytes()))
                            return error.SignatureVerificationFailed;
                    },
                    inline .p384, .p521 => |c| {
                        const E = if (c == .p384) p384.Ecdsa(H) else p521.Ecdsa(H);
                        const sig = try E.Signature.fromDer(encoded_sig);
                        const key = try E.PublicKey.fromSec1(pub_key);
                        try sig.verifyPrehashed(digest, key);
                    },
                }
            },
            inline .rsa_pkcs1_sha256,
            .rsa_pkcs1_sha384,
            .rsa_pkcs1_sha512,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .rsa_pss_pss_sha256,
            .rsa_pss_pss_sha384,
            .rsa_pss_pss_sha512,
            .rsa_pkcs1_sha1,
            => |comptime_scheme| {
                // zig-libs tlsclient: std's key DER walk and size gate, then
                // `rsa.VerifyKey` instead of std's `ff`-based key and modexp.
                // A signature that is not exactly the modulus length now fails
                // verification (RFC 8017 §8.1.2/§8.2.2 step 1) — std zero-padded
                // a short one and indexed past its buffer on a long one.
                const Hash = SchemeHash(comptime_scheme);
                const components = try Certificate.rsa.PublicKey.parseDer(pub_key);
                switch (components.modulus.len) {
                    128, 256, 384, 512 => {},
                    else => return error.TlsBadRsaSignatureBitCount,
                }
                const key = rsa.VerifyKey.fromBytes(components.modulus, components.exponent) catch
                    return error.CertificatePublicKeyInvalid;
                if (SchemeRsa(comptime_scheme) == Certificate.rsa.PSSSignature) {
                    // RFC 8446 §4.2.3: the salt is as long as the digest.
                    key.verifyPss(Hash, signed, encoded_sig, Hash.digest_length) catch return error.InvalidSignature;
                } else {
                    key.verifyPkcs1v15(Hash, signed, encoded_sig) catch return error.InvalidSignature;
                }
            },
            inline .ed25519 => |comptime_scheme| {
                const Eddsa = SchemeEddsa(comptime_scheme);
                if (encoded_sig.len != Eddsa.Signature.encoded_length) return error.InvalidEncoding;
                const sig = Eddsa.Signature.fromBytes(encoded_sig[0..Eddsa.Signature.encoded_length].*);
                if (pub_key.len != Eddsa.PublicKey.encoded_length) return error.InvalidEncoding;
                const key = try Eddsa.PublicKey.fromBytes(pub_key[0..Eddsa.PublicKey.encoded_length].*);
                var ver = try sig.verifier(key);
                for (msg) |part| ver.update(part);
                try ver.verify();
            },
            else => unreachable,
        }
    }
};

fn tryDownloadRootCert(chain: *Certificate.Chain, options: *const Options) !void {
    if (Certificate.Chain != void) switch (options.ca) {
        else => {},
        .bundle => |ca| {
            chain.verify(options.realtime_now) catch |err| switch (err) {
                error.Unexpected => return error.TlsCertificateNotVerified,
                else => |e| return e,
            };
            var bundle: Certificate.Bundle = .empty;
            defer bundle.deinit(ca.gpa);
            if (bundle.rescan(ca.gpa, ca.io, options.realtime_now)) {
                try ca.lock.lock(ca.io);
                defer ca.lock.unlock(ca.io);
                std.mem.swap(Certificate.Bundle, ca.bundle, &bundle);
            } else |err| switch (err) {
                error.Canceled => |e| return e,
                else => {},
            }
            return; // the os has verified the certificate for us
        },
    };
    return error.TlsCertificateNotVerified;
}

/// The priority order here is chosen based on what crypto algorithms Zig has
/// available in the standard library as well as what is faster. Following are
/// a few data points on the relative performance of these algorithms.
///
/// Measurement taken with 0.11.0-dev.810+c2f5848fe
/// on x86_64-linux Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz:
/// zig run .lib/std/crypto/benchmark.zig -OReleaseFast
///       aegis-128l:      15382 MiB/s
///        aegis-256:       9553 MiB/s
///       aes128-gcm:       3721 MiB/s
///       aes256-gcm:       3010 MiB/s
/// chacha20Poly1305:        597 MiB/s
///
/// Measurement taken with 0.11.0-dev.810+c2f5848fe
/// on x86_64-linux Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz:
/// zig run .lib/std/crypto/benchmark.zig -OReleaseFast -mcpu=baseline
///       aegis-128l:        629 MiB/s
/// chacha20Poly1305:        529 MiB/s
///        aegis-256:        461 MiB/s
///       aes128-gcm:        138 MiB/s
///       aes256-gcm:        120 MiB/s
const cipher_suites = if (crypto.core.aes.has_hardware_support)
    array(u16, tls.CipherSuite, .{
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        // zig-libs tlsclient: TLS 1.2 with an ECDSA certificate (Go offers
        // these; std had RSA key exchange signatures only).
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    })
else
    array(u16, tls.CipherSuite, .{
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .AEGIS_128L_SHA256,
        .AEGIS_256_SHA512,
        .AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        // zig-libs tlsclient: see above.
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    });

// ── zig-libs tlsclient: unit tests for the additions ──────────────────────

test "alpnSelected: exactly one offered name, nothing else (RFC 7301 §3.1-3.2)" {
    const offered = [_][]const u8{ "h2", "http/1.1" };
    try std.testing.expectEqualStrings("h2", try alpnSelected(&offered, "\x00\x03\x02h2"));
    try std.testing.expectEqualStrings("http/1.1", try alpnSelected(&offered, "\x00\x09\x08http/1.1"));
    const bad = [_][]const u8{
        "\x00\x03\x02h3", // not offered
        "\x00\x06\x02h2\x02h2", // two names
        "\x00\x01\x00", // an empty name
        "\x00\x04\x02h2", // list length over the data
        "\x00\x03\x02h2x", // trailing byte
        "\x00\x03\x03h2", // name length over the data
        "",
        "\x00",
        "\x00\x00",
    };
    for (bad) |b| try std.testing.expectError(error.TlsIllegalParameter, alpnSelected(&offered, b));
}

/// `parseCertRequest`, then the scheme choice for `key` in TLS 1.3.
fn pcr(d: *tls.Decoder, key: tls.SignatureScheme) !CertRequest {
    var cas: [CertRequest.max_cas][]const u8 = undefined;
    var n: usize = 0;
    var req = try parseCertRequest(d, &cas, &n);
    for (req.offered()) |s| if (s == key) {
        req.scheme_ok = true;
        req.scheme = s;
    };
    return req;
}

test "parseCertRequest: context, our scheme, mandatory signature_algorithms" {
    // context "ab"; extensions: signature_algorithms [ecdsa_secp384r1_sha384, ed25519]
    var good = "\x02ab\x00\x0a\x00\x0d\x00\x06\x00\x04\x05\x03\x08\x07".*;
    var d: tls.Decoder = .fromTheirSlice(&good);
    const r = try pcr(&d, .ed25519);
    try std.testing.expectEqualStrings("ab", r.context[0..r.context_len]);
    try std.testing.expect(r.scheme_ok);
    var good2 = good;
    d = .fromTheirSlice(&good2);
    try std.testing.expect(!(try pcr(&d, .ecdsa_secp256r1_sha256)).scheme_ok);
    // No signature_algorithms extension at all.
    // (oid_filters, empty: an extension this client ignores.)
    var none = "\x00\x00\x04\x00\x30\x00\x00".*;
    d = .fromTheirSlice(&none);
    try std.testing.expectError(error.TlsIllegalParameter, pcr(&d, .ed25519));
    // The extension twice.
    var twice = "\x00\x00\x10\x00\x0d\x00\x04\x00\x02\x08\x07\x00\x0d\x00\x04\x00\x02\x08\x07".*;
    d = .fromTheirSlice(&twice);
    try std.testing.expectError(error.TlsIllegalParameter, pcr(&d, .ed25519));
    // An odd list length; a truncated context.
    var odd = "\x00\x00\x07\x00\x0d\x00\x03\x00\x01\x08".*;
    d = .fromTheirSlice(&odd);
    try std.testing.expectError(error.TlsDecodeError, pcr(&d, .ed25519));
    var short = "\x05ab".*;
    d = .fromTheirSlice(&short);
    if (pcr(&d, .ed25519)) |_| return error.TestExpectedError else |_| {}
}

test "CertificateVerify: the RFC 8446 §4.4.3 content, verified with the public key" {
    // The signed bytes must be 64 spaces, the client context string, 0x00
    // and the transcript hash; an independent verifier over exactly that
    // content accepts the signature, one over the server string does not.
    const seed = @as([32]u8, @splat(7));
    const kp = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const key: ClientAuth.PrivateKey = .{ .ed25519 = seed };
    const auth: ClientAuth = .{ .certificate_chain = &.{"\x30\x00"}, .key = &key };
    var req: CertRequest = .{ .scheme_ok = true, .scheme = .ed25519, .auth = auth };
    req.context_len = 0;
    var th = crypto.hash.sha2.Sha256.init(.{});
    th.update("transcript so far");
    var buf: [max_client_auth_len]u8 = undefined;
    var rng = std.Random.DefaultCsprng.init(@splat(1));
    const msgs = try clientAuthMessages(&buf, &req, &th, rng.random());
    // Certificate: type 0b, length 11 = context length (1) + list length
    // (3) + one entry (3 + 2 + 2); empty context, list length 7, entry
    // length 2, the DER 30 00, no extensions.
    try std.testing.expectEqualSlices(u8, "\x0b\x00\x00\x0b\x00\x00\x00\x07\x00\x00\x02\x30\x00\x00\x00", msgs[0..15]);
    const cv = msgs[15..];
    try std.testing.expectEqual(@as(u8, 15), cv[0]);
    try std.testing.expectEqual(@as(u16, 0x0807), mem.readInt(u16, cv[4..6], .big));
    const sig = crypto.sign.Ed25519.Signature.fromBytes(cv[8..72].*);
    var h2 = crypto.hash.sha2.Sha256.init(.{});
    h2.update("transcript so far");
    h2.update(msgs[0..15]);
    const digest = h2.finalResult();
    try sig.verify(strRepeat(" ", 64) ++ "TLS 1.3, client CertificateVerify\x00" ++ digest, kp.public_key);
    try std.testing.expectError(error.SignatureVerificationFailed, sig.verify(strRepeat(" ", 64) ++ "TLS 1.3, server CertificateVerify\x00" ++ digest, kp.public_key));
    // Without our scheme: an empty Certificate and nothing else.
    var th2 = crypto.hash.sha2.Sha256.init(.{});
    const empty = try clientAuthMessages(&buf, &CertRequest{ .scheme_ok = false, .auth = auth }, &th2, rng.random());
    try std.testing.expectEqualSlices(u8, "\x0b\x00\x00\x04\x00\x00\x00\x00", empty);
}

/// `scheme || u16 length || signature` as a server's CertificateVerify body,
/// decoded by `verifySignature` over the content `parts`.
fn testServerSignature(key: *const CertificatePublicKey, scheme: tls.SignatureScheme, sig: []const u8, parts: []const []const u8) CertificatePublicKey.VerifyError!void {
    return testServerSignatureIn(.tls_1_3, key, scheme, sig, parts);
}

fn testServerSignatureIn(version: tls.ProtocolVersion, key: *const CertificatePublicKey, scheme: tls.SignatureScheme, sig: []const u8, parts: []const []const u8) CertificatePublicKey.VerifyError!void {
    var buf: [600]u8 = undefined;
    mem.writeInt(u16, buf[0..2], @backingInt(scheme), .big);
    mem.writeInt(u16, buf[2..4], @intCast(sig.len), .big);
    @memcpy(buf[4..][0..sig.len], sig);
    var d: tls.Decoder = .fromTheirSlice(buf[0 .. 4 + sig.len]);
    return key.verifySignature(version, &d, parts);
}

test "server signature: TLS 1.2 ECDSA schemes name the hash, the key names the curve; TLS 1.3 binds both" {
    // Go's server signs a TLS 1.2 ServerKeyExchange from a P-384 or P-521 key
    // with ecdsa_secp256r1_sha256 (= ECDSA with SHA-256 in TLS 1.2, RFC 5246
    // §7.4.1.4.1); std read it as a P-256 signature and failed with
    // InvalidEncoding (tools/interop.zig, 2026-10-26). Signed by std (P-256,
    // P-384) and by p521 (std has no P-521; Go's server covers it live).
    const five_c: [32]u8 = @splat(0x5c);
    const parts = [_][]const u8{ "client random+server random", &five_c };
    const content = "client random+server random" ++ five_c;
    const Sha256 = crypto.hash.sha2.Sha256;
    const Sha384 = crypto.hash.sha2.Sha384;
    inline for (.{
        .{ crypto.sign.ecdsa.Ecdsa(crypto.ecc.P384, Sha256), tls.SignatureScheme.ecdsa_secp256r1_sha256, tls.SignatureScheme.ecdsa_secp384r1_sha384 },
        .{ crypto.sign.ecdsa.Ecdsa(crypto.ecc.P256, Sha384), tls.SignatureScheme.ecdsa_secp384r1_sha384, tls.SignatureScheme.ecdsa_secp256r1_sha256 },
        .{ p521.Ecdsa(Sha256), tls.SignatureScheme.ecdsa_secp256r1_sha256, tls.SignatureScheme.ecdsa_secp521r1_sha512 },
        .{ p521.Ecdsa(crypto.hash.sha2.Sha512), tls.SignatureScheme.ecdsa_secp521r1_sha512, tls.SignatureScheme.ecdsa_secp521r1_sha512 },
    }) |case| {
        const E = case[0];
        const scheme = case[1];
        const native = case[2];
        const kp = try E.KeyPair.generateDeterministic(@as([E.KeyPair.seed_length]u8, @splat(0x42)));
        var key: CertificatePublicKey = undefined;
        try key.init(.X9_62_id_ecPublicKey, &kp.public_key.toUncompressedSec1());
        var der_buf: [E.Signature.der_encoded_length_max]u8 = undefined;
        const sig = (try kp.sign(content, null)).toDer(&der_buf);
        try testServerSignatureIn(.tls_1_2, &key, scheme, sig, &parts);
        try std.testing.expectError(error.SignatureVerificationFailed, testServerSignatureIn(.tls_1_2, &key, scheme, sig, &.{ "other", &five_c }));
        // TLS 1.3: only the scheme of the key's own curve.
        if (scheme == native)
            try testServerSignatureIn(.tls_1_3, &key, scheme, sig, &parts)
        else
            try std.testing.expectError(error.TlsBadSignatureScheme, testServerSignatureIn(.tls_1_3, &key, scheme, sig, &parts));
    }
}

test "server signature: a genuine P-256 / P-384 / RSA-PSS / PKCS#1 signature verifies, a damaged one does not" {
    // The server's CertificateVerify (TLS 1.3) and ServerKeyExchange (TLS 1.2)
    // signature is the only proof the peer holds the leaf's key; nothing
    // else in this file fed `verifySignature` a bad one (both negative
    // controls survived, 2026-10-11). Content split in parts as the callers
    // pass it.
    const five_c: [32]u8 = @splat(0x5c);
    const parts = [_][]const u8{ strRepeat(" ", 64), "TLS 1.3, server CertificateVerify\x00", &five_c };
    const content = strRepeat(" ", 64) ++ "TLS 1.3, server CertificateVerify\x00" ++ five_c;
    const other = [_][]const u8{ strRepeat(" ", 64), "TLS 1.3, client CertificateVerify\x00", &five_c };

    // ECDSA P-256 and P-384, signed by std (independent of the verifiers
    // under test: p256's and, since 2026-10-13, p384's).
    inline for (.{
        .{ crypto.sign.ecdsa.EcdsaP256Sha256, tls.SignatureScheme.ecdsa_secp256r1_sha256 },
        .{ crypto.sign.ecdsa.EcdsaP384Sha384, tls.SignatureScheme.ecdsa_secp384r1_sha384 },
    }) |case| {
        const E = case[0];
        const scheme = case[1];
        const kp = try E.KeyPair.generateDeterministic(@as([E.KeyPair.seed_length]u8, @splat(0x31)));
        var key: CertificatePublicKey = undefined;
        try key.init(.X9_62_id_ecPublicKey, &kp.public_key.toUncompressedSec1());
        var der_buf: [E.Signature.der_encoded_length_max]u8 = undefined;
        const sig = (try kp.sign(content, null)).toDer(&der_buf);
        try testServerSignature(&key, scheme, sig, &parts);
        try std.testing.expectError(error.SignatureVerificationFailed, testServerSignature(&key, scheme, sig, &other));
        var bad: [E.Signature.der_encoded_length_max]u8 = undefined;
        @memcpy(bad[0..sig.len], sig);
        bad[sig.len - 3] ^= 0x01; // inside s
        try std.testing.expectError(error.SignatureVerificationFailed, testServerSignature(&key, scheme, bad[0..sig.len], &parts));
    }

    // RSA-1024, PSS (rsae, salt = digest length) and PKCS#1 v1.5.
    {
        var prng = std.Random.DefaultPrng.init(0x7C5_2026);
        var kp: rsa.KeyPair = undefined;
        try rsa.generate(&kp, prng.random(), 1024, 65537);
        var n: [128]u8 = undefined;
        try kp.public_key.n.toBytes(&n, .big);
        // RSAPublicKey ::= SEQUENCE { INTEGER n (sign octet 00), INTEGER 65537 }
        const spk = "\x30\x81\x89\x02\x81\x81\x00" ++ n ++ "\x02\x03\x01\x00\x01";
        var key: CertificatePublicKey = undefined;
        try key.init(.rsaEncryption, spk);
        const Sha256 = crypto.hash.sha2.Sha256;
        var sig_buf: [128]u8 = undefined;
        const pss = try rsa.signPss(&kp.secret_key, Sha256, prng.random(), content, Sha256.digest_length, &sig_buf);
        try testServerSignature(&key, .rsa_pss_rsae_sha256, pss, &parts);
        try std.testing.expectError(error.InvalidSignature, testServerSignature(&key, .rsa_pss_rsae_sha256, pss, &other));
        pss[77] ^= 0x10;
        try std.testing.expectError(error.InvalidSignature, testServerSignature(&key, .rsa_pss_rsae_sha256, pss, &parts));
        // a signature one byte short of the modulus length is refused, not padded
        try std.testing.expectError(error.InvalidSignature, testServerSignature(&key, .rsa_pss_rsae_sha256, pss[0..127], &parts));
        var v15_buf: [128]u8 = undefined;
        const v15 = try rsa.signPkcs1v15(&kp.secret_key, Sha256, content, &v15_buf);
        // PKCS#1 v1.5 is TLS 1.2's only (RFC 8446 §4.2.3; review F1, 2026-10-26).
        try testServerSignatureIn(.tls_1_2, &key, .rsa_pkcs1_sha256, v15, &parts);
        try std.testing.expectError(error.TlsBadSignatureScheme, testServerSignatureIn(.tls_1_3, &key, .rsa_pkcs1_sha256, v15, &parts));
        // SHA-1 in neither (Go 1.25+, RFC 9155), even a genuine signature.
        var sha1_buf: [128]u8 = undefined;
        const v15_sha1 = try rsa.signPkcs1v15(&kp.secret_key, crypto.hash.Sha1, content, &sha1_buf);
        inline for (.{ tls.ProtocolVersion.tls_1_2, tls.ProtocolVersion.tls_1_3 }) |v|
            try std.testing.expectError(error.TlsBadSignatureScheme, testServerSignatureIn(v, &key, .rsa_pkcs1_sha1, v15_sha1, &parts));
        v15[5] ^= 0x01;
        try std.testing.expectError(error.InvalidSignature, testServerSignatureIn(.tls_1_2, &key, .rsa_pkcs1_sha256, v15, &parts));
    }
}

test "server signature: a scheme of another key category than the key is TlsBadSignatureScheme (audit 2026-10-26, mutant 63)" {
    // An ECDSA P-256 key offered an RSA-PSS or an Ed25519 signature must be
    // refused up front, not handed to a verifier of the wrong kind.
    const kp = try crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@as([32]u8, @splat(0x31)));
    var key: CertificatePublicKey = undefined;
    try key.init(.X9_62_id_ecPublicKey, &kp.public_key.toUncompressedSec1());
    const sig = @as([64]u8, @splat(0x11));
    const parts = [_][]const u8{"content"};
    try std.testing.expectError(error.TlsBadSignatureScheme, testServerSignature(&key, .rsa_pss_rsae_sha256, &sig, &parts));
    try std.testing.expectError(error.TlsBadSignatureScheme, testServerSignatureIn(.tls_1_2, &key, .rsa_pkcs1_sha256, &sig, &parts));
    try std.testing.expectError(error.TlsBadSignatureScheme, testServerSignature(&key, .ed25519, &sig, &parts));
}

test "ConnectionInfo.keep: an exact fit is accepted, one byte more is not (audit 2026-10-26, mutant 47)" {
    var storage: [4]u8 = undefined;
    var ci: ConnectionInfo = .init(&storage);
    try std.testing.expectEqualStrings("ab", try ci.keep("ab"));
    try std.testing.expectEqualStrings("cd", try ci.keep("cd")); // fills the storage exactly
    try std.testing.expectError(error.ConnectionInfoTooSmall, ci.keep("e"));
    ci.reset();
    try std.testing.expectEqualStrings("abcd", try ci.keep("abcd"));
}

test "ClientAuth.PrivateKey.fits: Ed25519 signs in TLS 1.3 only (audit 2026-10-26, mutant 39)" {
    const key: ClientAuth.PrivateKey = .{ .ed25519 = @as([32]u8, @splat(7)) };
    try std.testing.expect(key.fits(.ed25519, .tls_1_3));
    try std.testing.expect(!key.fits(.ed25519, .tls_1_2));
}

test "CertRequest.choose: a credential with no certificate answers with an empty Certificate (audit 2026-10-26, mutant 37)" {
    const key: ClientAuth.PrivateKey = .{ .ed25519 = @as([32]u8, @splat(7)) };
    var options: Options = undefined;
    options.client_auth_select = null;
    options.client_auth = .{ .certificate_chain = &.{}, .key = &key };
    var req: CertRequest = .{};
    req.schemes[0] = .ed25519;
    req.schemes_len = 1;
    req.choose(&options, .tls_1_3, &.{});
    try std.testing.expect(!req.scheme_ok);
    // The same key with a certificate does fit.
    const chain = [_][]const u8{"\x30\x00"};
    options.client_auth = .{ .certificate_chain = &chain, .key = &key };
    var req2: CertRequest = .{};
    req2.schemes[0] = .ed25519;
    req2.schemes_len = 1;
    req2.choose(&options, .tls_1_3, &.{});
    try std.testing.expect(req2.scheme_ok);
}

test "storeTicket: a NewSessionTicket for an entry another connection has taken is ignored (audit 2026-10-26, mutant 56)" {
    var entries: [1]ClientSession = undefined;
    var cache: SessionCache = .init(&entries, null);
    const entry = cache.reserve("a.test:443").?;
    var body_buf: [64]u8 = undefined;
    const body = try tlsresume.ticket.NewSessionTicket.encode(.{
        .ticket_lifetime = 100,
        .ticket_age_add = 7,
        .ticket_nonce = "",
        .ticket = "tkt",
    }, &body_buf);
    var c: Client = undefined;
    c.session_cache = &cache;
    c.session_entry = entry;
    c.handshake_time_ms = 5_000;
    // Another connection reserved the key since: our generation is stale.
    c.session_generation = entry.generation - 1;
    storeTicket(&c, body);
    try std.testing.expect(!entry.usable);
    try std.testing.expectEqual(@as(u16, 0), entry.ticket_len);
    // Our own generation: stored.
    c.session_generation = entry.generation;
    storeTicket(&c, body);
    try std.testing.expect(entry.usable);
    try std.testing.expectEqualStrings("tkt", entry.ticket());
    try std.testing.expectEqual(@as(i64, 5_000), entry.received_ms);
}

test "client Certificate echoes the request context (RFC 8446 §4.4.2)" {
    const key: ClientAuth.PrivateKey = .{ .ed25519 = @as([32]u8, @splat(7)) };
    const auth: ClientAuth = .{ .certificate_chain = &.{"\x30\x00"}, .key = &key };
    var req: CertRequest = .{ .scheme_ok = false, .context_len = 3, .auth = auth };
    @memcpy(req.context[0..3], "xyz");
    var th = crypto.hash.sha2.Sha256.init(.{});
    var buf: [max_client_auth_len]u8 = undefined;
    var rng = std.Random.DefaultCsprng.init(@splat(1));
    // Empty Certificate: type 0b, length 7 = 1 + 3 (context) + 3 (empty list).
    try std.testing.expectEqualSlices(u8, "\x0b\x00\x00\x07\x03xyz\x00\x00\x00", try clientAuthMessages(&buf, &req, &th, rng.random()));
}

test "writeHandshakeRecords: over 2^14 - 1 bytes splits into records with sequence 0, 1" {
    // Decrypted independently, record by record, with the RFC 8446 §5.3
    // per-record nonce (iv XOR big-endian sequence number).
    const A = crypto.aead.aes_gcm.Aes128Gcm;
    const P = struct {
        const AEAD = A;
    };
    const key = @as([A.key_length]u8, @splat(1));
    const iv = @as([A.nonce_length]u8, @splat(2));
    // Just over one record's 2^14 - 1 handshake bytes, within what the
    // function is ever given (client auth messages + Finished).
    var payload: [16400]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    var out_buf: [2 * (5 + 16384 + 16)]u8 = undefined;
    var w: Writer = .fixed(&out_buf);
    try writeHandshakeRecords(P, &w, &.{ payload[0..12000], payload[12000..] }, key, iv);
    var rest = w.buffered();
    var got: [16400]u8 = undefined;
    var n: usize = 0;
    var seq: u64 = 0;
    while (rest.len > 0) : (seq += 1) {
        const len = mem.readInt(u16, rest[3..5], .big);
        try std.testing.expectEqual(@as(u8, 23), rest[0]);
        const body = rest[5..][0..len];
        var nonce = iv;
        for (nonce[4..], mem.toBytes(mem.nativeToBig(u64, seq))) |*x, y| x.* ^= y;
        var pt: [16384 + 1]u8 = undefined;
        try A.decrypt(pt[0 .. len - 16], body[0 .. len - 16], body[len - 16 ..][0..16].*, rest[0..5], nonce, key);
        try std.testing.expectEqual(@as(u8, 22), pt[len - 17]); // inner content type: handshake
        @memcpy(got[n..][0 .. len - 17], pt[0 .. len - 17]);
        n += len - 17;
        rest = rest[5 + len ..];
    }
    try std.testing.expectEqual(@as(u64, 2), seq);
    try std.testing.expectEqualSlices(u8, &payload, got[0..n]);
}

/// A TLS 1.3 client past its handshake (AES-128-GCM, fixed keys) writing
/// into `output` from `write_buffer` and decrypting into `read_buffer`.
fn testAppClient(input: *Reader, output: *Writer, write_buffer: []u8, read_buffer: []u8) Client {
    return .{
        .input = input,
        .reader = .{ .buffer = read_buffer, .vtable = &.{ .stream = stream, .readVec = readVec }, .seek = 0, .end = 0 },
        .output = output,
        .writer = .{ .buffer = write_buffer, .vtable = &.{ .drain = drain, .flush = flush } },
        .tls_version = .tls_1_3,
        .read_seq = 0,
        .write_seq = 0,
        .received_close_notify = false,
        .allow_truncation_attacks = false,
        .application_cipher = .{ .AES_128_GCM_SHA256 = .{ .tls_1_3 = .{
            .client_secret = @splat(1),
            .server_secret = @splat(2),
            .client_key = @splat(3),
            .server_key = @splat(4),
            .client_iv = @splat(5),
            .server_iv = @splat(6),
        } } },
        .ssl_key_log = null,
    };
}

test "flush: a write_buffer larger than output's room goes out whole (sweep 2026-10-28)" {
    // `output` drains to nowhere and holds one record at a time, as a
    // socket writer with a `min_buffer_len` buffer does. std sealed one
    // record on flush and dropped the rest of the 40,000 bytes.
    var in_buf: [0]u8 = undefined;
    var input: Reader = .fixed(&in_buf);
    var out_buf: [min_buffer_len]u8 = undefined;
    var dw: Writer.Discarding = .init(&out_buf);
    var write_buf: [64 * 1024]u8 = undefined;
    var c = testAppClient(&input, &dw.writer, &write_buf, &.{});
    const payload: [40_000]u8 = @splat('x');
    try c.writer.writeAll(&payload);
    try c.writer.flush();
    // Every plaintext byte went out: each record adds a 5-byte header, the
    // inner content type and a 16-byte tag (records also fill the room left
    // after a full one, so there are more than the minimal three).
    try std.testing.expectEqual(@as(usize, 0), c.writer.end);
    try std.testing.expect(c.write_seq >= 3);
    try std.testing.expectEqual(@as(u64, payload.len + c.write_seq * (5 + 1 + 16)), dw.fullCount());
}

test "init: input or output buffer under min_buffer_len is BufferTooSmall, not an assert (sweep 2026-10-28)" {
    var entropy: [Options.entropy_len]u8 = @splat(7);
    var small: [64]u8 = undefined;
    var big_in: [min_buffer_len]u8 = undefined;
    var big_out: [min_buffer_len]u8 = undefined;
    var buf: [64]u8 = undefined;
    var rbuf: [max_ciphertext_len]u8 = undefined;
    const opts: Options = .{ .host = .no_verification, .ca = .no_verification, .write_buffer = &buf, .read_buffer = &rbuf, .entropy = &entropy, .realtime_now = .zero };
    {
        var input: Reader = .fixed(&small);
        var dw: Writer.Discarding = .init(&big_out);
        try std.testing.expectError(error.BufferTooSmall, init(&input, &dw.writer, opts));
    }
    {
        // A socket-like writer (its rebase drains, never grows) with a small
        // buffer; std's greedy slice asserted on it at the first record.
        var input: Reader = .fixed(&big_in);
        var dw: Writer.Discarding = .init(&small);
        try std.testing.expectError(error.BufferTooSmall, init(&input, &dw.writer, opts));
        // The same writer after init: WriteFailed, not an assert.
        var c = testAppClient(&input, &dw.writer, &buf, &.{});
        try c.writer.writeAll("hi");
        try std.testing.expectError(error.WriteFailed, c.writer.flush());
    }
    {
        // A read_buffer one byte short of the largest record's plaintext.
        var input: Reader = .fixed(&big_in);
        var dw: Writer.Discarding = .init(&big_out);
        var o = opts;
        o.read_buffer = rbuf[0 .. rbuf.len - 1];
        try std.testing.expectError(error.BufferTooSmall, init(&input, &dw.writer, o));
        o.read_buffer = &.{};
        try std.testing.expectError(error.BufferTooSmall, init(&input, &dw.writer, o));
    }
    {
        // A growing writer starts empty and is fine; the handshake then
        // fails on the empty input, past the buffer checks.
        var input: Reader = .fixed(&big_in);
        input.end = 0;
        var aw: Writer.Allocating = .init(std.testing.allocator);
        defer aw.deinit();
        try std.testing.expectError(error.TlsConnectionTruncated, init(&input, &aw.writer, opts));
    }
}

test "KeyUpdate: one ends its record; a message after it in the same record is unexpected_message (RFC 8446 §5.1, sweep 2026-10-28)" {
    const A = crypto.aead.aes_gcm.Aes128Gcm;
    const ku = [_]u8{ @backingInt(tls.HandshakeType.key_update), 0, 0, 1, 0 };
    for ([_]usize{ 1, 2 }) |count| {
        // One record from the server (key 4.., iv 6.., sequence 0) holding
        // `count` KeyUpdates.
        var inner: [2 * ku.len + 1]u8 = undefined;
        for (0..count) |i| @memcpy(inner[i * ku.len ..][0..ku.len], &ku);
        inner[count * ku.len] = @backingInt(tls.ContentType.handshake);
        const pt = inner[0 .. count * ku.len + 1];
        var rec: [5 + inner.len + A.tag_length]u8 = undefined;
        rec[0..5].* = .{ @backingInt(tls.ContentType.application_data), 3, 3, 0, @intCast(pt.len + A.tag_length) };
        A.encrypt(rec[5..][0..pt.len], rec[5 + pt.len ..][0..A.tag_length], pt, rec[0..5], @splat(6), @splat(4));
        var input: Reader = .fixed(rec[0 .. 5 + pt.len + A.tag_length]);
        var out_buf: [min_buffer_len]u8 = undefined;
        var dw: Writer.Discarding = .init(&out_buf);
        var read_buf: [max_ciphertext_len]u8 = undefined;
        var c = testAppClient(&input, &dw.writer, &.{}, &read_buf);
        const key_before = c.application_cipher.AES_128_GCM_SHA256.tls_1_3.server_key;
        if (count == 1) {
            try std.testing.expectEqual(@as(usize, 0), try readIndirect(&c));
            try std.testing.expect(!mem.eql(u8, &key_before, &c.application_cipher.AES_128_GCM_SHA256.tls_1_3.server_key));
        } else {
            try std.testing.expectError(error.ReadFailed, readIndirect(&c));
            try std.testing.expectEqual(@as(?ReadError, error.TlsUnexpectedMessage), c.read_err);
            // Refused before any key was switched.
            try std.testing.expectEqualSlices(u8, &key_before, &c.application_cipher.AES_128_GCM_SHA256.tls_1_3.server_key);
        }
    }
}

test "init: a realtime_now outside i64 milliseconds is RealtimeInvalid (sweep 2026-10-28)" {
    var entropy: [Options.entropy_len]u8 = @splat(7);
    var in_buf: [min_buffer_len]u8 = undefined;
    var input: Reader = .fixed(&in_buf);
    var out_buf: [min_buffer_len]u8 = undefined;
    var dw: Writer.Discarding = .init(&out_buf);
    var buf: [64]u8 = undefined;
    var rbuf: [max_ciphertext_len]u8 = undefined;
    for ([_]i96{ std.math.maxInt(i96), std.math.minInt(i96) }) |ns| {
        const opts: Options = .{ .host = .no_verification, .ca = .no_verification, .write_buffer = &buf, .read_buffer = &rbuf, .entropy = &entropy, .realtime_now = .{ .nanoseconds = ns } };
        try std.testing.expectError(error.RealtimeInvalid, init(&input, &dw.writer, opts));
    }
}

test "encryptedExtensionsAlpn: one answer, or none; twice is refused" {
    const offered = [_][]const u8{"h2"};
    // server_name (empty) + ALPN "h2".
    var one = "\x00\x00\x00\x00\x00\x10\x00\x05\x00\x03\x02h2".*;
    var d: tls.Decoder = .fromTheirSlice(&one);
    try std.testing.expectEqualStrings("h2", (try encryptedExtensionsAlpn(&d, &offered)).?);
    // Not offered anything: the server's answer is ignored, as std does.
    var one2 = one;
    d = .fromTheirSlice(&one2);
    try std.testing.expectEqual(@as(?[]const u8, null), try encryptedExtensionsAlpn(&d, &.{}));
    var twice = "\x00\x10\x00\x05\x00\x03\x02h2\x00\x10\x00\x05\x00\x03\x02h2".*;
    d = .fromTheirSlice(&twice);
    try std.testing.expectError(error.TlsIllegalParameter, encryptedExtensionsAlpn(&d, &offered));
    var none = "\x00\x00\x00\x00".*;
    d = .fromTheirSlice(&none);
    try std.testing.expectEqual(@as(?[]const u8, null), try encryptedExtensionsAlpn(&d, &offered));
}

test "sweep: the server-controlled ALPN and CertificateRequest parsers on damaged input" {
    // Valid encodings damaged at random (a byte set, flipped or dropped,
    // length fields aimed at), seeded and deterministic. Every result is a
    // clean error or a value within the input's promises: an ALPN choice is
    // always one of ours, a request context never over 255 bytes.
    const offered = [_][]const u8{ "h2", "http/1.1" };
    const ee = "\x00\x10\x00\x0b\x00\x09\x08http/1.1\x00\x00\x00\x00";
    const cr = "\x02ab\x00\x0a\x00\x0d\x00\x06\x00\x04\x05\x03\x08\x07";
    var reach = [_]usize{ 0, 0, 0, 0 };
    for (0..20_000) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        const r = prng.random();
        const src: []const u8 = if (seed % 2 == 0) ee else cr;
        var buf: [64]u8 = undefined;
        @memcpy(buf[0..src.len], src);
        var len = src.len;
        for (0..r.intRangeAtMost(usize, 1, 3)) |_| {
            switch (r.uintLessThan(u8, 4)) {
                0 => buf[r.uintLessThan(usize, len)] = r.int(u8),
                1 => buf[r.uintLessThan(usize, len)] ^= @as(u8, 1) << r.int(u3),
                2 => buf[r.uintLessThan(usize, @min(len, 8))] = r.uintLessThan(u8, 12), // length fields
                else => len = r.uintAtMost(usize, len),
            }
            if (len == 0) break;
        }
        var d: tls.Decoder = .fromTheirSlice(buf[0..len]);
        if (seed % 2 == 0) {
            if (encryptedExtensionsAlpn(&d, &offered)) |sel| {
                if (sel) |s| {
                    try std.testing.expect(s.ptr == offered[0].ptr or s.ptr == offered[1].ptr);
                    reach[0] += 1;
                }
            } else |_| reach[1] += 1;
        } else {
            if (pcr(&d, .ed25519)) |req| {
                try std.testing.expect(req.context_len <= 255);
                reach[2] += 1;
            } else |_| reach[3] += 1;
        }
    }
    // Measured 2026-10-04: 323 ALPN answers accepted (each one of ours),
    // 8 209 refused; 1 394 requests parsed, 8 606 refused.
    try std.testing.expect(reach[0] > 200 and reach[1] > 6000);
    try std.testing.expect(reach[2] > 1000 and reach[3] > 6000);
}

test "leafEntryExtensions: TLS 1.3 CertificateEntry OCSP and SCTs are kept; malformed ones refused" {
    var storage: [256]u8 = undefined;
    var ci: ConnectionInfo = .init(&storage);
    // status_request: ocsp(1), u24 5, the response; then an SCT list of one.
    const exts = "\x00\x05\x00\x09\x01\x00\x00\x05\x30\x03\x0a\x01\x01" ++
        "\x00\x12\x00\x07\x00\x05\x00\x03abc";
    try leafEntryExtensions(&ci, .fromTheirSlice(@constCast(exts)), true, true);
    try std.testing.expectEqualSlices(u8, "\x30\x03\x0a\x01\x01", ci.ocsp_response);
    try std.testing.expectEqual(@as(usize, 1), ci.signedCertificateTimestamps().len);
    try std.testing.expectEqualStrings("abc", ci.signedCertificateTimestamps()[0]);
    // Not asked for: ignored.
    var ci2: ConnectionInfo = .init(&storage);
    try leafEntryExtensions(&ci2, .fromTheirSlice(@constCast(exts)), false, false);
    try std.testing.expectEqual(@as(usize, 0), ci2.ocsp_response.len);
    // A list length that lies, an empty SCT, a status type that is not ocsp.
    try std.testing.expectError(error.TlsDecodeError, keepScts(&ci2, "\x00\x09\x00\x03abc"));
    try std.testing.expectError(error.TlsDecodeError, keepScts(&ci2, "\x00\x02\x00\x00"));
    try std.testing.expectError(error.TlsDecodeError, parseCertificateStatus("\x02\x00\x00\x01\x00"));
    try std.testing.expectError(error.TlsDecodeError, parseCertificateStatus("\x01\x00\x00\x02\x00"));
}

test "exportKeyingMaterial: TLS 1.2 refuses reserved labels; no exporter before a handshake" {
    var c: Client = undefined;
    c.exporter = .none;
    var out: [8]u8 = undefined;
    try std.testing.expectError(error.ExporterUnavailable, c.exportKeyingMaterial("EXPERIMENTAL-x", null, &out));
    c.exporter = .{ .tls12 = .{ .hash = .sha256, .master = @splat(1), .randoms = @splat(2) } };
    try std.testing.expectError(error.ExporterLabelReserved, c.exportKeyingMaterial("master secret", null, &out));
    try c.exportKeyingMaterial("EXPERIMENTAL-x", null, &out);
    var with_ctx: [8]u8 = undefined;
    try c.exportKeyingMaterial("EXPERIMENTAL-x", "", &with_ctx);
    // RFC 5705: an empty context is not no context in TLS 1.2.
    try std.testing.expect(!std.mem.eql(u8, &out, &with_ctx));
    c.exporter = .{ .tls13 = .{ .hash = .sha256, .secret = @splat(3) } };
    try c.exportKeyingMaterial("EXPERIMENTAL-x", null, &out);
    try c.exportKeyingMaterial("EXPERIMENTAL-x", "", &with_ctx);
    // RFC 8446 §7.5: in TLS 1.3 they are the same.
    try std.testing.expectEqualSlices(u8, &out, &with_ctx);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

test "re-audit 2026-10-28: end: close_notify goes out on a minimal output; a too-small output is WriteFailed, not an assert" {
    var in_buf: [0]u8 = undefined;
    var input: Reader = .fixed(&in_buf);
    var buf: [64]u8 = undefined;
    {
        var out_buf: [min_buffer_len]u8 = undefined;
        var dw: Writer.Discarding = .init(&out_buf);
        var c = testAppClient(&input, &dw.writer, &buf, &.{});
        try c.end();
        // 5-byte header, the 2-byte alert, its inner type and the 16-byte tag.
        try std.testing.expectEqual(@as(u64, 5 + 2 + 1 + 16), dw.fullCount());
    }
    {
        var small: [64]u8 = undefined;
        var dw: Writer.Discarding = .init(&small);
        var c = testAppClient(&input, &dw.writer, &buf, &.{});
        try std.testing.expectError(error.WriteFailed, c.end());
    }
}
