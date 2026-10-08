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
/// The buffer is asserted to have capacity at least `min_buffer_len`.
input: *Reader,
/// Decrypted stream from the server to the client.
reader: Reader,

/// The encrypted stream from the client to the server. Bytes are pushed here
/// via `writer`.
///
/// The buffer is asserted to have capacity at least `min_buffer_len`.
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
    write_buffer: []u8,
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
    /// A client certificate for a TLS 1.3 server that sends a
    /// CertificateRequest. Null (the default): such a request is
    /// `error.TlsUnexpectedMessage`, as in std. Set: the chain is sent and
    /// signed for with `key`; when the request's signature_algorithms do not
    /// include `key`'s scheme, an empty Certificate is sent (RFC 8446
    /// §4.4.2.3) and the server decides. TLS 1.2 client authentication is
    /// not implemented (a TLS 1.2 CertificateRequest stays an error).
    client_auth: ?ClientAuth = null,

    pub const entropy_len = 240;
};

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
        /// Ed25519 seed (RFC 8032 private key). Signs `ed25519`.
        ed25519: [32]u8,

        pub fn scheme(k: *const PrivateKey) tls.SignatureScheme {
            return switch (k.*) {
                .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1_sha256,
                .ecdsa_secp384r1_sha384 => .ecdsa_secp384r1_sha384,
                .ed25519 => .ed25519,
            };
        }
    };
};

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
} || std.Io.Writer.Error || std.Io.Reader.ShortError || std.Io.Cancelable;

/// Initiates a TLS handshake and establishes a TLSv1.2 or TLSv1.3 session.
///
/// `host` is only borrowed during this function call.
///
/// `input` is asserted to have buffer capacity at least `min_buffer_len`.
pub fn init(input: *Reader, output: *Writer, options: Options) InitError!Client {
    assert(input.buffer.len >= min_buffer_len);
    const host = switch (options.host) {
        .no_verification => "",
        .explicit => |host| host,
    };
    const host_len: u16 = @intCast(host.len);

    const client_hello_rand = options.entropy[0..32].*;
    var key_seq: u64 = 0;
    var server_hello_rand: [32]u8 = undefined;
    const legacy_session_id = options.entropy[32..64].*;

    var key_share = KeyShare.init(options.entropy[64..240]) catch |err| switch (err) {
        // Only possible to happen if the seed is all zeroes.
        error.IdentityElement => return error.InsufficientEntropy,
    };

    const extensions_payload = tls.extension(.supported_versions, array(u8, tls.ProtocolVersion, .{
        .tls_1_3,
        .tls_1_2,
    })) ++ tls.extension(.signature_algorithms, array(u16, tls.SignatureScheme, .{
        .ecdsa_secp256r1_sha256,
        .ecdsa_secp384r1_sha384,
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
    })) ++ tls.extension(.supported_groups, array(u16, tls.NamedGroup, .{
        .x25519_ml_kem768,
        .secp256r1,
        .secp384r1,
        .x25519,
    })) ++ tls.extension(.psk_key_exchange_modes, array(u8, tls.PskKeyExchangeMode, .{
        .psk_dhe_ke,
    })) ++ tls.extension(.key_share, array(
        u16,
        u8,
        int(u16, @intFromEnum(tls.NamedGroup.x25519_ml_kem768)) ++
            array(u16, u8, key_share.ml_kem768_kp.public_key.toBytes() ++ key_share.x25519_kp.public_key) ++
            int(u16, @intFromEnum(tls.NamedGroup.secp256r1)) ++
            array(u16, u8, key_share.secp256r1_kp.public_key.toUncompressedSec1()) ++
            int(u16, @intFromEnum(tls.NamedGroup.secp384r1)) ++
            array(u16, u8, key_share.secp384r1_kp.public_key.toUncompressedSec1()) ++
            int(u16, @intFromEnum(tls.NamedGroup.x25519)) ++
            array(u16, u8, key_share.x25519_kp.public_key),
    ));
    const server_name_extension = int(u16, @intFromEnum(tls.ExtensionType.server_name)) ++
        int(u16, 2 + 1 + 2 + host_len) ++ // byte length of this extension payload
        int(u16, 1 + 2 + host_len) ++ // server_name_list byte count
        .{0x00} ++ // name_type
        int(u16, host_len);
    const server_name_extension_len = switch (options.host) {
        .no_verification => 0,
        .explicit => server_name_extension.len + host_len,
    };

    const extensions_header =
        int(u16, @intCast(extensions_payload.len + server_name_extension_len)) ++
        extensions_payload ++
        server_name_extension;

    const client_hello =
        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
        client_hello_rand ++
        [1]u8{32} ++ legacy_session_id ++
        cipher_suites ++
        array(u8, tls.CompressionMethod, .{.null}) ++
        extensions_header;

    const out_handshake = .{@intFromEnum(tls.HandshakeType.client_hello)} ++
        int(u24, @intCast(client_hello.len - server_name_extension.len + server_name_extension_len)) ++
        client_hello;

    const cleartext_header_buf = .{@intFromEnum(tls.ContentType.handshake)} ++
        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_0)) ++
        int(u16, @intCast(out_handshake.len - server_name_extension.len + server_name_extension_len)) ++
        out_handshake;
    const cleartext_header = switch (options.host) {
        .no_verification => cleartext_header_buf[0 .. cleartext_header_buf.len - server_name_extension.len],
        .explicit => &cleartext_header_buf,
    };

    // zig-libs tlsclient: ALPN. With no protocols the ClientHello is std's,
    // byte for byte. Otherwise the extension goes last (after the host
    // name) and the three length fields in front of it grow by its size.
    var alpn_ext_buf: [4 + 2 + max_alpn_len]u8 = undefined;
    const alpn_ext = try alpnExtension(&alpn_ext_buf, options.alpn_protocols);
    var patched_header_buf: [cleartext_header_buf.len]u8 = undefined;
    const hello_header: []const u8 = if (alpn_ext.len == 0) cleartext_header else blk: {
        const h = patched_header_buf[0..cleartext_header.len];
        @memcpy(h, cleartext_header);
        const ext_len_at = tls.record_header_len + 4 + 2 + 32 + 1 + 32 + cipher_suites.len + 2;
        const grow: u16 = @intCast(alpn_ext.len);
        mem.writeInt(u16, h[3..5], mem.readInt(u16, h[3..5], .big) + grow, .big);
        mem.writeInt(u24, h[6..9], mem.readInt(u24, h[6..9], .big) + grow, .big);
        mem.writeInt(u16, h[ext_len_at..][0..2], mem.readInt(u16, h[ext_len_at..][0..2], .big) + grow, .big);
        break :blk h;
    };

    {
        var iovecs: [3][]const u8 = .{ hello_header, host, alpn_ext };
        var n: usize = 0;
        for (iovecs) |v| {
            if (v.len == 0) continue;
            iovecs[n] = v;
            n += 1;
        }
        try output.writeVecAll(iovecs[0..n]);
        try output.flush();
    }
    // zig-libs tlsclient: client authentication -- the server's
    // CertificateRequest, when one came.
    var cert_request: ?CertRequest = null;

    var tls_version: tls.ProtocolVersion = undefined;
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
                if (record_ct != .application_data) return error.TlsUnexpectedMessage;
                try record_decoder.ensure(record_len);
                const cleartext_buf = &cleartext_bufs[cert_buf_index % 2];
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
                            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                            const operand: V = pad ++ @as([8]u8, @bitCast(big(read_seq)));
                            break :nonce @as(V, pv.server_handshake_iv) ^ operand;
                        };
                        P.AEAD.decrypt(cleartext, ciphertext, auth_tag, record_header, nonce, pv.server_handshake_key) catch
                            return error.TlsBadRecordMac;
                        // TODO use scalar, non-slice version
                        cleartext_fragment_end += mem.trimEnd(u8, cleartext, "\x00").len;
                    },
                }
                read_seq += 1;
                cleartext_fragment_end -= 1;
                const ct: tls.ContentType = @enumFromInt(cleartext_buf[cleartext_fragment_end]);
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
                            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                            const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
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
                switch (handshake_type) {
                    .server_hello => {
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .hello) return error.TlsUnexpectedMessage;
                        try hsd.ensure(2 + 32 + 1);
                        const legacy_version = hsd.decode(u16);
                        @memcpy(&server_hello_rand, hsd.array(32));
                        if (mem.eql(u8, &server_hello_rand, &tls.hello_retry_request_sequence)) {
                            // This is a HelloRetryRequest message. This client implementation
                            // does not expect to get one.
                            return error.TlsUnexpectedMessage;
                        }
                        const legacy_session_id_echo_len = hsd.decode(u8);
                        try hsd.ensure(legacy_session_id_echo_len + 2 + 1);
                        const legacy_session_id_echo = hsd.slice(legacy_session_id_echo_len);
                        const cipher_suite_tag = hsd.decode(tls.CipherSuite);
                        hsd.skip(1); // legacy_compression_method
                        var supported_version: ?u16 = null;
                        // zig-libs tlsclient: ALPN.
                        var alpn_seen = false;
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
                                    .key_share => {
                                        if (key_share.getSharedSecret()) |_| return error.TlsIllegalParameter;
                                        try extd.ensure(4);
                                        const named_group = extd.decode(tls.NamedGroup);
                                        const key_size = extd.decode(u16);
                                        try extd.ensure(key_size);
                                        try key_share.exchange(named_group, extd.slice(key_size));
                                    },
                                    // zig-libs tlsclient: ALPN (TLS 1.2 answers in ServerHello).
                                    .application_layer_protocol_negotiation => if (options.alpn_protocols.len != 0) {
                                        if (alpn_seen) return error.TlsIllegalParameter;
                                        alpn_seen = true;
                                        alpn_selected = try alpnSelected(options.alpn_protocols, extd.rest());
                                    },
                                    else => {},
                                }
                            }
                        }

                        tls_version = @enumFromInt(supported_version orelse legacy_version);
                        switch (tls_version) {
                            .tls_1_3 => if (!mem.eql(u8, legacy_session_id_echo, &legacy_session_id)) return error.TlsIllegalParameter,
                            .tls_1_2 => if (mem.eql(u8, server_hello_rand[24..31], "DOWNGRD") and
                                server_hello_rand[31] >> 1 == 0x00) return error.TlsIllegalParameter,
                            else => return error.TlsIllegalParameter,
                        }

                        switch (cipher_suite_tag) {
                            inline .AES_128_GCM_SHA256,
                            .AES_256_GCM_SHA384,
                            .CHACHA20_POLY1305_SHA256,
                            .AEGIS_256_SHA512,
                            .AEGIS_128L_SHA256,

                            .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                            .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                            .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                            => |tag| {
                                handshake_cipher = @unionInit(tls.HandshakeCipher, @tagName(tag.with()), .{
                                    .transcript_hash = .init(.{}),
                                    .version = undefined,
                                });
                                const p = &@field(handshake_cipher, @tagName(tag.with()));
                                p.transcript_hash.update(hello_header[tls.record_header_len..]); // Client Hello part 1
                                p.transcript_hash.update(host); // Client Hello part 2
                                p.transcript_hash.update(alpn_ext); // zig-libs tlsclient: ALPN (empty when off)
                                p.transcript_hash.update(wrapped_handshake);
                            },

                            else => return error.TlsIllegalParameter,
                        }
                        switch (tls_version) {
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
                                        const zeroes = [1]u8{0} ** P.Hash.digest_length;
                                        const early_secret = P.Hkdf.extract(&[1]u8{0}, &zeroes);
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
                                handshake_state = .encrypted_extensions;
                            },
                            .tls_1_2 => switch (cipher_suite_tag) {
                                .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                => handshake_state = .certificate,
                                else => return error.TlsIllegalParameter,
                            },
                            else => return error.TlsIllegalParameter,
                        }
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
                                _ = all_extd;
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
                                switch (options.host) {
                                    .no_verification => {},
                                    .explicit => try subject.verifyHostName(host),
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
                    // zig-libs tlsclient: client authentication. Without
                    // `client_auth`, or in TLS 1.2, this is std's
                    // TlsUnexpectedMessage.
                    .certificate_request => {
                        const auth = if (options.client_auth) |*a| a else return error.TlsUnexpectedMessage;
                        if (tls_version != .tls_1_3) return error.TlsUnexpectedMessage;
                        if (cipher_state != .handshake) return error.TlsUnexpectedMessage;
                        if (handshake_state != .certificate or cert_request != null) return error.TlsUnexpectedMessage;
                        switch (handshake_cipher) {
                            inline else => |*p| p.transcript_hash.update(wrapped_handshake),
                        }
                        cert_request = try parseCertRequest(&hsd, auth.key.scheme());
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
                        const key_size = hsd.decode(u8);
                        try hsd.ensure(key_size);
                        const server_pub_key = hsd.slice(key_size);
                        try main_cert_pub_key.verifySignature(&hsd, &.{ &client_hello_rand, &server_hello_rand, hsd.buf[0..hsd.idx] });
                        try key_share.exchange(named_group, server_pub_key);
                        handshake_state = .server_hello_done;
                    },
                    .server_hello_done => {
                        if (tls_version != .tls_1_2) return error.TlsUnexpectedMessage;
                        if (cipher_state != .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .server_hello_done) return error.TlsUnexpectedMessage;

                        const public_key_bytes: []const u8 = switch (tls12_negotiated_group orelse .secp256r1) {
                            .secp256r1 => &key_share.secp256r1_kp.public_key.toUncompressedSec1(),
                            .secp384r1 => &key_share.secp384r1_kp.public_key.toUncompressedSec1(),
                            .x25519 => &key_share.x25519_kp.public_key,
                            else => return error.TlsIllegalParameter,
                        };

                        const client_key_exchange_prefix = .{@intFromEnum(tls.ContentType.handshake)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            int(u16, @intCast(public_key_bytes.len + 5)) ++ // record length
                            .{@intFromEnum(tls.HandshakeType.client_key_exchange)} ++
                            int(u24, @intCast(public_key_bytes.len + 1)) ++ // handshake message length
                            .{@as(u8, @intCast(public_key_bytes.len))}; // public key length
                        const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                            array(u16, tls.ChangeCipherSpecType, .{.change_cipher_spec});
                        const pre_master_secret = key_share.getSharedSecret().?;
                        switch (handshake_cipher) {
                            inline else => |*p| {
                                const P = @TypeOf(p.*).A;
                                p.transcript_hash.update(wrapped_handshake);
                                p.transcript_hash.update(client_key_exchange_prefix[tls.record_header_len..]);
                                p.transcript_hash.update(public_key_bytes);
                                const master_secret = hmacExpandLabel(P.Hmac, pre_master_secret, &.{
                                    "master secret",
                                    &client_hello_rand,
                                    &server_hello_rand,
                                }, 48);
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
                                const client_verify_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
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
                                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                                    const operand: V = pad ++ @as([8]u8, @bitCast(big(write_seq)));
                                    break :nonce @as(V, pv.app_cipher.client_write_IV ++ pv.app_cipher.client_salt) ^ operand;
                                };
                                var client_verify_msg = .{@intFromEnum(tls.ContentType.handshake)} ++
                                    int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
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
                                var all_msgs_vec: [4][]const u8 = .{
                                    &client_key_exchange_prefix,
                                    public_key_bytes,
                                    &client_change_cipher_spec_msg,
                                    &client_verify_msg,
                                };
                                try output.writeVecAll(&all_msgs_vec);
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
                                try main_cert_pub_key.verifySignature(&hsd, &.{
                                    " " ** 64 ++ "TLS 1.3, server CertificateVerify\x00",
                                    &p.transcript_hash.peek(),
                                });
                                p.transcript_hash.update(wrapped_handshake);
                            },
                        }
                        handshake_state = .finished;
                    },
                    .finished => {
                        if (cipher_state == .cleartext) return error.TlsUnexpectedMessage;
                        if (handshake_state != .finished) return error.TlsUnexpectedMessage;
                        // This message is to trick buggy proxies into behaving correctly.
                        const client_change_cipher_spec_msg = .{@intFromEnum(tls.ContentType.change_cipher_spec)} ++
                            int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
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
                                        try clientAuthMessages(&auth_buf, req, &options.client_auth.?, &p.transcript_hash)
                                    else
                                        "";
                                    const verify_data = tls.hmac(P.Hmac, &p.transcript_hash.peek(), pv.client_finished_key);
                                    const out_cleartext = .{@intFromEnum(tls.HandshakeType.finished)} ++
                                        array(u24, u8, verify_data) ++
                                        .{@intFromEnum(tls.ContentType.handshake)};

                                    const wrapped_len = out_cleartext.len + P.AEAD.tag_length;

                                    var finished_msg = .{@intFromEnum(tls.ContentType.application_data)} ++
                                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
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
    mem.writeInt(u16, buf[0..2], @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), .big);
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

const CertRequest = struct {
    context: [255]u8 = undefined,
    context_len: u8 = 0,
    /// The request's signature_algorithms list includes our key's scheme.
    scheme_ok: bool = false,
};

/// A TLS 1.3 CertificateRequest (RFC 8446 §4.3.2): the context, and
/// whether `ours` is among its signature_algorithms. The extension is
/// mandatory there; without it, or with it twice, the request is refused.
fn parseCertRequest(hsd: *tls.Decoder, ours: tls.SignatureScheme) !CertRequest {
    var req: CertRequest = .{};
    try hsd.ensure(1);
    req.context_len = hsd.decode(u8);
    try hsd.ensure(@as(usize, req.context_len) + 2);
    @memcpy(req.context[0..req.context_len], hsd.slice(req.context_len));
    const ext_len = hsd.decode(u16);
    var all_extd = try hsd.sub(ext_len);
    var seen = false;
    while (!all_extd.eof()) {
        try all_extd.ensure(4);
        const et = all_extd.decode(tls.ExtensionType);
        const size = all_extd.decode(u16);
        var extd = try all_extd.sub(size);
        if (et != .signature_algorithms) continue;
        if (seen) return error.TlsIllegalParameter;
        seen = true;
        try extd.ensure(2);
        const list_len = extd.decode(u16);
        if (list_len % 2 != 0) return error.TlsDecodeError;
        try extd.ensure(list_len);
        var i: usize = 0;
        while (i < list_len) : (i += 2) {
            if (extd.decode(tls.SignatureScheme) == ours) req.scheme_ok = true;
        }
    }
    if (!seen) return error.TlsIllegalParameter;
    return req;
}

/// The client's Certificate (and, when the request accepts our scheme, a
/// CertificateVerify) into `buf`, each mixed into `transcript` as written.
/// RFC 8446 §4.4.2.3: with no acceptable certificate the client sends an
/// empty Certificate and no CertificateVerify -- the server then decides
/// (openssl `-verify` proceeds, `-Verify` aborts with certificate_required).
fn clientAuthMessages(buf: *[max_client_auth_len]u8, req: *const CertRequest, auth: *const ClientAuth, transcript: anytype) ![]const u8 {
    var w: Writer = .fixed(buf);
    const send_chain = req.scheme_ok and auth.certificate_chain.len != 0;
    // Certificate (§4.4.2).
    var list_len: usize = 0;
    if (send_chain) for (auth.certificate_chain) |der| {
        if (der.len == 0) return error.ClientCertificateTooLarge;
        list_len += 3 + der.len + 2;
    };
    const cert_body = 1 + @as(usize, req.context_len) + 3 + list_len;
    if (4 + cert_body > buf.len) return error.ClientCertificateTooLarge;
    w.writeByte(@intFromEnum(tls.HandshakeType.certificate)) catch unreachable;
    w.writeInt(u24, @intCast(cert_body), .big) catch unreachable;
    w.writeByte(req.context_len) catch unreachable;
    w.writeAll(req.context[0..req.context_len]) catch unreachable;
    w.writeInt(u24, @intCast(list_len), .big) catch unreachable;
    if (send_chain) for (auth.certificate_chain) |der| {
        w.writeInt(u24, @intCast(der.len), .big) catch unreachable;
        w.writeAll(der) catch unreachable;
        w.writeInt(u16, 0, .big) catch unreachable; // no CertificateEntry extensions
    };
    transcript.update(w.buffered());
    if (!send_chain) return w.buffered();

    // CertificateVerify (§4.4.3): the signature covers 64 spaces, the
    // context string, a zero byte and the transcript hash through our
    // Certificate.
    const cv_start = w.end;
    const content = " " ** 64 ++ "TLS 1.3, client CertificateVerify\x00";
    var msg: [content.len + 64]u8 = undefined;
    const th = transcript.peek();
    @memcpy(msg[0..content.len], content);
    @memcpy(msg[content.len..][0..th.len], &th);
    const signed = msg[0 .. content.len + th.len];
    var sig_buf: [160]u8 = undefined;
    const sig = try signCertificateVerify(&sig_buf, auth.key, signed);
    if (w.end + 4 + 4 + sig.len > buf.len) return error.ClientCertificateTooLarge;
    w.writeByte(@intFromEnum(tls.HandshakeType.certificate_verify)) catch unreachable;
    w.writeInt(u24, @intCast(4 + sig.len), .big) catch unreachable;
    w.writeInt(u16, @intFromEnum(auth.key.scheme()), .big) catch unreachable;
    w.writeInt(u16, @intCast(sig.len), .big) catch unreachable;
    w.writeAll(sig) catch unreachable;
    transcript.update(w.buffered()[cv_start..]);
    return w.buffered();
}

/// Sign with the client key. ECDSA is RFC 6979 deterministic (no noise),
/// DER-encoded as TLS wants; Ed25519 is RFC 8032. The body runs one frame
/// down and the stack it dirtied is zeroed after it: the `secureZero`s below
/// wipe this frame's copies, but std's signers leave the key and the nonce
/// in their own frames (2026-10-09 stack probe). `pub` for
/// `stackprobe_test.zig`.
pub fn signCertificateVerify(out: *[160]u8, key: *const ClientAuth.PrivateKey, msg: []const u8) error{ClientKeyInvalid}![]const u8 {
    return burn.run(burn.sign_burn, error{ClientKeyInvalid}![]const u8, signCertificateVerifyBody, .{ out, key, msg });
}

fn signCertificateVerifyBody(out: *[160]u8, key: *const ClientAuth.PrivateKey, msg: []const u8) error{ClientKeyInvalid}![]const u8 {
    switch (key.*) {
        inline .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => |*raw, tag| {
            const E = if (tag == .ecdsa_secp256r1_sha256) crypto.sign.ecdsa.EcdsaP256Sha256 else crypto.sign.ecdsa.EcdsaP384Sha384;
            var sk = E.SecretKey.fromBytes(raw.*) catch return error.ClientKeyInvalid;
            defer crypto.secureZero(u8, mem.asBytes(&sk));
            var kp = E.KeyPair.fromSecretKey(sk) catch return error.ClientKeyInvalid;
            defer crypto.secureZero(u8, mem.asBytes(&kp));
            const sig = kp.sign(msg, null) catch return error.ClientKeyInvalid;
            var der: [E.Signature.der_encoded_length_max]u8 = undefined;
            const d = sig.toDer(&der);
            @memcpy(out[0..d.len], d);
            return out[0..d.len];
        },
        .ed25519 => |*seed| {
            var kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed.*) catch return error.ClientKeyInvalid;
            defer crypto.secureZero(u8, mem.asBytes(&kp));
            const sig = (kp.sign(msg, null) catch return error.ClientKeyInvalid).toBytes();
            @memcpy(out[0..64], &sig);
            return out[0..64];
        },
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
        inner[chunk.len] = @intFromEnum(tls.ContentType.handshake);
        const pt = inner[0 .. chunk.len + 1];
        var rec: [@as(usize, tls.record_header_len) + tls.max_ciphertext_inner_record_len + P.AEAD.tag_length]u8 = undefined;
        rec[0] = @intFromEnum(tls.ContentType.application_data);
        mem.writeInt(u16, rec[1..3], @intFromEnum(tls.ProtocolVersion.tls_1_2), .big);
        mem.writeInt(u16, rec[3..5], @intCast(pt.len + P.AEAD.tag_length), .big);
        const nonce = nonce: {
            const V = @Vector(P.AEAD.nonce_length, u8);
            const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
            const operand: V = pad ++ @as([8]u8, @bitCast(big(seq)));
            break :nonce @as(V, iv) ^ operand;
        };
        P.AEAD.encrypt(rec[5..][0..pt.len], rec[5 + pt.len ..][0..P.AEAD.tag_length], pt, rec[0..5], nonce, key);
        try output.writeAll(rec[0 .. 5 + pt.len + P.AEAD.tag_length]);
    }
    crypto.secureZero(u8, all[0..n]);
}

fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
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
    const c: *Client = @alignCast(@fieldParentPtr("writer", w));
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
    const prepared = prepareCiphertextRecord(c, ciphertext_buf, w.buffered(), .application_data);
    output.advance(prepared.ciphertext_end);
    w.end = 0;
}

/// Sends a `close_notify` alert, which is necessary for the server to
/// distinguish between a properly finished TLS session, or a truncation
/// attack.
pub fn end(c: *Client) Writer.Error!void {
    try flush(&c.writer);
    const output = c.output;
    const ciphertext_buf = try output.writableSliceGreedy(min_buffer_len);
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

                    @memcpy(cleartext_buf[0..encrypted_content_len], bytes[bytes_i..][0..encrypted_content_len]);
                    cleartext_buf[encrypted_content_len] = @intFromEnum(inner_content_type);
                    bytes_i += encrypted_content_len;
                    const ciphertext_len = encrypted_content_len + 1;
                    const cleartext = cleartext_buf[0..ciphertext_len];

                    const ad = ciphertext_buf[ciphertext_end..][0..tls.record_header_len];
                    ad.* = .{@intFromEnum(tls.ContentType.application_data)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, ciphertext_len + P.AEAD.tag_length);
                    ciphertext_end += ad.len;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..ciphertext_len];
                    ciphertext_end += ciphertext_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.AEAD.tag_length];
                    ciphertext_end += auth_tag.len;
                    const nonce = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ mem.toBytes(big(c.write_seq));
                        break :nonce @as(V, pv.client_iv) ^ operand;
                    };
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_key);
                    c.write_seq += 1; // TODO send key_update on overflow
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
                    record_header.* = .{@intFromEnum(inner_content_type)} ++
                        int(u16, @intFromEnum(tls.ProtocolVersion.tls_1_2)) ++
                        int(u16, P.record_iv_length + message_len + P.mac_length);
                    const ad = mem.toBytes(big(c.write_seq)) ++ record_header[0 .. 1 + 2] ++ int(u16, message_len);
                    const record_iv = ciphertext_buf[ciphertext_end..][0..P.record_iv_length];
                    ciphertext_end += P.record_iv_length;
                    const nonce: [P.AEAD.nonce_length]u8 = nonce: {
                        const V = @Vector(P.AEAD.nonce_length, u8);
                        const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                        const operand: V = pad ++ @as([8]u8, @bitCast(big(c.write_seq)));
                        break :nonce @as(V, pv.client_write_IV ++ pv.client_salt) ^ operand;
                    };
                    record_iv.* = nonce[P.fixed_iv_length..].*;
                    const ciphertext = ciphertext_buf[ciphertext_end..][0..message_len];
                    ciphertext_end += message_len;
                    const auth_tag = ciphertext_buf[ciphertext_end..][0..P.mac_length];
                    ciphertext_end += P.mac_length;
                    P.AEAD.encrypt(ciphertext, auth_tag, cleartext, ad, nonce, pv.client_write_key);
                    c.write_seq += 1; // TODO send key_update on overflow
                }
            },
            else => unreachable,
        },
    }
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
    const ct: tls.ContentType = @enumFromInt(record_header[0]);
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
                const ad = input.take(tls.record_header_len) catch unreachable; // already peeked
                const ciphertext_len = record_len - P.AEAD.tag_length;
                const ciphertext = input.take(ciphertext_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.AEAD.tag_length) catch unreachable).*; // already peeked
                const nonce = nonce: {
                    const V = @Vector(P.AEAD.nonce_length, u8);
                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                    const operand: V = pad ++ mem.toBytes(big(c.read_seq));
                    break :nonce @as(V, pv.server_iv) ^ operand;
                };
                rebase(r, ciphertext.len);
                const cleartext = r.buffer[r.end..][0..ciphertext.len];
                P.AEAD.decrypt(cleartext, ciphertext, auth_tag, ad, nonce, pv.server_key) catch
                    return failRead(c, error.TlsBadRecordMac);
                // TODO use scalar, non-slice version
                const msg = mem.trimEnd(u8, cleartext, "\x00");
                break :cleartext .{ msg.len - 1, @enumFromInt(msg[msg.len - 1]) };
            },
            .tls_1_2 => {
                const pv = &p.tls_1_2;
                const P = @TypeOf(p.*);
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
                    const pad = [1]u8{0} ** (P.AEAD.nonce_length - 8);
                    const operand: V = pad ++ @as([8]u8, @bitCast(big(masked_read_seq)));
                    break :nonce @as(V, pv.server_write_IV ++ record_iv) ^ operand;
                };
                const ciphertext = input.take(message_len) catch unreachable; // already peeked
                const auth_tag = (input.takeArray(P.mac_length) catch unreachable).*; // already peeked
                rebase(r, ciphertext.len);
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
                .level = @enumFromInt(cleartext[0]),
                .description = @enumFromInt(cleartext[1]),
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
                const handshake_type: tls.HandshakeType = @enumFromInt(cleartext[ct_i]);
                ct_i += 1;
                const handshake_len = mem.readInt(u24, cleartext[ct_i..][0..3], .big);
                ct_i += 3;
                const next_handshake_i = ct_i + handshake_len;
                if (next_handshake_i > cleartext.len) return failRead(c, error.TlsBadLength);
                const handshake = cleartext[ct_i..next_handshake_i];
                switch (handshake_type) {
                    .new_session_ticket => {
                        // This client implementation ignores new session tickets.
                    },
                    .key_update => {
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

                        switch (@as(tls.KeyUpdateRequest, @enumFromInt(handshake[0]))) {
                            .update_requested => {
                                switch (c.application_cipher) {
                                    inline else => |*p| {
                                        const pv = &p.tls_1_3;
                                        const P = @TypeOf(p.*);
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
                                    },
                                }
                                c.write_seq = 0;
                            },
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

fn rebase(r: *Reader, capacity: usize) void {
    if (r.buffer.len - r.end >= capacity) return;
    const data = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..data.len], data);
    r.seek = 0;
    r.end = data.len;
    assert(r.buffer.len - r.end >= capacity);
}

fn failRead(c: *Client, err: ReadError) error{ReadFailed} {
    c.read_err = err;
    return error.ReadFailed;
}

fn logSecrets(w: *Writer, context: anytype, secrets: anytype) void {
    inline for (@typeInfo(@TypeOf(secrets)).@"struct".fields) |field| w.print("{s}" ++
        (if (@hasField(@TypeOf(context), "counter")) "_{d}" else "") ++ " {x} {x}\n", .{field.name} ++
        (if (@hasField(@TypeOf(context), "counter")) .{context.counter} else .{}) ++ .{
        context.client_random,
        @field(secrets, field.name),
    }) catch {};
}

fn big(x: anytype) @TypeOf(x) {
    return switch (native_endian) {
        .big => x,
        .little => @byteSwap(x),
    };
}

const KeyShare = struct {
    ml_kem768_kp: crypto.kem.ml_kem.MLKem768.KeyPair,
    secp256r1_kp: crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    secp384r1_kp: crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,
    x25519_kp: crypto.dh.X25519.KeyPair,
    sk_buf: [sk_max_len]u8,
    sk_len: std.math.IntFittingRange(0, sk_max_len),

    const sk_max_len = @max(
        crypto.dh.X25519.shared_length + crypto.kem.ml_kem.MLKem768.shared_length,
        crypto.ecc.P256.scalar.encoded_length,
        crypto.ecc.P384.scalar.encoded_length,
        crypto.dh.X25519.shared_length,
    );

    fn init(seed: *const [176]u8) error{IdentityElement}!KeyShare {
        return .{
            .ml_kem768_kp = try .generateDeterministic(seed[0..64].*),
            .secp256r1_kp = try .generateDeterministic(seed[64..96].*),
            .secp384r1_kp = try .generateDeterministic(seed[96..144].*),
            .x25519_kp = try .generateDeterministic(seed[144..176].*),
            .sk_buf = undefined,
            .sk_len = 0,
        };
    }

    fn exchange(
        ks: *KeyShare,
        named_group: tls.NamedGroup,
        server_pub_key: []const u8,
    ) error{ TlsIllegalParameter, TlsDecryptFailure }!void {
        switch (named_group) {
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = ks.ml_kem768_kp.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
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
                const PublicKey = crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                // zig-libs tlsclient: `mul`, not std's `mulPublic` — that one is
                // variable-time ("for a *PUBLIC* scalar") and this scalar is our
                // ephemeral ECDHE secret.
                const mul = pk.p.mul(ks.secp384r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(ks.sk_buf[0..sk.len], &sk);
                ks.sk_len = sk.len;
            },
            .x25519 => {
                const ksl = crypto.dh.X25519.public_length;
                if (server_pub_key.len != ksl) return error.TlsIllegalParameter;
                const sk = crypto.dh.X25519.scalarmult(ks.x25519_kp.secret_key, server_pub_key[0..ksl].*) catch
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
        // rsa
        error{TlsBadRsaSignatureBitCount} ||
        Certificate.rsa.PublicKey.ParseDerError ||
        Certificate.rsa.PublicKey.FromBytesError ||
        Certificate.rsa.PSSSignature.VerifyError ||
        Certificate.rsa.PKCS1v1_5Signature.VerifyError ||
        // eddsa
        SchemeEddsa(.ed25519).Signature.VerifyError;

    fn verifySignature(
        cert_pub_key: *const CertificatePublicKey,
        sigd: *tls.Decoder,
        msg: []const []const u8,
    ) VerifyError!void {
        const pub_key = cert_pub_key.buf[0..cert_pub_key.len];

        try sigd.ensure(2 + 2);
        const scheme = sigd.decode(tls.SignatureScheme);
        const sig_len = sigd.decode(u16);
        try sigd.ensure(sig_len);
        const encoded_sig = sigd.slice(sig_len);

        if (cert_pub_key.algo != @as(Certificate.AlgorithmCategory, switch (scheme) {
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
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
            else => return error.TlsBadSignatureScheme,
        })) return error.TlsBadSignatureScheme;

        switch (scheme) {
            inline .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            => |comptime_scheme| {
                const Ecdsa = SchemeEcdsa(comptime_scheme);
                const sig = try Ecdsa.Signature.fromDer(encoded_sig);
                const key = try Ecdsa.PublicKey.fromSec1(pub_key);
                var ver = try sig.verifier(key);
                for (msg) |part| ver.update(part);
                try ver.verify();
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
                const RsaSignature = SchemeRsa(comptime_scheme);
                const Hash = SchemeHash(comptime_scheme);
                const PublicKey = Certificate.rsa.PublicKey;
                const components = try PublicKey.parseDer(pub_key);
                const exponent = components.exponent;
                const modulus = components.modulus;
                switch (modulus.len) {
                    inline 128, 256, 384, 512 => |modulus_len| {
                        const key: PublicKey = try .fromBytes(exponent, modulus);
                        const sig = RsaSignature.fromBytes(modulus_len, encoded_sig);
                        try RsaSignature.concatVerify(modulus_len, sig, msg, key, Hash);
                    },
                    else => return error.TlsBadRsaSignatureBitCount,
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

test "parseCertRequest: context, our scheme, mandatory signature_algorithms" {
    // context "ab"; extensions: signature_algorithms [ecdsa_secp384r1_sha384, ed25519]
    var good = "\x02ab\x00\x0a\x00\x0d\x00\x06\x00\x04\x05\x03\x08\x07".*;
    var d: tls.Decoder = .fromTheirSlice(&good);
    const r = try parseCertRequest(&d, .ed25519);
    try std.testing.expectEqualStrings("ab", r.context[0..r.context_len]);
    try std.testing.expect(r.scheme_ok);
    var good2 = good;
    d = .fromTheirSlice(&good2);
    try std.testing.expect(!(try parseCertRequest(&d, .ecdsa_secp256r1_sha256)).scheme_ok);
    // No signature_algorithms extension at all.
    var none = "\x00\x00\x04\x00\x2f\x00\x00".*;
    d = .fromTheirSlice(&none);
    try std.testing.expectError(error.TlsIllegalParameter, parseCertRequest(&d, .ed25519));
    // The extension twice.
    var twice = "\x00\x00\x10\x00\x0d\x00\x04\x00\x02\x08\x07\x00\x0d\x00\x04\x00\x02\x08\x07".*;
    d = .fromTheirSlice(&twice);
    try std.testing.expectError(error.TlsIllegalParameter, parseCertRequest(&d, .ed25519));
    // An odd list length; a truncated context.
    var odd = "\x00\x00\x07\x00\x0d\x00\x03\x00\x01\x08".*;
    d = .fromTheirSlice(&odd);
    try std.testing.expectError(error.TlsDecodeError, parseCertRequest(&d, .ed25519));
    var short = "\x05ab".*;
    d = .fromTheirSlice(&short);
    if (parseCertRequest(&d, .ed25519)) |_| return error.TestExpectedError else |_| {}
}

test "CertificateVerify: the RFC 8446 §4.4.3 content, verified with the public key" {
    // The signed bytes must be 64 spaces, the client context string, 0x00
    // and the transcript hash; an independent verifier over exactly that
    // content accepts the signature, one over the server string does not.
    var req: CertRequest = .{ .scheme_ok = true };
    req.context_len = 0;
    const seed = [_]u8{7} ** 32;
    const kp = try crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
    const key: ClientAuth.PrivateKey = .{ .ed25519 = seed };
    const auth: ClientAuth = .{ .certificate_chain = &.{"\x30\x00"}, .key = &key };
    var th = crypto.hash.sha2.Sha256.init(.{});
    th.update("transcript so far");
    var buf: [max_client_auth_len]u8 = undefined;
    const msgs = try clientAuthMessages(&buf, &req, &auth, &th);
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
    try sig.verify(" " ** 64 ++ "TLS 1.3, client CertificateVerify\x00" ++ digest, kp.public_key);
    try std.testing.expectError(error.SignatureVerificationFailed, sig.verify(" " ** 64 ++ "TLS 1.3, server CertificateVerify\x00" ++ digest, kp.public_key));
    // Without our scheme: an empty Certificate and nothing else.
    var th2 = crypto.hash.sha2.Sha256.init(.{});
    const empty = try clientAuthMessages(&buf, &CertRequest{ .scheme_ok = false }, &auth, &th2);
    try std.testing.expectEqualSlices(u8, "\x0b\x00\x00\x04\x00\x00\x00\x00", empty);
}

test "client Certificate echoes the request context (RFC 8446 §4.4.2)" {
    var req: CertRequest = .{ .scheme_ok = false, .context_len = 3 };
    @memcpy(req.context[0..3], "xyz");
    const key: ClientAuth.PrivateKey = .{ .ed25519 = [_]u8{7} ** 32 };
    const auth: ClientAuth = .{ .certificate_chain = &.{"\x30\x00"}, .key = &key };
    var th = crypto.hash.sha2.Sha256.init(.{});
    var buf: [max_client_auth_len]u8 = undefined;
    // Empty Certificate: type 0b, length 7 = 1 + 3 (context) + 3 (empty list).
    try std.testing.expectEqualSlices(u8, "\x0b\x00\x00\x07\x03xyz\x00\x00\x00", try clientAuthMessages(&buf, &req, &auth, &th));
}

test "writeHandshakeRecords: over 2^14 - 1 bytes splits into records with sequence 0, 1" {
    // Decrypted independently, record by record, with the RFC 8446 §5.3
    // per-record nonce (iv XOR big-endian sequence number).
    const A = crypto.aead.aes_gcm.Aes128Gcm;
    const P = struct {
        const AEAD = A;
    };
    const key = [_]u8{1} ** A.key_length;
    const iv = [_]u8{2} ** A.nonce_length;
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
            if (parseCertRequest(&d, .ed25519)) |req| {
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
