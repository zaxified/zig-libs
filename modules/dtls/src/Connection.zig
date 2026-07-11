// SPDX-License-Identifier: MIT

//! dtls.Connection — the public, top-level PSK-mode DTLS 1.3 client/server
//! API surface. Wires `record.zig`/`messages.zig` framing to the real
//! `keyschedule.zig`/`aead.zig` crypto core.
//!
//! **What is real here:** `Config.validate`, `clientInit`/`serverInit`, and
//! the application-data record path — `installApplicationKeys` (derive the
//! per-direction AEAD key / static IV / sequence-number key from a
//! completed handshake's traffic secrets) plus `send`/`recv`, which perform
//! RFC 9147 §4.2 AEAD record protection AND §4.2.3 sequence-number
//! encryption over the unified record header, for the two validated
//! 12-byte-nonce suites (`aes_128_gcm_sha256`, `chacha20_poly1305_sha256`).
//!
//! **What is NOT here (out of scope for this crypto-core pass):** the full
//! handshake state machine — `startHandshake` and the ClientHello/
//! ServerHello/Finished flight sequencing. All the crypto and framing
//! PRIMITIVES those need are implemented and tested (`keyschedule.zig`,
//! `messages.zig`, `handshake.zig`, `flight.zig`); assembling them into a
//! live wire handshake is deliberately left as a follow-on. `startHandshake`
//! therefore still returns `error.HandshakeEngineNotImplemented` rather than
//! pretending to drive a handshake.

const std = @import("std");
const messages = @import("messages.zig");
const keyschedule = @import("keyschedule.zig");
const aead = @import("aead.zig");
const record = @import("record.zig");

pub const Role = enum { client, server };

/// RFC 8446 §B.4 registry values. `aes_128_ccm_8_sha256` is RFC 7925 §4.2's
/// default for the CoAP/constrained-IoT profile — the suite this module's
/// intended `coap`-transport consumer cares about most.
pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    chacha20_poly1305_sha256 = 0x1303,
    aes_128_ccm_sha256 = 0x1304,
    aes_128_ccm_8_sha256 = 0x1305,
};

pub const ConfigError = error{
    EmptyPsk,
    EmptyPskIdentity,
    NoCipherSuites,
};

pub const Config = struct {
    role: Role,
    psk_identity: []const u8,
    psk: []const u8,
    /// Preference order, most-preferred first.
    cipher_suites: []const CipherSuite = &.{.aes_128_ccm_8_sha256},

    /// Real, non-crypto validation — catches obviously-broken configs
    /// before anything touches a keyschedule stub.
    pub fn validate(self: Config) ConfigError!void {
        if (self.psk.len == 0) return error.EmptyPsk;
        if (self.psk_identity.len == 0) return error.EmptyPskIdentity;
        if (self.cipher_suites.len == 0) return error.NoCipherSuites;
    }
};

pub const State = enum {
    start,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_finished,
    connected,
};

/// The DTLS 1.3 `application_data` inner content type (RFC 8446 §5.2,
/// reused unchanged). It is appended to the plaintext to form the
/// DTLSInnerPlaintext before AEAD sealing.
pub const content_type_application_data: u8 = 23;

/// Application-data epoch (RFC 9147 §4.1): epoch 3 is the first epoch after
/// the handshake completes.
pub const application_epoch: u16 = 3;

pub const HandshakeError = error{HandshakeEngineNotImplemented};

pub const SendError = error{
    NotConnected,
    UnsupportedSuite,
    BufferTooShort,
    RecordTooShort,
    DecryptionFailed,
    Malformed,
};

/// One direction's record-protection key material, derived from a traffic
/// secret by `installApplicationKeys`. Fixed-size storage (no allocator);
/// `key_len`/`sn_len` record how much is live for the negotiated suite.
const DirKeys = struct {
    key: [32]u8 = undefined,
    key_len: u8 = 0,
    iv: [12]u8 = undefined,
    sn_key: [32]u8 = undefined,
    sn_len: u8 = 0,
};

pub const Connection = struct {
    role: Role,
    config: Config,
    state: State = .start,
    /// RFC 9147 §5.2's handshake-message counter (independent of the
    /// record layer's sequence number).
    message_seq: u16 = 0,
    /// Current epoch (RFC 9147 §4.1); starts at 0 (the unencrypted flight).
    epoch: u16 = 0,

    // ── application-data record state (post-handshake) ──────────────────
    suite: CipherSuite = .aes_128_ccm_8_sha256,
    write_keys: DirKeys = .{},
    read_keys: DirKeys = .{},
    /// Next record sequence number to send in the application epoch.
    send_seq: u48 = 0,
    /// Highest sequence number successfully deprotected (for §4.2.2/§4.3
    /// reconstruction).
    recv_max_seq: u48 = 0,
    recv_seen_any: bool = false,

    pub const InitError = ConfigError;

    pub fn clientInit(config: Config) InitError!Connection {
        try config.validate();
        return .{ .role = .client, .config = config };
    }

    pub fn serverInit(config: Config) InitError!Connection {
        try config.validate();
        return .{ .role = .server, .config = config };
    }

    /// Out of scope for the crypto-core pass: the full handshake flight
    /// engine. Every primitive it needs (PSK binder, key schedule, message
    /// framing, fragmentation, flights/ACKs) is implemented and tested in
    /// the sibling files; assembling them into a live wire handshake is a
    /// follow-on. Returns a typed error rather than panicking or faking it.
    pub fn startHandshake(self: *Connection, out: []u8) HandshakeError![]const u8 {
        std.debug.assert(self.role == .client);
        _ = out;
        return error.HandshakeEngineNotImplemented;
    }

    /// Installs the negotiated suite's application-data record-protection
    /// keys from a completed handshake's client/server application traffic
    /// secrets (RFC 8446 §7.3 key/iv + RFC 9147 §4.2.3 sn), and marks the
    /// connection `connected`. `client_ap_secret`/`server_ap_secret` are the
    /// outputs of `keyschedule.deriveApplicationTrafficSecrets`. All four
    /// supported suites use SHA-256, so the schedule uses `HkdfSha256`.
    ///
    /// The client WRITES with the client secret and READS with the server's
    /// (and vice-versa for the server), so one call wires both directions
    /// correctly for either role.
    pub fn installApplicationKeys(
        self: *Connection,
        suite: CipherSuite,
        client_ap_secret: [32]u8,
        server_ap_secret: [32]u8,
    ) SendError!void {
        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const params = suiteParams(suite) orelse return error.UnsupportedSuite;

        const my_secret = if (self.role == .client) client_ap_secret else server_ap_secret;
        const peer_secret = if (self.role == .client) server_ap_secret else client_ap_secret;

        self.write_keys = deriveDir(Hkdf, params, my_secret);
        self.read_keys = deriveDir(Hkdf, params, peer_secret);
        self.suite = suite;
        self.epoch = application_epoch;
        self.send_seq = 0;
        self.recv_max_seq = 0;
        self.recv_seen_any = false;
        self.state = .connected;
    }

    /// Protects `plaintext` as an application_data record (RFC 9147 §4.2):
    /// builds the DTLSInnerPlaintext (`plaintext || content_type=23`), AEAD-
    /// seals it with the connection's write key over the unified record
    /// header as additional data, then encrypts the header's sequence number
    /// (RFC 9147 §4.2.3). Returns `header || protected_record` written into
    /// `out`. Advances the send sequence number.
    pub fn send(self: *Connection, plaintext: []const u8, out: []u8) SendError![]const u8 {
        if (self.state != .connected) return error.NotConnected;
        const params = suiteParams(self.suite) orelse return error.UnsupportedSuite;

        // DTLSInnerPlaintext = content || content_type (no extra padding).
        var inner_buf: [1500]u8 = undefined;
        if (plaintext.len + 1 > inner_buf.len) return error.BufferTooShort;
        @memcpy(inner_buf[0..plaintext.len], plaintext);
        inner_buf[plaintext.len] = content_type_application_data;
        const inner = inner_buf[0 .. plaintext.len + 1];

        const ct_len = inner.len + params.tag_len;
        const seq_len: record.SeqNumLen = if (self.send_seq <= 0xff) .short else .long;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;

        // Encode the header with the PLAINTEXT sequence number — this is the
        // AEAD additional_data (RFC 9147 §4.2.1: header prior to sn encrypt).
        const hdr = record.UnifiedHeader{
            .epoch_low = @truncate(self.epoch),
            .seq_len = seq_len,
            .seq_wire = @truncate(self.send_seq),
            .cid = null,
            .length = @intCast(ct_len),
        };
        const hdr_slice = record.encodeUnified(hdr, out) catch return error.BufferTooShort;
        const hdr_len = hdr_slice.len;
        if (out.len < hdr_len + ct_len) return error.BufferTooShort;

        const n = protectDispatch(self.suite, self.write_keys, self.epoch, self.send_seq, inner, out[0..hdr_len], out[hdr_len..]) catch
            return error.BufferTooShort;
        std.debug.assert(n == ct_len);

        // RFC 9147 §4.2.3: encrypt the on-wire sequence number using a
        // 16-byte sample of the record ciphertext. The seq bytes follow the
        // 1-byte flags (and CID, if any) — here no CID, so offset 1.
        const seq_off: usize = 1;
        try snMaskDispatch(self.suite, self.write_keys, out[hdr_len..][0..16], out[seq_off..][0..seq_bytes_n]);

        self.send_seq +%= 1;
        return out[0 .. hdr_len + ct_len];
    }

    /// Un-protects an incoming datagram back into application data (the
    /// mirror of `send`): decrypts the header sequence number, reconstructs
    /// the full 48-bit value, AEAD-opens the record over the recovered
    /// header, and strips the trailing content type. Returns the recovered
    /// application bytes written into `out`. A tag mismatch or malformed
    /// record is a typed error — never a panic.
    pub fn recv(self: *Connection, datagram: []const u8, out: []u8) SendError![]const u8 {
        if (self.state != .connected) return error.NotConnected;

        const dec = record.decodeUnified(datagram, 0) catch return error.Malformed;
        const seq_len = dec.hdr.seq_len;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;
        const hdr_len = dec.consumed;
        // Sequence number follows the 1-byte flags (+ CID, if any).
        const seq_off: usize = if (dec.hdr.cid) |c| 1 + c.len else 1;

        // The ciphertext is the explicit length, or the rest of the datagram.
        const ct = if (dec.hdr.length) |l| blk: {
            if (datagram.len < hdr_len + l) return error.Malformed;
            break :blk datagram[hdr_len..][0..l];
        } else datagram[hdr_len..];
        if (ct.len < 16) return error.RecordTooShort;

        // Copy the header into a working buffer so we can un-mask the seq
        // number in place: the AEAD additional_data is the header with the
        // PLAINTEXT sequence number (RFC 9147 §4.2.1).
        var hdr_buf: [16]u8 = undefined;
        if (hdr_len > hdr_buf.len) return error.Malformed;
        @memcpy(hdr_buf[0..hdr_len], datagram[0..hdr_len]);
        try snMaskDispatch(self.suite, self.read_keys, ct[0..16], hdr_buf[seq_off..][0..seq_bytes_n]);

        const wire_low: u16 = if (seq_len == .short)
            hdr_buf[seq_off]
        else
            std.mem.readInt(u16, hdr_buf[seq_off..][0..2], .big);
        const largest = if (self.recv_seen_any) self.recv_max_seq else 0;
        const full_seq = record.reconstructSequenceNumber(largest, seq_len, wire_low);

        const body_len = unprotectDispatch(self.suite, self.read_keys, self.epoch, full_seq, ct, hdr_buf[0..hdr_len], out) catch
            return error.DecryptionFailed;
        if (body_len == 0) return error.Malformed; // must hold at least the content type

        // Strip trailing zero padding, then the content-type byte
        // (RFC 8446 §5.2 DTLSInnerPlaintext).
        var end = body_len;
        while (end > 0 and out[end - 1] == 0) end -= 1;
        if (end == 0) return error.Malformed;
        const ctype = out[end - 1];
        if (ctype != content_type_application_data) return error.Malformed;

        if (!self.recv_seen_any or full_seq > self.recv_max_seq) {
            self.recv_max_seq = full_seq;
            self.recv_seen_any = true;
        }
        return out[0 .. end - 1];
    }

    pub fn deinit(self: *Connection) void {
        self.write_keys = .{};
        self.read_keys = .{};
    }
};

// ── suite dispatch (runtime CipherSuite -> comptime AEAD/sn primitives) ──

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

const SuiteParams = struct { key_len: u8, sn_len: u8, tag_len: u8, is_chacha: bool };

/// Returns the record-layer parameters for the suites whose 12-byte-nonce
/// AEAD is validated here, or `null` for suites this pass does not wire
/// (the CCM suites — std ships only a 13-byte-nonce CCM; see aead.zig).
fn suiteParams(suite: CipherSuite) ?SuiteParams {
    return switch (suite) {
        .aes_128_gcm_sha256 => .{ .key_len = 16, .sn_len = 16, .tag_len = 16, .is_chacha = false },
        .chacha20_poly1305_sha256 => .{ .key_len = 32, .sn_len = 32, .tag_len = 16, .is_chacha = true },
        .aes_128_ccm_sha256, .aes_128_ccm_8_sha256 => null,
    };
}

fn deriveDir(comptime Hkdf: type, params: SuiteParams, secret: [32]u8) DirKeys {
    var d = DirKeys{ .key_len = params.key_len, .sn_len = params.sn_len };
    // Derive each of key + sn at the negotiated width (HKDF-Expand-Label's
    // length is part of its input, so a 16-byte "key" is NOT a prefix of a
    // 32-byte one — it must be expanded at the exact suite width).
    d.iv = keyschedule.deriveTrafficKeyIv(Hkdf, 16, 12, secret).iv; // iv width is suite-independent (12)
    switch (params.key_len) {
        16 => @memcpy(d.key[0..16], &keyschedule.deriveTrafficKeyIv(Hkdf, 16, 12, secret).key),
        32 => @memcpy(d.key[0..32], &keyschedule.deriveTrafficKeyIv(Hkdf, 32, 12, secret).key),
        else => unreachable,
    }
    switch (params.sn_len) {
        16 => @memcpy(d.sn_key[0..16], &keyschedule.deriveSequenceNumberKey(Hkdf, 16, secret)),
        32 => @memcpy(d.sn_key[0..32], &keyschedule.deriveSequenceNumberKey(Hkdf, 32, secret)),
        else => unreachable,
    }
    return d;
}

fn protectDispatch(
    suite: CipherSuite,
    keys: DirKeys,
    epoch: u16,
    seq: u48,
    inner: []const u8,
    aad: []const u8,
    out: []u8,
) !usize {
    return switch (suite) {
        .aes_128_gcm_sha256 => aead.Protection(Aes128Gcm).protect(keys.key[0..16].*, keys.iv, epoch, seq, inner, aad, out),
        .chacha20_poly1305_sha256 => aead.Protection(ChaCha20Poly1305).protect(keys.key[0..32].*, keys.iv, epoch, seq, inner, aad, out),
        else => error.UnsupportedSuite,
    };
}

fn unprotectDispatch(
    suite: CipherSuite,
    keys: DirKeys,
    epoch: u16,
    seq: u48,
    ct: []const u8,
    aad: []const u8,
    out: []u8,
) !usize {
    return switch (suite) {
        .aes_128_gcm_sha256 => aead.Protection(Aes128Gcm).unprotect(keys.key[0..16].*, keys.iv, epoch, seq, ct, aad, out),
        .chacha20_poly1305_sha256 => aead.Protection(ChaCha20Poly1305).unprotect(keys.key[0..32].*, keys.iv, epoch, seq, ct, aad, out),
        else => error.UnsupportedSuite,
    };
}

fn snMaskDispatch(suite: CipherSuite, keys: DirKeys, sample: []const u8, seq_bytes: []u8) !void {
    return switch (suite) {
        .aes_128_gcm_sha256 => aead.encryptSequenceNumberAes(keys.sn_key[0..16], sample, seq_bytes),
        .chacha20_poly1305_sha256 => aead.encryptSequenceNumberChaCha20(keys.sn_key[0..32], sample, seq_bytes),
        else => error.UnsupportedSuite,
    };
}

// ── tests: validation-only — must never call into crypto stubs ──────────

const testing = std.testing;

test "Config.validate: rejects empty PSK" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = &.{} };
    try testing.expectError(error.EmptyPsk, cfg.validate());
}

test "Config.validate: rejects empty PSK identity" {
    const cfg = Config{ .role = .client, .psk_identity = &.{}, .psk = "secret" };
    try testing.expectError(error.EmptyPskIdentity, cfg.validate());
}

test "Config.validate: rejects an empty cipher-suite list" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret", .cipher_suites = &.{} };
    try testing.expectError(error.NoCipherSuites, cfg.validate());
}

test "Config.validate: accepts a sane config" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    try cfg.validate();
}

test "clientInit/serverInit: real, validated, non-panicking construction" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "s3cr3t" };
    var client = try Connection.clientInit(cfg);
    try testing.expectEqual(Role.client, client.role);
    try testing.expectEqual(State.start, client.state);
    client.deinit();

    var server = try Connection.serverInit(cfg);
    try testing.expectEqual(Role.server, server.role);
    server.deinit();
}

test "clientInit: propagates Config validation errors" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = &.{} };
    try testing.expectError(error.EmptyPsk, Connection.clientInit(cfg));
}

test "send/recv: real guard rejects use before the handshake completes" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var conn = try Connection.clientInit(cfg);
    var out: [64]u8 = undefined;
    try testing.expectError(error.NotConnected, conn.send("hi", &out));
    try testing.expectError(error.NotConnected, conn.recv("datagram", &out));
}

test "startHandshake: honest typed error (full handshake engine out of scope)" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var conn = try Connection.clientInit(cfg);
    var out: [1500]u8 = undefined;
    try testing.expectError(error.HandshakeEngineNotImplemented, conn.startHandshake(&out));
}

// ── end-to-end record-layer self-consistency (both validated suites) ────
//
// Simulates a COMPLETED handshake by deriving matching application traffic
// secrets on both endpoints (identical PSK + identical transcript => same
// schedule) and installing them, then proves the real send/recv record path:
// client.send -> server.recv round-trips, sequence numbers advance and are
// encrypted on the wire, and any tamper is rejected without a panic.

fn deriveApSecrets(psk: []const u8) struct { c: [32]u8, s: [32]u8 } {
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const Sha256 = std.crypto.hash.sha2.Sha256;
    var empty: [32]u8 = undefined;
    Sha256.hash("", &empty, .{});
    var th: [32]u8 = undefined;
    Sha256.hash("dtls self-consistency transcript through server Finished", &th, .{});

    const es = keyschedule.earlySecret(Hkdf, psk);
    const hs = keyschedule.deriveHandshakeSecret(Hkdf, es, &empty, null);
    const ms = keyschedule.deriveMasterSecret(Hkdf, hs, &empty);
    const ap = keyschedule.deriveApplicationTrafficSecrets(Hkdf, ms, &th);
    return .{ .c = ap.client, .s = ap.server };
}

fn roundtripSuite(suite: CipherSuite) !void {
    const cfg = Config{ .role = .client, .psk_identity = "device-042", .psk = "a-shared-pre-shared-key" };
    var client = try Connection.clientInit(cfg);
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = cfg.psk_identity, .psk = cfg.psk });

    const ap = deriveApSecrets(cfg.psk);
    try client.installApplicationKeys(suite, ap.c, ap.s);
    try server.installApplicationKeys(suite, ap.c, ap.s);
    try testing.expectEqual(State.connected, client.state);

    // Both endpoints must have derived identical directional keys
    // (client write == server read, and vice versa).
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server.read_keys.iv);

    // Two application records from client -> server, seq numbers advancing.
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;

    const msg1 = "hello over DTLS 1.3 PSK";
    const rec1 = try client.send(msg1, &wire);
    try testing.expectEqual(@as(u48, 1), client.send_seq);
    const got1 = try server.recv(rec1, &plain);
    try testing.expectEqualSlices(u8, msg1, got1);

    const msg2 = "second record, seq=1";
    var wire2: [256]u8 = undefined;
    const rec2 = try client.send(msg2, &wire2);
    const got2 = try server.recv(rec2, &plain);
    try testing.expectEqualSlices(u8, msg2, got2);

    // The wire sequence number is ENCRYPTED (RFC 9147 §4.2.3): the on-wire
    // seq byte for record 1 must not equal the plaintext value (1). The seq
    // byte is the last header byte before the ciphertext; header is 1 byte
    // flags + 1 seq byte + 2 length bytes = seq at offset 1 for a short seq.
    try testing.expect(rec1[1] != 0x00); // masked, not the plaintext 0

    // Reverse direction: server -> client.
    var wire3: [256]u8 = undefined;
    const srv_msg = "ack from server";
    const rec3 = try server.send(srv_msg, &wire3);
    const got3 = try client.recv(rec3, &plain);
    try testing.expectEqualSlices(u8, srv_msg, got3);

    // Tamper: flip a ciphertext byte -> DecryptionFailed, never a panic.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..rec1.len], rec1);
    tampered[rec1.len - 1] ^= 0x80; // flip the last tag byte of the record
    // recv advances state, so use a fresh server for a clean seq window.
    var server2 = try Connection.serverInit(.{ .role = .server, .psk_identity = cfg.psk_identity, .psk = cfg.psk });
    try server2.installApplicationKeys(suite, ap.c, ap.s);
    try testing.expectError(error.DecryptionFailed, server2.recv(tampered[0..rec1.len], &plain));
}

test "record round-trip self-consistency: AES-128-GCM" {
    try roundtripSuite(.aes_128_gcm_sha256);
}

test "record round-trip self-consistency: ChaCha20-Poly1305" {
    try roundtripSuite(.chacha20_poly1305_sha256);
}

test "installApplicationKeys: CCM suites are honestly rejected (std nonce gap)" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var conn = try Connection.clientInit(cfg);
    const ap = deriveApSecrets(cfg.psk);
    try testing.expectError(error.UnsupportedSuite, conn.installApplicationKeys(.aes_128_ccm_8_sha256, ap.c, ap.s));
}
