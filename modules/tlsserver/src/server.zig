// SPDX-License-Identifier: MIT

//! tlsserver.server — the sans-I/O TLS 1.3 server: a full (EC)DHE handshake
//! with a certificate (RFC 8446 §2, Figure 1), then application data.
//!
//! The caller owns the I/O. It hands received octets to `feed`, which says
//! how many it is done with and what happened; whatever the server wants to
//! send accumulates in `pendingOutput` until the caller writes it out and
//! `discardOutput`s it. Two buffers come from the caller: the handshake
//! joiner (`inbound.Joiner.bufferLen`) and the output buffer, which must
//! hold the server's whole first flight (`minOutputLen`).
//!
//! Negotiation follows rustls 0.23 (the scope reference):
//!
//! - **version** TLS 1.3 only — no `supported_versions` with 0x0304 is
//!   `protocol_version`, checked before anything else;
//! - **certificate** fixed, or chosen by a callback from the SNI and the
//!   ClientHello (none chosen: `access_denied`); the signature scheme is
//!   the key's first candidate the client offers and the key can produce
//!   (`certverify.canSign`: a 1024-bit RSA key has no `rsa_pss_rsae_sha512`;
//!   `handshake_failure` if none, or no `signature_algorithms` at all);
//! - **cipher suite** the client's first that the server enables;
//! - **group** the client's first `supported_groups` entry the server
//!   enables (no `supported_groups` or no `key_share` at all is
//!   `missing_extension`, RFC 8446 §9.2), and the client must have sent a
//!   share for it — the
//!   HelloRetryRequest that would ask for one comes with M2, so for now it
//!   is `handshake_failure`;
//! - **ALPN** the server's first protocol the client offers; none in
//!   common while the server has some is `no_application_protocol`;
//! - a compatibility `change_cipher_spec` follows the ServerHello; the
//!   EncryptedExtensions acknowledge a DNS-name SNI with an empty
//!   `server_name` and carry the ALPN choice; an OCSP response is stapled
//!   to the leaf if the client asked for one.
//!
//! Not yet (later milestones): HelloRetryRequest, PSK resumption and
//! NewSessionTicket, client certificates, KeyUpdate. A pre_shared_key offer
//! is ignored (full handshake); early data is never accepted and is skipped
//! (`inbound.Inbound.skip_early`).

const std = @import("std");
const tls13 = @import("tls13");
const record = @import("record.zig");
const alert = @import("alert.zig");
const inbound = @import("inbound.zig");
const outbound = @import("outbound.zig");
const hello = @import("hello.zig");
const messages = @import("messages.zig");
const burn = @import("burn.zig");

const certverify = tls13.certverify;
const kex = tls13.kex;
const ks = tls13.keyschedule.tls13;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;

/// A certificate chain (DER, leaf first) and the leaf's signing key.
pub const CertifiedKey = struct {
    chain: []const []const u8,
    /// Borrowed (`certverify.SecretKey` holds pointers): must outlive the
    /// connections that use it.
    key: certverify.SecretKey,
    /// A DER OCSPResponse to staple when the client asks (RFC 8446 §4.4.2.1).
    ocsp_response: ?[]const u8 = null,
};

/// Chooses the certificate for a ClientHello. `sni` is the requested DNS
/// name (null when the client sent none or an IP literal); `ch` is valid
/// only during the call. Null refuses the connection (`access_denied`).
pub const CertificateSelector = struct {
    ctx: ?*anyopaque = null,
    select: *const fn (ctx: ?*anyopaque, sni: ?[]const u8, ch: *const hello.ClientHello) ?*const CertifiedKey,
};

pub const Config = struct {
    certificate: union(enum) {
        fixed: *const CertifiedKey,
        select: CertificateSelector,
    },
    /// The suites the server enables (the client's order decides).
    cipher_suites: []const record.CipherSuite = &default_cipher_suites,
    /// The groups the server enables (the client's order decides).
    groups: []const u16 = &default_groups,
    /// In the server's order of preference.
    alpn_protocols: []const []const u8 = &.{},
    /// MUST be a cryptographically secure source: it draws the server
    /// random, the ephemeral key-exchange secret and signing randomness.
    random: std.Random,
};

/// Records sealed under one send key before the connection must stop
/// (RFC 8446 §5.5: AES-GCM's limit is 2^24.5 full records; qap rekeys at
/// 2^23, which is the bound here until KeyUpdate arrives in M2).
pub const max_records_per_key: u64 = 1 << 23;

pub const default_cipher_suites = [_]record.CipherSuite{ .aes_256_gcm_sha384, .aes_128_gcm_sha256, .chacha20_poly1305_sha256 };
pub const default_groups = [_]u16{ kex.x25519_mlkem768_group, kex.x25519_group, kex.secp256r1_group, kex.secp384r1_group };

pub const Error = inbound.Error || error{
    HandshakeFailure,
    ProtocolVersion,
    MissingExtension,
    DecryptError,
    AccessDenied,
    NoApplicationProtocol,
    /// A certificate or signature the server cannot encode or produce (a
    /// configuration problem), or a signing fault.
    InternalError,
    /// The output buffer cannot take the records: drain it, or size it
    /// with `minOutputLen`.
    OutputFull,
    /// The connection failed or was closed; nothing more can be done.
    Closed,
    /// Application data before the handshake completed.
    NotConnected,
    /// The send key sealed `max_records_per_key` records and there is no
    /// KeyUpdate yet (M2): the connection ends with close_notify.
    KeyLimitReached,
};

/// The alert a failure sends (null: none — the peer aborted, or the
/// output is the problem).
pub fn alertFor(err: Error) ?alert.Description {
    return switch (err) {
        error.HandshakeFailure => .handshake_failure,
        error.ProtocolVersion => .protocol_version,
        error.MissingExtension => .missing_extension,
        error.DecryptError => .decrypt_error,
        error.AccessDenied => .access_denied,
        error.NoApplicationProtocol => .no_application_protocol,
        error.InternalError => .internal_error,
        error.OutputFull, error.Closed, error.NotConnected => null,
        // Not the peer's fault, and no alert names it: close politely.
        error.KeyLimitReached => .close_notify,
        else => |e| inbound.alertFor(@errorCast(e)),
    };
}

/// An output buffer that holds the first flight for `ck`: ServerHello
/// (with the largest share), CCS, EncryptedExtensions (ALPN), the chain
/// with an OCSP staple, CertificateVerify, Finished, each record's
/// overhead, plus one alert.
pub fn minOutputLen(ck: *const CertifiedKey) usize {
    var chain: usize = 3;
    for (ck.chain) |c| chain += 3 + c.len + 2;
    if (ck.ocsp_response) |o| chain += 4 + 4 + o.len;
    const sig = for (certverify.candidateSchemes(ck.key)) |s| {
        break certverify.maxSignatureLen(s);
    } else 0;
    const flight = (4 + 2 + 32 + 33 + 3 + 2 + 8 + kex.hybrid_server_share_len + 6) + // ServerHello
        6 + // CCS
        (4 + 2 + 4 + 2 + 1 + 255 + 4) + // EncryptedExtensions
        (4 + 1 + chain) + (4 + 4 + sig) + (4 + 48);
    const records = flight / record.max_plaintext_len + 6;
    return flight + records * (record.header_len + 1 + record.tag_len) + 64;
}

pub const Event = union(enum) {
    /// Everything buffered was used: read more and feed again.
    need_more,
    /// The client's Finished verified: the connection is up.
    handshake_done,
    /// Application data, a slice of the buffer given to `feed` (inside
    /// `consumed`: use it before discarding those octets).
    app_data: []u8,
    /// The client sent close_notify. It may still be written to.
    peer_closed,
};

pub const Result = struct {
    event: Event,
    consumed: usize,
};

const State = enum { client_hello, client_finished, connected, failed };

const Transcript = union(enum) {
    sha256: tls13.transcript.Transcript(Sha256),
    sha384: tls13.transcript.Transcript(Sha384),
};

fn HashSuite(comptime H: type, comptime M: type) type {
    return struct {
        const Hash = H;
        const Hmac = M;
        const Hkdf = std.crypto.kdf.hkdf.Hkdf(M);
        const len = H.digest_length;

        fn transcript(t: *Transcript) *tls13.transcript.Transcript(H) {
            return if (H == Sha256) &t.sha256 else &t.sha384;
        }
    };
}
const S256 = HashSuite(Sha256, HmacSha256);
const S384 = HashSuite(Sha384, HmacSha384);

pub const Server = struct {
    config: *const Config,
    inbound: inbound.Inbound,
    out: outbound.Outbound,
    state: State = .client_hello,
    suite: record.CipherSuite = undefined,
    /// `suite` has been chosen (the ClientHello got that far).
    has_suite: bool = false,
    /// close_notify sent: no more writes, reading goes on.
    write_closed: bool = false,
    transcript: Transcript = undefined,
    /// Secrets of the schedule, `suite.hashLen()` octets each. The
    /// handshake ones are wiped once the client's Finished is verified.
    handshake_secret: [48]u8 = @splat(0),
    client_handshake_secret: [48]u8 = @splat(0),
    master_secret: [48]u8 = @splat(0),
    client_application_secret: [48]u8 = @splat(0),
    server_application_secret: [48]u8 = @splat(0),
    /// The negotiated ALPN protocol (one of `config.alpn_protocols`).
    alpn: ?[]const u8 = null,
    /// The negotiated key-exchange group (0: not chosen yet).
    group: u16 = 0,
    sni_buf: [253]u8 = undefined,
    sni_len: ?u8 = null,
    peer_closed: bool = false,

    pub fn init(config: *const Config, joiner_buf: []u8, output_buf: []u8) Server {
        return .{
            .config = config,
            .inbound = .init(joiner_buf),
            .out = .init(output_buf),
        };
    }

    /// Wipe every secret and both buffers.
    pub fn deinit(self: *Server) void {
        self.inbound.wipe();
        self.out.wipe();
        self.wipeHandshakeSecrets();
        std.crypto.secureZero(u8, &self.master_secret);
        std.crypto.secureZero(u8, &self.client_application_secret);
        std.crypto.secureZero(u8, &self.server_application_secret);
        self.state = .failed;
    }

    fn wipeHandshakeSecrets(self: *Server) void {
        std.crypto.secureZero(u8, &self.handshake_secret);
        std.crypto.secureZero(u8, &self.client_handshake_secret);
    }

    pub fn isConnected(self: *const Server) bool {
        return self.state == .connected;
    }

    /// The DNS name the client asked for, if any (valid while `self` is).
    pub fn serverName(self: *const Server) ?[]const u8 {
        return if (self.sni_len) |n| self.sni_buf[0..n] else null;
    }

    pub fn cipherSuite(self: *const Server) ?record.CipherSuite {
        return if (self.has_suite) self.suite else null;
    }

    /// The key-exchange group of the handshake (IANA code point), once the
    /// ClientHello was accepted.
    pub fn negotiatedGroup(self: *const Server) ?u16 {
        return if (self.group != 0) self.group else null;
    }

    /// The ALPN protocol chosen (one of `Config.alpn_protocols`), if any.
    pub fn alpnProtocol(self: *const Server) ?[]const u8 {
        return self.alpn;
    }

    pub fn pendingOutput(self: *const Server) []const u8 {
        return self.out.pending();
    }

    pub fn discardOutput(self: *Server, n: usize) void {
        self.out.discard(n);
    }

    /// Process received octets (`buf`: everything received and not yet
    /// consumed) up to the next event. On an error the connection is dead:
    /// the alert it calls for (if any) is already in `pendingOutput` —
    /// send it, then close.
    pub fn feed(self: *Server, buf: []u8) Error!Result {
        if (self.state == .failed) return error.Closed;
        var at: usize = 0;
        while (true) {
            const r = self.inbound.next(buf[at..]) catch |err| return self.fail(err);
            at += r.consumed;
            switch (r.event) {
                .need_more => return .{ .event = .need_more, .consumed = at },
                .app_data => |d| return .{ .event = .{ .app_data = d }, .consumed = at },
                .peer_closed => {
                    self.peer_closed = true;
                    return .{ .event = .peer_closed, .consumed = at };
                },
                .handshake => |m| {
                    const done = self.onHandshake(m) catch |err| return self.fail(err);
                    if (done) return .{ .event = .handshake_done, .consumed = at };
                },
            }
        }
    }

    /// Seal application data into the output, as much as fits (at least
    /// one octet unless the output is full). Returns how much was taken.
    pub fn write(self: *Server, data: []const u8) Error!usize {
        switch (self.state) {
            .connected => {},
            .failed => return error.Closed,
            else => return error.NotConnected,
        }
        if (self.write_closed) return error.Closed;
        // RFC 8446 §5.5: an AEAD key must be retired well before its usage
        // limit. Until KeyUpdate exists (M2) the connection ends instead.
        if (self.out.tx.seq >= max_records_per_key) return self.fail(error.KeyLimitReached);
        var done: usize = 0;
        while (done < data.len) {
            const s = self.out.slot();
            if (s.len == 0) break;
            const n = @min(s.len, data.len - done, record.max_plaintext_len);
            @memcpy(s[0..n], data[done..][0..n]);
            self.out.commit(.application_data, n) catch |err| return self.fail(err);
            done += n;
        }
        if (done == 0 and data.len != 0) return error.OutputFull;
        return done;
    }

    /// Queue close_notify. Nothing more can be written afterwards; the
    /// client's remaining data and its close_notify can still be read.
    pub fn close(self: *Server) Error!void {
        if (self.state == .failed or self.write_closed) return error.Closed;
        self.out.write(.alert, &alert.Alert.close_notify.encode()) catch {};
        self.write_closed = true;
        self.out.wipeKey();
    }

    /// Queue the error's alert, then wipe every key and secret (the queued
    /// records stay for the caller to send).
    fn fail(self: *Server, err: anyerror) Error {
        const e: Error = @errorCast(err);
        if (self.state != .failed) {
            if (!self.write_closed) if (alertFor(e)) |d| {
                const a: alert.Alert = if (d == .close_notify) .close_notify else .fatal(d);
                self.out.write(.alert, &a.encode()) catch {};
            };
            self.state = .failed;
            self.out.wipeKey();
            self.inbound.wipe();
            self.wipeHandshakeSecrets();
            std.crypto.secureZero(u8, &self.master_secret);
            std.crypto.secureZero(u8, &self.client_application_secret);
            std.crypto.secureZero(u8, &self.server_application_secret);
        }
        return e;
    }

    fn onHandshake(self: *Server, m: inbound.HandshakeMessage) Error!bool {
        const t: messages.HandshakeType = @fromBackingInt(m.msg_type);
        switch (self.state) {
            .client_hello => {
                if (t != .client_hello) return error.UnexpectedMessage;
                try burn.run(burn.handshake_burn, Error!void, onClientHello, .{ self, m });
                return false;
            },
            .client_finished => {
                if (t != .finished) return error.UnexpectedMessage;
                try burn.run(burn.handshake_burn, Error!void, onClientFinished, .{ self, m });
                return true;
            },
            // Post-handshake messages (KeyUpdate, M2) are not handled yet.
            .connected => return error.UnexpectedMessage,
            .failed => unreachable,
        }
    }

    fn onClientHello(self: *Server, m: inbound.HandshakeMessage) Error!void {
        const cfg = self.config;
        const ch = hello.parseClientHello(m.body) catch |err| return switch (err) {
            error.DecodeError => error.DecodeError,
            error.IllegalParameter => error.IllegalParameter,
        };
        if (std.mem.indexOfScalar(u8, ch.legacy_compression_methods, 0) == null) return error.IllegalParameter;
        var sni: ?[]const u8 = null;
        if (ch.server_name) |sn| switch (sn) {
            .dns_name => |n| sni = n,
            .ip_address => {},
            .invalid => return error.IllegalParameter,
        };
        // The version first: a TLS 1.2 (or older) client gets
        // `protocol_version` whatever else its hello lacks (rustls order).
        const versions = ch.supportedVersions() orelse return error.ProtocolVersion;
        if (!versions.contains(messages.tls13_version)) return error.ProtocolVersion;
        const sig_algs = ch.signatureAlgorithms() orelse return error.HandshakeFailure;

        const ck: *const CertifiedKey = switch (cfg.certificate) {
            .fixed => |k| k,
            .select => |s| s.select(s.ctx, sni, &ch) orelse return error.AccessDenied,
        };
        const scheme = for (certverify.candidateSchemes(ck.key)) |s| {
            if (sig_algs.contains(@backingInt(s)) and certverify.canSign(ck.key, s)) break s;
        } else return error.HandshakeFailure;

        var cs = ch.cipherSuites();
        const suite: record.CipherSuite = while (cs.next()) |c| {
            const cand: record.CipherSuite = @fromBackingInt(c);
            if (cand.hashLen() != null and std.mem.indexOfScalar(record.CipherSuite, cfg.cipher_suites, cand) != null) break cand;
        } else return error.HandshakeFailure;
        // RFC 8446 §9.2: supported_groups and key_share come together.
        var gs = ch.supportedGroups() orelse return error.MissingExtension;
        const group: u16 = while (gs.next()) |g| {
            if (std.mem.indexOfScalar(u16, cfg.groups, g) != null) break g;
        } else return error.HandshakeFailure;

        if (ch.legacy_compression_methods.len != 1) return error.IllegalParameter;
        var shares = ch.keyShares() orelse return error.MissingExtension;
        var seen: std.StaticBitSet(1 << 16) = .empty;
        var share: ?[]const u8 = null;
        while (shares.next()) |e| {
            if (seen.isSet(e.group)) return error.IllegalParameter;
            seen.set(e.group);
            if (e.group == group) share = e.key_exchange;
        }
        // M2: a HelloRetryRequest for `group`.
        const client_share = share orelse return error.HandshakeFailure;
        if (ch.pre_shared_key != null and ch.psk_key_exchange_modes == null) return error.MissingExtension;

        if (ch.alpn()) |theirs| {
            for (cfg.alpn_protocols) |ours| {
                var it = theirs;
                while (it.next()) |p| if (std.mem.eql(u8, p, ours)) {
                    self.alpn = ours;
                    break;
                };
                if (self.alpn != null) break;
            }
            if (self.alpn == null and cfg.alpn_protocols.len != 0) return error.NoApplicationProtocol;
        }
        if (sni) |n| {
            @memcpy(self.sni_buf[0..n.len], n);
            self.sni_len = @intCast(n.len);
        }

        var ex: kex.ServerExchange = undefined;
        defer std.crypto.secureZero(u8, &ex.shared.bytes);
        // A share that does not exchange (wrong length, low order, off the
        // curve) is the peer's fault; a group this build cannot compute
        // being enabled is the configuration's.
        kex.serverExchange(group, client_share, cfg.random, &ex) catch |err| return switch (err) {
            error.KeyExchangeFailed => error.IllegalParameter,
            error.MissingKeyShare => if (kex.expectedShareLen(group) != 0) error.IllegalParameter else error.InternalError,
        };

        self.suite = suite;
        self.has_suite = true;
        self.group = group;
        switch (suite) {
            .aes_256_gcm_sha384 => {
                self.transcript = .{ .sha384 = .{} };
                try self.serverFlight(S384, m.raw, &ch, ck, scheme, group, &ex);
            },
            else => {
                self.transcript = .{ .sha256 = .{} };
                try self.serverFlight(S256, m.raw, &ch, ck, scheme, group, &ex);
            },
        }
        // Early data the client may have sent under a PSK we did not take.
        if (ch.early_data) self.inbound.skip_early = record.max_plaintext_len;
        self.state = .client_finished;
    }

    /// Frame the message just encoded at the start of the output slot and
    /// add it to the transcript.
    fn send(self: *Server, comptime H: type, msg: []const u8) Error!void {
        H.transcript(&self.transcript).append(msg[0], msg[4..]);
        try self.out.commit(.handshake, msg.len);
    }

    fn encoded(r: messages.Error![]u8) Error![]u8 {
        return r catch |err| switch (err) {
            error.BufferTooSmall => error.OutputFull,
            error.FieldTooLong => error.InternalError,
        };
    }

    fn serverFlight(
        self: *Server,
        comptime H: type,
        client_hello_raw: []const u8,
        ch: *const hello.ClientHello,
        ck: *const CertifiedKey,
        scheme: certverify.SignatureScheme,
        group: u16,
        ex: *const kex.ServerExchange,
    ) Error!void {
        const cfg = self.config;
        const t = H.transcript(&self.transcript);
        t.append(client_hello_raw[0], client_hello_raw[4..]);

        var random: [32]u8 = undefined;
        cfg.random.bytes(&random);
        try self.send(H, try encoded(messages.serverHello(self.out.slot(), .{
            .random = &random,
            .legacy_session_id_echo = ch.legacy_session_id,
            .cipher_suite = @backingInt(self.suite),
            .key_share = .{ .group = group, .key_exchange = ex.public[0..ex.public_len] },
        })));
        try self.out.write(.change_cipher_spec, &.{1});

        // RFC 8446 §7.1, no PSK.
        const L = H.len;
        var empty_hash: [L]u8 = undefined;
        H.Hash.hash("", &empty_hash, .{});
        var early: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &early);
        const zeros: [L]u8 = @splat(0);
        tls13.keyschedule.earlySecret(H.Hkdf, &early, &zeros);
        const hs = self.handshake_secret[0..L];
        ks.deriveHandshakeSecret(H.Hkdf, hs, &early, &empty_hash, ex.shared.slice());
        var server_hs: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &server_hs);
        var th = t.currentHash();
        ks.deriveHandshakeTrafficSecrets(H.Hkdf, self.client_handshake_secret[0..L], &server_hs, hs, &th);
        self.out.installTx(self.suite, &server_hs) catch return error.InternalError;
        self.inbound.installRx(self.suite, self.client_handshake_secret[0..L]) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };

        // EncryptedExtensions.
        var alpn_body: [2 + 1 + 255]u8 = undefined;
        var exts: [2]messages.Extension = undefined;
        var n_exts: usize = 0;
        if (self.alpn) |p| {
            exts[n_exts] = .{ .type = 16, .data = try encoded(messages.alpnData(&alpn_body, p)) };
            n_exts += 1;
        }
        if (self.sni_len != null) {
            exts[n_exts] = .{ .type = 0, .data = "" };
            n_exts += 1;
        }
        try self.send(H, try encoded(messages.encryptedExtensions(self.out.slot(), exts[0..n_exts])));

        // Certificate, the OCSP staple on the leaf if the client asked.
        var entries: [16]messages.CertificateEntry = undefined;
        if (ck.chain.len == 0 or ck.chain.len > entries.len) return error.InternalError;
        for (ck.chain, 0..) |der, i| entries[i] = .{ .cert_data = der };
        if (ch.ocsp_requested) entries[0].ocsp_response = ck.ocsp_response;
        try self.send(H, try encoded(messages.certificate(self.out.slot(), "", entries[0..ck.chain.len])));

        // CertificateVerify over the transcript through Certificate.
        th = t.currentHash();
        var sig_buf: [1024]u8 = undefined;
        const sig = certverify.sign(scheme, ck.key, .server, &th, cfg.random, &sig_buf) catch return error.InternalError;
        try self.send(H, try encoded(messages.certificateVerify(self.out.slot(), @backingInt(scheme), sig)));

        // Finished.
        th = t.currentHash();
        var finished_key: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &finished_key);
        ks.deriveFinishedKey(H.Hkdf, L, &finished_key, &server_hs);
        var verify_data: [L]u8 = undefined;
        tls13.keyschedule.computeFinishedVerifyData(H.Hmac, &verify_data, &finished_key, &th);
        try self.send(H, try encoded(messages.finished(self.out.slot(), &verify_data)));

        // Application secrets over the transcript through the server's
        // Finished; the server sends under its application key from here.
        const ms = self.master_secret[0..L];
        ks.deriveMasterSecret(H.Hkdf, ms, hs, &empty_hash);
        th = t.currentHash();
        ks.deriveApplicationTrafficSecrets(H.Hkdf, self.client_application_secret[0..L], self.server_application_secret[0..L], ms, &th);
        self.out.installTx(self.suite, self.server_application_secret[0..L]) catch return error.InternalError;
    }

    fn onClientFinished(self: *Server, m: inbound.HandshakeMessage) Error!void {
        switch (self.suite) {
            .aes_256_gcm_sha384 => try self.clientFinished(S384, m),
            else => try self.clientFinished(S256, m),
        }
        self.wipeHandshakeSecrets();
        self.inbound.app_data_ok = true;
        self.state = .connected;
    }

    fn clientFinished(self: *Server, comptime H: type, m: inbound.HandshakeMessage) Error!void {
        const L = H.len;
        const t = H.transcript(&self.transcript);
        const th = t.currentHash();
        var finished_key: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &finished_key);
        ks.deriveFinishedKey(H.Hkdf, L, &finished_key, self.client_handshake_secret[0..L]);
        var expected: [L]u8 = undefined;
        defer std.crypto.secureZero(u8, &expected);
        tls13.keyschedule.computeFinishedVerifyData(H.Hmac, &expected, &finished_key, &th);
        if (m.body.len != L or !std.crypto.timing_safe.eql([L]u8, expected, m.body[0..L].*)) return error.DecryptError;
        t.append(m.msg_type, m.body);
        self.inbound.installRx(self.suite, self.client_application_secret[0..L]) catch |err| return switch (err) {
            error.UnexpectedMessage => error.UnexpectedMessage,
            else => error.InternalError,
        };
    }
};

// ── tests ────────────────────────────────────────────────────────────────
//
// Negotiation refusals, each with the alert it sends: a ClientHello built
// field by field, fed as one plaintext record. Whole handshakes against an
// independent client are in `handshake_test.zig`.

const testing = std.testing;
const certs = @import("test_certs.zig");

const Hello = struct {
    versions: ?[]const u16 = &.{0x0304},
    sig_algs: ?[]const u16 = &.{0x0403},
    suites: []const u16 = &.{0x1301},
    groups: ?[]const u16 = &.{0x001d},
    /// Key shares (group, key); a real x25519 key is filled in for 0x001d
    /// entries with an empty key.
    shares: ?[]const struct { u16, []const u8 } = &.{.{ 0x001d, "" }},
    compression: []const u8 = &.{0},
    sni: ?[]const u8 = null,
    alpn: ?[]const []const u8 = null,
    psk_without_modes: bool = false,
};

fn buildRecord(gpa: std.mem.Allocator, h: Hello) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(gpa);
    const W = struct {
        fn u16be(l: *std.ArrayList(u8), a: std.mem.Allocator, v: usize) !void {
            try l.appendSlice(a, &.{ @truncate(v >> 8), @truncate(v) });
        }
        fn ext(l: *std.ArrayList(u8), a: std.mem.Allocator, t: u16, data: []const u8) !void {
            try u16be(l, a, t);
            try u16be(l, a, data.len);
            try l.appendSlice(a, data);
        }
        fn list16(a: std.mem.Allocator, comptime prefix: type, vals: []const u16) ![]u8 {
            var l: std.ArrayList(u8) = .empty;
            const n = vals.len * 2;
            if (prefix == u8) try l.append(a, @intCast(n)) else try u16be(&l, a, n);
            for (vals) |v| try u16be(&l, a, v);
            return l.toOwnedSlice(a);
        }
    };
    // Record header and handshake header, lengths patched at the end.
    try b.appendSlice(gpa, &.{ 22, 3, 1, 0, 0, 1, 0, 0, 0 });
    try b.appendSlice(gpa, &.{ 3, 3 });
    try b.appendNTimes(gpa, 0x42, 32);
    try b.append(gpa, 0);
    try W.u16be(&b, gpa, h.suites.len * 2);
    for (h.suites) |s| try W.u16be(&b, gpa, s);
    try b.append(gpa, @intCast(h.compression.len));
    try b.appendSlice(gpa, h.compression);
    var e: std.ArrayList(u8) = .empty;
    defer e.deinit(gpa);
    if (h.versions) |v| {
        const d = try W.list16(gpa, u8, v);
        defer gpa.free(d);
        try W.ext(&e, gpa, 43, d);
    }
    if (h.sig_algs) |v| {
        const d = try W.list16(gpa, u16, v);
        defer gpa.free(d);
        try W.ext(&e, gpa, 13, d);
    }
    if (h.groups) |v| {
        const d = try W.list16(gpa, u16, v);
        defer gpa.free(d);
        try W.ext(&e, gpa, 10, d);
    }
    if (h.shares) |shares| {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        for (shares) |sh| {
            var key: []const u8 = sh[1];
            var x: [32]u8 = undefined;
            if (sh[0] == 0x001d and key.len == 0) {
                const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(@splat(7));
                x = kp.public_key;
                key = &x;
            }
            try W.u16be(&body, gpa, sh[0]);
            try W.u16be(&body, gpa, key.len);
            try body.appendSlice(gpa, key);
        }
        try W.u16be(&d, gpa, body.items.len);
        try d.appendSlice(gpa, body.items);
        try W.ext(&e, gpa, 51, d.items);
    }
    if (h.sni) |n| {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        try W.u16be(&d, gpa, n.len + 3);
        try d.append(gpa, 0);
        try W.u16be(&d, gpa, n.len);
        try d.appendSlice(gpa, n);
        try W.ext(&e, gpa, 0, d.items);
    }
    if (h.alpn) |names| {
        var d: std.ArrayList(u8) = .empty;
        defer d.deinit(gpa);
        var total: usize = 0;
        for (names) |n| total += 1 + n.len;
        try W.u16be(&d, gpa, total);
        for (names) |n| {
            try d.append(gpa, @intCast(n.len));
            try d.appendSlice(gpa, n);
        }
        try W.ext(&e, gpa, 16, d.items);
    }
    if (h.psk_without_modes) {
        const psk = [_]u8{ 0, 7, 0, 1, 0xaa, 0, 0, 0, 0, 0, 33, 32 } ++ @as([32]u8, @splat(0x55));
        try W.ext(&e, gpa, 41, &psk);
    }
    try W.u16be(&b, gpa, e.items.len);
    try b.appendSlice(gpa, e.items);
    const body_len = b.items.len - 9;
    std.mem.writeInt(u24, b.items[6..9], @intCast(body_len), .big);
    std.mem.writeInt(u16, b.items[3..5], @intCast(body_len + 4), .big);
    return b.toOwnedSlice(gpa);
}

var test_p256: ?std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = null;
const test_chain = [_][]const u8{&certs.p256_cert};

fn testKey() *const CertifiedKey {
    if (test_p256 == null) test_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(certs.p256_scalar) catch unreachable;
    const S = struct {
        var ck: CertifiedKey = undefined;
    };
    S.ck = .{ .chain = &test_chain, .key = .{ .ecdsa_p256 = &test_p256.? } };
    return &S.ck;
}

/// Feed `h` to a fresh server; return its error and the alert it queued.
fn refuse(h: Hello, config_override: ?Config) !struct { err: Error, alert: ?[2]u8 } {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = config_override orelse .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    const joiner = try testing.allocator.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer testing.allocator.free(joiner);
    const out = try testing.allocator.alloc(u8, 32 * 1024);
    defer testing.allocator.free(out);
    var s: Server = .init(&cfg, joiner, out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, h);
    defer testing.allocator.free(rec);
    if (s.feed(rec)) |r| {
        std.debug.print("accepted: {t}\n", .{r.event});
        return error.HelloAccepted;
    } else |err| {
        const p = s.pendingOutput();
        // A plaintext alert record, the last thing queued.
        const a: ?[2]u8 = if (p.len >= 7 and p[p.len - 7] == 21) p[p.len - 2 ..][0..2].* else null;
        return .{ .err = err, .alert = a };
    }
}

fn expectRefusal(h: Hello, want: Error, want_alert: ?alert.Description) !void {
    const r = try refuse(h, null);
    try testing.expectEqual(want, r.err);
    if (want_alert) |d| {
        try testing.expectEqualSlices(u8, &.{ 2, @backingInt(d) }, &(r.alert orelse return error.NoAlertSent));
    } else try testing.expect(r.alert == null);
}

test "a well-formed hello gets a first flight (the builder works)" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .sni = "example.com" });
    defer testing.allocator.free(rec);
    const r = try s.feed(rec);
    try testing.expect(r.event == .need_more);
    try testing.expectEqual(rec.len, r.consumed);
    try testing.expectEqualStrings("example.com", s.serverName().?);
    // ServerHello in the clear, then the CCS, then protected records.
    const p = s.pendingOutput();
    try testing.expectEqual(@as(u8, 22), p[0]);
    const sh_len = std.mem.readInt(u16, p[3..5], .big);
    try testing.expectEqualSlices(u8, &.{ 20, 3, 3, 0, 1, 1 }, p[5 + sh_len ..][0..6]);
    try testing.expectEqual(@as(u8, 23), p[5 + sh_len + 6]);
}

test "refusals and their alerts" {
    // Not TLS 1.3.
    try expectRefusal(.{ .versions = null }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .versions = &.{ 0x0303, 0x0302 } }, error.ProtocolVersion, .protocol_version);
    // Nothing to sign with, nothing in common.
    try expectRefusal(.{ .sig_algs = null }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .sig_algs = &.{ 0x0807, 0x0804 } }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .suites = &.{ 0xc02f, 0x1304 } }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .groups = null }, error.MissingExtension, .missing_extension);
    // The version is checked before anything else the hello lacks.
    try expectRefusal(.{ .versions = null, .sig_algs = null, .groups = null }, error.ProtocolVersion, .protocol_version);
    try expectRefusal(.{ .groups = &.{ 0x0019, 0x0100 } }, error.HandshakeFailure, .handshake_failure);
    // A group in common but no share for it (HelloRetryRequest: M2).
    try expectRefusal(.{ .groups = &.{ 0x0017, 0x001d }, .shares = &.{.{ 0x001d, "" }} }, error.HandshakeFailure, .handshake_failure);
    try expectRefusal(.{ .shares = null }, error.MissingExtension, .missing_extension);
    // Malformed or forbidden.
    try expectRefusal(.{ .shares = &.{ .{ 0x001d, "" }, .{ 0x001d, "" } } }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .shares = &.{.{ 0x001d, &@as([31]u8, @splat(9)) }} }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .shares = &.{.{ 0x001d, &@as([32]u8, @splat(0)) }} }, error.IllegalParameter, .illegal_parameter); // low-order point
    try expectRefusal(.{ .compression = &.{ 1, 0 } }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .compression = &.{1} }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .sni = "not a name" }, error.IllegalParameter, .illegal_parameter);
    try expectRefusal(.{ .psk_without_modes = true }, error.MissingExtension, .missing_extension);
}

test "ALPN: the server's first protocol the client offers; none in common is refused" {
    var prng = std.Random.DefaultPrng.init(1);
    var cfg: Config = .{
        .certificate = .{ .fixed = testKey() },
        .random = prng.random(),
        .alpn_protocols = &.{ "h2", "http/1.1" },
    };
    const r = try refuse(.{ .alpn = &.{ "spdy/3", "acme-tls/1" } }, cfg);
    try testing.expectEqual(error.NoApplicationProtocol, r.err);
    try testing.expectEqualSlices(u8, &.{ 2, 120 }, &r.alert.?);

    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .alpn = &.{ "http/1.1", "h2" } });
    defer testing.allocator.free(rec);
    _ = try s.feed(rec);
    try testing.expectEqualStrings("h2", s.alpn.?);
    // A client without ALPN is served without it.
    cfg.alpn_protocols = &.{"h2"};
    var s2: Server = .init(&cfg, &joiner, &out);
    defer s2.deinit();
    const rec2 = try buildRecord(testing.allocator, .{});
    defer testing.allocator.free(rec2);
    _ = try s2.feed(rec2);
    try testing.expect(s2.alpn == null);
}

test "certificate selector: sees the SNI, null is access_denied" {
    var prng = std.Random.DefaultPrng.init(1);
    const Sel = struct {
        var seen: [64]u8 = undefined;
        var seen_len: usize = 0;
        fn select(_: ?*anyopaque, sni: ?[]const u8, _: *const hello.ClientHello) ?*const CertifiedKey {
            const n = sni orelse return null;
            @memcpy(seen[0..n.len], n);
            seen_len = n.len;
            return if (std.mem.eql(u8, n, "known.example")) testKey() else null;
        }
    };
    const cfg: Config = .{ .certificate = .{ .select = .{ .select = Sel.select } }, .random = prng.random() };
    const r = try refuse(.{ .sni = "unknown.example" }, cfg);
    try testing.expectEqual(error.AccessDenied, r.err);
    try testing.expectEqualSlices(u8, &.{ 2, 49 }, &r.alert.?);
    try testing.expectEqualStrings("unknown.example", Sel.seen[0..Sel.seen_len]);
    // An IP literal is no SNI.
    const r2 = try refuse(.{ .sni = "192.0.2.1" }, cfg);
    try testing.expectEqual(error.AccessDenied, r2.err);
}

test "first message not a ClientHello; a second ClientHello; a bad client Finished" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    {
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        var rec = [_]u8{ 22, 3, 3, 0, 8, 20, 0, 0, 4, 1, 2, 3, 4 };
        try testing.expectError(error.UnexpectedMessage, s.feed(&rec));
        try testing.expectEqualSlices(u8, &.{ 21, 3, 3, 0, 2, 2, 10 }, s.pendingOutput());
        try testing.expectError(error.Closed, s.feed(&rec));
    }
    {
        // Two ClientHellos in one record: the second is data across the key
        // change.
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const one = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(one);
        var two: std.ArrayList(u8) = .empty;
        defer two.deinit(testing.allocator);
        try two.appendSlice(testing.allocator, one);
        try two.appendSlice(testing.allocator, one[5..]);
        std.mem.writeInt(u16, two.items[3..5], @intCast(two.items.len - 5), .big);
        try testing.expectError(error.UnexpectedMessage, s.feed(two.items));
    }
    {
        // A client Finished that does not verify: decrypt_error, sealed
        // under the server's key (so not readable here as plaintext).
        var s: Server = .init(&cfg, &joiner, &out);
        defer s.deinit();
        const rec = try buildRecord(testing.allocator, .{});
        defer testing.allocator.free(rec);
        _ = try s.feed(rec);
        const flight = s.pendingOutput().len;
        // Seal a wrong Finished under the client's handshake key.
        var tx: record.Protection = undefined;
        try tx.init(.aes_128_gcm_sha256, s.client_handshake_secret[0..32]);
        var buf: [128]u8 = undefined;
        const fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, @splat(0xee));
        @memcpy(buf[5..][0..fin.len], &fin);
        const sealed = try tx.seal(&buf, fin.len, .handshake, 0);
        try testing.expectError(error.DecryptError, s.feed(sealed));
        // One more record went out: the protected alert.
        try testing.expectEqual(flight + 5 + 2 + 1 + 16, s.pendingOutput().len);
    }
}

test "application data is refused before the handshake completes" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    try testing.expectError(error.NotConnected, s.write("x"));
    try testing.expectEqual(@as(?record.CipherSuite, null), s.cipherSuite());
}

test "alertFor covers every error" {
    inline for (@typeInfo(Error).error_set.error_names.?) |name| {
        _ = alertFor(@field(anyerror, name));
    }
}

test "after a refusal every secret is wiped; the suite is unknown if it was not chosen" {
    var prng = std.Random.DefaultPrng.init(1);
    const cfg: Config = .{ .certificate = .{ .fixed = testKey() }, .random = prng.random() };
    var joiner: [inbound.Joiner.bufferLen(inbound.default_max_message)]u8 = undefined;
    var out: [32 * 1024]u8 = undefined;
    var s: Server = .init(&cfg, &joiner, &out);
    defer s.deinit();
    const rec = try buildRecord(testing.allocator, .{ .groups = &.{0x0100} });
    defer testing.allocator.free(rec);
    try testing.expectError(error.HandshakeFailure, s.feed(rec));
    try testing.expectEqual(@as(?record.CipherSuite, null), s.cipherSuite());

    // Refused after the keys exist: a bad Finished.
    var s2: Server = .init(&cfg, &joiner, &out);
    defer s2.deinit();
    const ok = try buildRecord(testing.allocator, .{});
    defer testing.allocator.free(ok);
    _ = try s2.feed(ok);
    var tx: record.Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, s2.client_handshake_secret[0..32]);
    var buf: [128]u8 = undefined;
    const fin = [_]u8{ 20, 0, 0, 32 } ++ @as([32]u8, @splat(0xee));
    @memcpy(buf[5..][0..fin.len], &fin);
    try testing.expectError(error.DecryptError, s2.feed(try tx.seal(&buf, fin.len, .handshake, 0)));
    for ([_][]const u8{ &s2.handshake_secret, &s2.client_handshake_secret, &s2.master_secret, &s2.client_application_secret, &s2.server_application_secret }) |sec|
        for (sec) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expect(!s2.out.protected and !s2.inbound.protected);
    try testing.expectEqual(record.CipherSuite.aes_128_gcm_sha256, s2.cipherSuite().?);
}
