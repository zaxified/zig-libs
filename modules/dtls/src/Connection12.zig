// SPDX-License-Identifier: MIT

//! dtls.Connection12 — a DTLS 1.2 (RFC 6347) client and server with the same
//! method shape as the 1.3 `Connection` (`clientInit`/`serverInit` from the
//! shared `Config`, `startHandshake`, `handleFlight`, `poll`, `send`,
//! `recv`, `exportKeyingMaterial`, `deinit`), so a caller switches by
//! `Config.versions`; `Endpoint` negotiates between the two.
//!
//! **Handshake** (RFC 6347 §4.2, RFC 5246 §7.3), full handshakes only:
//!
//!     ClientHello                 -->
//!                                 <--  HelloVerifyRequest   (Config.hello_retry)
//!     ClientHello + cookie        -->
//!                                       ServerHello
//!                                       Certificate*          (ECDHE_ECDSA/RSA)
//!                                       ServerKeyExchange*    (ECDHE, PSK hint)
//!                                       CertificateRequest*   (request_client_cert)
//!                                 <--  ServerHelloDone
//!     Certificate*
//!     ClientKeyExchange
//!     CertificateVerify*
//!     [ChangeCipherSpec]
//!     Finished                    -->
//!                                       [ChangeCipherSpec]
//!                                 <--  Finished
//!
//! Suites: `suite12.CipherSuite12` — ECDHE_ECDSA / ECDHE_RSA with
//! AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, PSK with AES-128-GCM and
//! ECDHE_PSK with ChaCha20-Poly1305. ECDHE groups X25519, secp256r1,
//! secp384r1 (RFC 8422). Extended master secret (RFC 7627) mandatory by
//! default; RFC 5746 `renegotiation_info` always sent by a client and
//! required from the server; a server answers it when the client signals it
//! and, since it never renegotiates, also serves a client that does not
//! (RFC 5746 §4.3, as OpenSSL, wolfSSL and mbedTLS do). Renegotiation itself
//! is never performed (a peer's HelloRequest or
//! renewed ClientHello after the handshake is ignored).
//!
//! **Deliberately absent:** CBC suites, static-RSA key exchange, compression
//! (only `null` is offered or accepted), renegotiation, session resumption
//! (session IDs / RFC 5077 tickets; every handshake is full), CCM suites,
//! `use_srtp`, connection ID (RFC 9146), and sending alerts (errors are
//! typed; the caller decides).
//!
//! **Fragmentation** (RFC 6347 §4.2.3): with `Config.max_datagram_len` set,
//! an epoch-0 handshake message whose record would exceed it is sent as
//! several fragments (`handshake.Fragmenter`), one record each, and the
//! returned bytes are cut into datagrams with `record.nextDatagram`. With
//! it 0 (the default) every message travels in one record, as before.
//!
//! **Retransmission** (RFC 6347 §4.2.4): the last flight is cached as
//! MESSAGES, not records, and re-encoded with fresh record sequence numbers
//! on each resend (a verbatim resend would be dropped by the peer's replay
//! window). It is resent when `poll`'s timer expires and when the peer
//! retransmits its previous flight (a duplicate `message_seq` arrives). A
//! server that has finished keeps its last flight (ChangeCipherSpec +
//! Finished): a client that lost it retransmits its own final flight, which
//! `recv` reports as `error.ReceivedPostHandshakeMessage` and the next
//! `poll` answers.
//!
//! **Robustness:** every `handleFlight` is a transaction — on any error the
//! connection is restored to its state before the call (as in the 1.3
//! engine: epoch-0 records are unauthenticated, so a forged one must not
//! poison the handshake). Incoming handshake messages are reassembled one
//! at a time by `handshake.Reassembler` (fragments in any order, duplicates
//! tolerated, a contradicting overlap refused), bounded by
//! `max_message_len`. Fragments of a LATER message (RFC 6347 §4.2.2) are
//! queued, up to `max_future_ahead` messages ahead and `max_future_bytes` in
//! all, and fed in once their turn comes; beyond that they are dropped and
//! the peer retransmits.

const std = @import("std");
const conn13 = @import("Connection.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const flight = @import("flight.zig");
const burn = @import("burn.zig");
const m12 = @import("messages12.zig");
const messages = @import("messages.zig");
const record12 = @import("record12.zig");
const prf12 = @import("prf12.zig");
const sig12 = @import("sig12.zig");
const suite12 = @import("suite12.zig");
const suitehash = @import("suitehash.zig");
const certauth = @import("certauth.zig");
const certverify = @import("tls13").certverify;
const kex = @import("tls13").kex;

pub const Config = conn13.Config;
pub const Role = conn13.Role;
pub const Entropy = conn13.Entropy;
pub const HandshakeError = conn13.HandshakeError;
pub const SendError = conn13.SendError;
pub const InitError = conn13.ConfigError;
pub const HandshakeResult = conn13.Connection.HandshakeResult;
pub const CipherSuite12 = suite12.CipherSuite12;
pub const KeyExchange12 = suite12.KeyExchange12;
const HashAlg = suitehash.HashAlg;

pub const State = enum {
    start,
    /// Client: ClientHello sent; HelloVerifyRequest or ServerHello next.
    wait_server_hello,
    /// Client: ServerHello processed; Certificate / ServerKeyExchange /
    /// CertificateRequest / ServerHelloDone next.
    wait_server_hello_done,
    /// Client: final flight sent; the server's ChangeCipherSpec + Finished
    /// next.
    wait_server_finished,
    /// Server: flight 4 sent; the client's final flight next.
    wait_client_flight,
    connected,
};

pub const ExportError = prf12.ExportError || error{ NotConnected, ExtendedMasterSecretRequired };

/// Largest incoming handshake message (a Certificate chain, in practice).
pub const max_message_len = 4096;
/// Raw transcript capacity: every handshake message of one handshake with
/// its 12-byte DTLS header (RFC 6347 §4.2.6 hashes those too). Two
/// `max_message_len` certificates plus the rest fit.
const transcript_cap = 12288;
/// The cached last flight (messages with their headers, see `TxKind`).
const tx_cap = 6144;
const max_client_hello = 2048;
const max_plain = max_message_len + handshake.header_len + 64;
const max_send_seq: u48 = std.math.maxInt(u48);
/// Queue for fragments of messages AHEAD of the expected one (RFC 6347
/// §4.2.2): bytes in all, and how far ahead. Sized like the 1.3 engine's
/// `max_flight_bytes` bound: the largest flight this engine accepts
/// (ServerHello + a `max_message_len` Certificate + ServerKeyExchange +
/// CertificateRequest + ServerHelloDone) fits, so a fully reversed flight is
/// still taken in one pass; anything beyond is dropped and retransmitted.
const max_future_bytes = 6144;
const max_future_ahead: u16 = 8;
const future_entry_header = 1 + handshake.header_len;
const max_psk_len = 512;
const max_point_len = 133;

const content_change_cipher_spec: u8 = 20;
const content_alert: u8 = 21;
const content_handshake: u8 = 22;
const content_application_data: u8 = 23;

/// Entries of the retransmission cache.
const TxKind = enum(u8) { handshake_epoch0 = 0, change_cipher_spec = 1, handshake_epoch1 = 2 };

const Window = struct {
    seen_any: bool = false,
    high: u48 = 0,
    bits: u64 = 0,

    fn accept(self: *Window, seq: u48) bool {
        return conn13.replayCheckAndUpdate(&self.seen_any, &self.high, &self.bits, seq);
    }

    /// `accept` without the update: whether `seq` would be taken.
    fn fresh(self: Window, seq: u48) bool {
        var w = self;
        return w.accept(seq);
    }

    /// Records an UNAUTHENTICATED (epoch-0) `seq`, unless it lies more than
    /// `epoch0_max_jump` past the highest recorded number (past 0 before
    /// any): such a record is processed but not recorded, so a forged
    /// record number near 2^48 can never become the window's high mark.
    /// A genuine peer that lost many records keeps working (its records
    /// are still ahead of the window, hence fresh); only their replay
    /// protection lapses until one lands within reach.
    fn recordUnauthenticated(self: *Window, seq: u48) void {
        const base: u48 = if (self.seen_any) self.high else 0;
        if (seq > base +| epoch0_max_jump) return;
        _ = self.accept(seq);
    }
};

/// How far one epoch-0 record may move the window's high mark: the window
/// width (`replayCheckAndUpdate`'s 64-record bitmap).
const epoch0_max_jump = 64;

/// What an epoch-0 record has to change to count as having advanced the
/// handshake (see `processRecord`): a COMPLETED message (the next expected
/// one moves on) or an accepted ChangeCipherSpec (the read epoch moves on).
/// New bytes of a message still in progress do not count: they are
/// unauthenticated, and one forged byte would otherwise be enough.
const Progress = struct { next_recv_seq: u16, read_epoch: u16 };

const cookie_mac_label = "dtls 1.2 hello verify cookie v1";
const cookie_len = 32;

fn source(e: Entropy) std.Random {
    return switch (e) {
        .csprng => |r| r,
        .seeded_for_test => |r| r,
    };
}

/// Output accumulator for one call: records are appended to `buf`.
const Out = struct {
    buf: []u8,
    len: usize = 0,

    fn rest(self: *Out) []u8 {
        return self.buf[self.len..];
    }
    fn slice(self: *const Out) []const u8 {
        return self.buf[0..self.len];
    }
};

pub const Connection12 = struct {
    role: Role,
    config: Config,
    state: State = .start,
    suite: CipherSuite12 = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
    kx: KeyExchange12 = .ecdhe_ecdsa,
    /// RFC 7627 was negotiated.
    ems: bool = false,
    /// Server: the client signalled RFC 5746 (extension or SCSV).
    peer_ri: bool = false,
    client_random: [32]u8 = @splat(0),
    server_random: [32]u8 = @splat(0),

    // ── handshake message counters (RFC 6347 §4.2.2)
    message_seq: u16 = 0,
    next_recv_seq: u16 = 0,

    // ── record layer
    send_seq: [2]u48 = .{ 0, 0 },
    recv_win: [2]Window = .{ .{}, .{} },
    read_epoch: u16 = 0,
    write_keys: record12.DirKeys = .{},
    read_keys: record12.DirKeys = .{},
    master: [prf12.master_secret_len]u8 = @splat(0),
    keys_live: bool = false,

    // ── transcript: raw handshake messages (header + body)
    transcript: [transcript_cap]u8 = undefined,
    transcript_len: usize = 0,
    /// Where the peer's leaf certificate sits inside `transcript`.
    peer_leaf_off: usize = 0,
    peer_leaf_len: usize = 0,

    // ── incoming reassembly (one message at a time)
    rx_msg: [max_message_len]u8 = undefined,
    rx_active: bool = false,
    rx_type: u8 = 0,
    rx_total: usize = 0,
    rx_filled: usize = 0,
    /// Which bytes of `rx_msg` have arrived (`handshake.Reassembler`).
    rx_have: [max_message_len]bool = undefined,
    /// Fragments of later messages (`stashFuture`): entries of an epoch
    /// byte, the 12-byte handshake header and the fragment.
    rx_future: [max_future_bytes]u8 = undefined,
    rx_future_len: usize = 0,
    /// This `handleFlight` call fed a queued fragment (see there).
    queue_used: bool = false,
    /// The message in progress holds bytes that came from the queue.
    rx_from_queue: bool = false,
    /// Rank of the last message processed in the current flight, for order
    /// enforcement (see `rank`).
    last_rank: u8 = 0,
    /// Record sequence number of the record currently being processed.
    cur_record_seq: u48 = 0,
    saw_duplicate: bool = false,
    stateless_reply: bool = false,

    // ── ECDHE
    ecdhe_group: u16 = 0,
    ecdhe_secret: [kex.secret_len]u8 = undefined,
    ecdhe_live: bool = false,
    server_point: [max_point_len]u8 = undefined,
    server_point_len: usize = 0,

    // ── certificate state
    got_certificate: bool = false,
    got_ske: bool = false,
    cert_requested: bool = false,
    peer_schemes: [32]u16 = undefined,
    peer_schemes_len: usize = 0,
    /// Server: the client presented a non-empty Certificate.
    client_cert_presented: bool = false,
    got_cke: bool = false,
    got_cv: bool = false,

    // ── client: the ClientHello (kept for the HelloVerifyRequest resend)
    ch_body: [max_client_hello]u8 = undefined,
    ch_body_len: usize = 0,
    hvr_count: u8 = 0,

    // ── retransmission
    tx: [tx_cap]u8 = undefined,
    tx_len: usize = 0,
    timer: flight.RetransmitTimer = flight.RetransmitTimer.init(1000, 60_000),
    resend_pending: bool = false,

    alpn: [255]u8 = undefined,
    alpn_len: u8 = 0,
    /// RFC 5764: the negotiated SRTP protection profile, 0 = none.
    srtp_profile: u16 = 0,
    /// The last alert the peer sent (`level`, `description`), RFC 5246 §7.2.
    peer_alert: ?[2]u8 = null,

    // secret-api-ok: a fresh value holds no key material; Config is slices and pointers only.
    pub fn clientInit(config: Config) InitError!Connection12 {
        try config.validate();
        if (!config.allows(.dtls12)) return error.InvalidVersions;
        return .{ .role = .client, .config = config };
    }

    // secret-api-ok: as `clientInit`.
    pub fn serverInit(config: Config) InitError!Connection12 {
        try config.validate();
        if (!config.allows(.dtls12)) return error.InvalidVersions;
        return .{ .role = .server, .config = config };
    }

    pub fn deinit(self: *Connection12) void {
        std.crypto.secureZero(u8, &self.master);
        self.write_keys.wipe();
        self.read_keys.wipe();
        std.crypto.secureZero(u8, &self.ecdhe_secret);
        self.keys_live = false;
        self.ecdhe_live = false;
    }

    pub fn negotiatedSuite(self: *const Connection12) ?CipherSuite12 {
        return if (self.state == .connected) self.suite else null;
    }

    pub fn negotiatedAlpn(self: *const Connection12) ?[]const u8 {
        return if (self.alpn_len == 0) null else self.alpn[0..self.alpn_len];
    }

    /// RFC 5764: the SRTP protection profile both sides agreed on, or null
    /// (`Config.srtp_profiles`).
    pub fn negotiatedSrtpProfile(self: *const Connection12) ?u16 {
        return if (self.srtp_profile == 0) null else self.srtp_profile;
    }

    pub fn isConnected(self: *const Connection12) bool {
        return self.state == .connected;
    }

    // ── handshake entry points ───────────────────────────────────────────

    /// Client only: sends the ClientHello (flight 1).
    pub fn startHandshake(self: *Connection12, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError![]const u8 {
        return burn.run(burn.start_burn, HandshakeError![]const u8, startBody, .{ self, entropy, now_ms, out });
    }

    fn startBody(self: *Connection12, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError![]const u8 {
        if (self.role != .client or self.state != .start) return error.WrongState;
        source(entropy).bytes(&self.client_random);
        const body = try self.buildClientHello(&self.ch_body);
        self.ch_body_len = body.len;
        return self.sendClientHello(now_ms, out);
    }

    /// Client: continues a handshake whose ClientHello the 1.3 engine sent
    /// (a dual-version hello) after the peer answered as a DTLS 1.2 server.
    /// `ch_body` is that hello's body, `message_seq` 0, sent in epoch-0
    /// record `next_record_seq - 1`. Used by `Endpoint`.
    // secret-api-ok: the returned value holds a ClientHello and counters only; no key material exists before the ServerHello.
    pub fn fromDualClientHello(config: Config, ch_body: []const u8, next_record_seq: u48, now_ms: u64) HandshakeError!Connection12 {
        if (ch_body.len > max_client_hello or ch_body.len < 34) return error.Malformed;
        var c = Connection12{ .role = .client, .config = config, .state = .wait_server_hello };
        @memcpy(c.ch_body[0..ch_body.len], ch_body);
        c.ch_body_len = ch_body.len;
        c.client_random = ch_body[2..34].*;
        c.message_seq = 1;
        c.send_seq[0] = next_record_seq;
        try c.appendTranscript(m12.HandshakeType.client_hello, 0, ch_body);
        try c.cacheMessage(.handshake_epoch0, m12.HandshakeType.client_hello, 0, ch_body);
        c.timer.arm(now_ms);
        return c;
    }

    /// Both roles: feeds one datagram (any number of coalesced records) to
    /// the handshake. See the file comment for the transaction semantics.
    pub fn handleFlight(self: *Connection12, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        return burn.run(burn.flight_burn, HandshakeError!HandshakeResult, handleFlightBody, .{ self, datagram, entropy, now_ms, out });
    }

    fn handleFlightBody(self: *Connection12, datagram: []const u8, entropy: Entropy, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        if (self.state == .start and self.role == .client) return error.WrongState;
        var saved = self.*;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&saved));
        const was_connected = self.state == .connected;
        var o = Out{ .buf = out };
        self.saw_duplicate = false;
        self.stateless_reply = false;
        self.queue_used = false;
        self.processDatagram(datagram, entropy, now_ms, &o) catch |err| {
            const used_queue = self.queue_used or saved.rx_from_queue;
            self.* = saved;
            if (!used_queue and !saved.rx_active) return err;
            // The queue is unauthenticated: a forged fragment of a later
            // message, queued earlier (and possibly already latched into the
            // message in progress by an earlier call), would otherwise fail
            // every genuine copy of this flight the same way. Retry once from
            // live bytes alone (what the engine did before it queued
            // anything); the queue is lost, the peer's retransmission
            // refills it.
            //
            // The message in progress from an EARLIER call is just as
            // unauthenticated: one forged fragment latched there (a 1-byte
            // ServerHello piece) would answer every genuine copy with
            // `InconsistentLength`, for ever. Without the queue involved, the
            // retry drops it, but its result is kept only if this datagram
            // alone COMPLETES the message; otherwise the partial message
            // stays and the error stands, so a forged fragment cannot evict
            // a genuine partial message either.
            if (used_queue) self.dropQueue() else self.rx_active = false;
            o.len = 0;
            self.saw_duplicate = false;
            self.stateless_reply = false;
            self.processDatagram(datagram, entropy, now_ms, &o) catch |err2| {
                self.* = saved;
                return err2;
            };
            if (!used_queue and self.next_recv_seq == saved.next_recv_seq) {
                self.* = saved;
                return err;
            }
        };
        if (self.stateless_reply) {
            // HelloVerifyRequest: the server keeps NOTHING (RFC 6347 §4.2.1).
            self.* = saved;
            return .{ .out = o.slice(), .done = false };
        }
        if (o.len == 0 and self.saw_duplicate and self.tx_len > 0 and self.state != .start and !was_connected) {
            // RFC 6347 §4.2.4: the peer retransmitted its previous flight,
            // so ours was lost — resend it.
            try self.emitFlight(&o);
        }
        const done = !was_connected and self.state == .connected;
        return .{ .out = o.slice(), .done = done, .need_more_data = o.len == 0 and !done };
    }

    /// Caller-clocked retransmission (RFC 6347 §4.2.4). Once connected it
    /// returns the last flight once after `recv` reported a peer
    /// retransmission (`resend_pending`).
    pub fn poll(self: *Connection12, now_ms: u64, out: []u8) HandshakeError!?[]const u8 {
        return burn.run(burn.record_burn, HandshakeError!?[]const u8, pollBody, .{ self, now_ms, out });
    }

    fn pollBody(self: *Connection12, now_ms: u64, out: []u8) HandshakeError!?[]const u8 {
        if (self.tx_len == 0) return null;
        var o = Out{ .buf = out };
        if (self.state == .connected) {
            if (!self.resend_pending) return null;
            try self.emitFlight(&o);
            self.resend_pending = false;
            return o.slice();
        }
        if (self.state == .start or !self.timer.isExpired(now_ms)) return null;
        try self.emitFlight(&o);
        self.timer.onTimeout(now_ms);
        return o.slice();
    }

    // ── application data ─────────────────────────────────────────────────

    pub fn send(self: *Connection12, plaintext: []const u8, out: []u8) SendError![]const u8 {
        return burn.run(burn.record_burn, SendError![]const u8, sendBody, .{ self, plaintext, out });
    }

    fn sendBody(self: *Connection12, plaintext: []const u8, out: []u8) SendError![]const u8 {
        if (self.state != .connected) return error.NotConnected;
        if (plaintext.len > 16384) return error.BufferTooShort;
        if (self.send_seq[1] == max_send_seq) return error.SequenceNumberExhausted;
        const rec = record12.seal(&self.write_keys, 1, self.send_seq[1], content_application_data, plaintext, out) catch return error.BufferTooShort;
        self.send_seq[1] += 1;
        return rec;
    }

    /// Opens the first record of `datagram` and returns its application
    /// data. Handshake records after the handshake are a peer
    /// retransmission (`error.ReceivedPostHandshakeMessage`; a server then
    /// owes its last flight — call `poll`) or a renegotiation attempt
    /// (ignored, same error); an alert is `error.ReceivedAlert`.
    pub fn recv(self: *Connection12, datagram: []const u8, out: []u8) SendError![]const u8 {
        return burn.run(burn.record_burn, SendError![]const u8, recvBody, .{ self, datagram, out });
    }

    fn recvBody(self: *Connection12, datagram: []const u8, out: []u8) SendError![]const u8 {
        if (self.state != .connected) return error.NotConnected;
        if (datagram.len < record.plaintext_header_len) return error.RecordTooShort;
        const hdr = record.decodePlaintext(datagram) catch return error.Malformed;
        if (datagram.len - record.plaintext_header_len < hdr.length) return error.RecordTooShort;
        const frag = datagram[record.plaintext_header_len..][0..hdr.length];
        if (hdr.epoch == 0) {
            // Unauthenticated: only ever a retransmission of the peer's
            // epoch-0 handshake messages (its final flight, server side).
            if (hdr.content_type == content_handshake and self.role == .server) self.resend_pending = true;
            return error.ReceivedPostHandshakeMessage;
        }
        if (hdr.epoch != 1) return error.Malformed;
        const pt = record12.open(&self.read_keys, hdr, frag, out) catch |e| return switch (e) {
            error.BufferTooShort => error.BufferTooShort,
            error.RecordTooShort => error.RecordTooShort,
            error.DecryptionFailed => error.DecryptionFailed,
        };
        if (!self.recv_win[1].accept(hdr.sequence_number)) {
            std.crypto.secureZero(u8, pt);
            return error.ReplayedRecord;
        }
        switch (hdr.content_type) {
            content_application_data => return pt,
            content_alert => {
                if (pt.len != 2) return error.Malformed;
                self.peer_alert = pt[0..2].*;
                return error.ReceivedAlert;
            },
            content_handshake => {
                // A retransmitted Finished (the peer lost ours), or a
                // HelloRequest / ClientHello asking to renegotiate, which
                // this module never does.
                if (self.role == .server) self.resend_pending = true;
                return error.ReceivedPostHandshakeMessage;
            },
            else => return error.Malformed,
        }
    }

    /// RFC 5705 exporter over the master secret. Requires the extended
    /// master secret (RFC 7627 §5.4: without it the exported values of two
    /// sessions can be synchronised by a man in the middle).
    pub fn exportKeyingMaterial(self: *const Connection12, label: []const u8, context: ?[]const u8, out: []u8) ExportError!void {
        if (self.state != .connected) return error.NotConnected;
        if (!self.ems) return error.ExtendedMasterSecretRequired;
        return prf12.exportKeyingMaterial(self.suite.hash(), &self.master, &self.client_random, &self.server_random, label, context, out);
    }

    // ── record intake ────────────────────────────────────────────────────

    fn processDatagram(self: *Connection12, dg: []const u8, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        var pos: usize = 0;
        while (pos < dg.len) {
            if (dg.len - pos < record.plaintext_header_len) return error.Malformed;
            const hdr = try record.decodePlaintext(dg[pos..]);
            const start = pos + record.plaintext_header_len;
            if (dg.len - start < hdr.length) return error.Malformed;
            const frag = dg[start..][0..hdr.length];
            pos = start + hdr.length;
            if (hdr.legacy_version[0] != 0xfe) return error.Malformed;
            try self.processRecord(hdr, frag, entropy, now_ms, o);
            if (self.stateless_reply) return;
        }
    }

    fn processRecord(self: *Connection12, hdr: record.PlaintextHeader, frag: []const u8, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        var pt_buf: [max_plain]u8 = undefined;
        defer std.crypto.secureZero(u8, &pt_buf);
        var plain: []const u8 = undefined;
        switch (hdr.epoch) {
            0 => {
                // Checked here, recorded only below, once the record has
                // advanced the handshake. Epoch 0 has no MAC, so recording
                // every well-formed record let an off-path sender with a
                // huge sequence number make the genuine records look stale
                // (RFC 6347 §4.1.2.6 updates the window only after the MAC
                // verified). Only a record that completed a message or was
                // an accepted CCS is recorded, and never far ahead (see
                // `Window.recordUnauthenticated`); one that merely parses —
                // a duplicate, a partial fragment, a queued later message, a
                // stray CCS — is not. Hence a verbatim replay of such a
                // record is processed again: a replayed duplicate makes this
                // side resend its flight once per replayed datagram, as a
                // forged duplicate under a fresh number always could (no
                // growth, same peer address).
                if (!self.recv_win[0].fresh(hdr.sequence_number)) return; // duplicate record: drop
                plain = frag;
            },
            1 => {
                // Epoch-1 records before the peer's ChangeCipherSpec cannot be
                // read yet: dropped (RFC 6347 §4.1 allows discarding them; the
                // peer retransmits).
                if (self.read_epoch != 1) return;
                if (frag.len > pt_buf.len + record12.Bulk.overhead(self.read_keys.bulk)) return error.FlightTooLarge;
                plain = record12.open(&self.read_keys, hdr, frag, &pt_buf) catch |e| return switch (e) {
                    error.DecryptionFailed => error.DecryptionFailed,
                    error.RecordTooShort => error.RecordTooShort,
                    error.BufferTooShort => error.FlightTooLarge,
                };
                if (!self.recv_win[1].accept(hdr.sequence_number)) return;
            },
            else => return,
        }
        self.cur_record_seq = hdr.sequence_number;
        const before = self.progress();
        defer if (hdr.epoch == 0 and !std.meta.eql(before, self.progress())) {
            self.recv_win[0].recordUnauthenticated(hdr.sequence_number);
        };
        switch (hdr.content_type) {
            content_handshake => try self.processHandshakeRecord(plain, hdr.epoch, entropy, now_ms, o),
            content_change_cipher_spec => {
                if (plain.len != 1 or plain[0] != 1) return error.Malformed;
                if (hdr.epoch != 0) return error.UnexpectedMessage;
                if (self.ccsExpected()) {
                    self.read_epoch = 1;
                } else if (self.read_epoch == 1) {
                    self.saw_duplicate = true; // a retransmitted CCS
                }
                // Otherwise early (reordered ahead of the messages it
                // follows): dropped, the peer retransmits.
            },
            content_alert => {
                if (plain.len != 2) return error.Malformed;
                self.peer_alert = plain[0..2].*;
                return error.ReceivedAlert;
            },
            content_application_data => {}, // not before the handshake completes
            else => return error.Malformed,
        }
    }

    fn progress(self: *const Connection12) Progress {
        return .{ .next_recv_seq = self.next_recv_seq, .read_epoch = self.read_epoch };
    }

    fn ccsExpected(self: *const Connection12) bool {
        if (self.read_epoch != 0 or !self.keys_live) return false;
        return switch (self.role) {
            .client => self.state == .wait_server_finished,
            .server => self.state == .wait_client_flight and self.got_cke and (!self.client_cert_presented or self.got_cv),
        };
    }

    fn processHandshakeRecord(self: *Connection12, plain: []const u8, epoch: u16, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        var p: usize = 0;
        while (p < plain.len) {
            const hh = handshake.decodeHeader(plain[p..]) catch return error.Malformed;
            const fl: usize = hh.fragment_length;
            if (plain.len - p - handshake.header_len < fl) return error.Malformed;
            const frag = plain[p + handshake.header_len ..][0..fl];
            p += handshake.header_len + fl;
            if (hh.length > max_message_len) return error.FlightTooLarge;
            // A stateless server (RFC 6347 §4.2.1) cannot know whether this
            // is ClientHello 0 or the post-cookie ClientHello 1.
            // At `.start` nothing is committed yet, so a WHOLE ClientHello
            // under another `message_seq` than the partial one in progress
            // replaces it (a forged partial ClientHello must not make the
            // genuine one look like an old duplicate); a mere fragment does
            // not.
            if (self.role == .server and self.state == .start and hh.msg_type == m12.HandshakeType.client_hello and
                (!self.rx_active or (hh.message_seq != self.next_recv_seq and hh.fragment_offset == 0 and hh.fragment_length == hh.length)))
            {
                self.next_recv_seq = hh.message_seq;
                self.rx_active = false;
            }
            if (messageSeqBefore(hh.message_seq, self.next_recv_seq)) {
                self.saw_duplicate = true;
                continue;
            }
            if (hh.message_seq != self.next_recv_seq) {
                // RFC 6347 §4.2.2: a later message is queued, not dropped.
                self.stashFuture(hh, frag, epoch);
                continue;
            }
            try self.takeFragment(hh, frag, epoch, entropy, now_ms, o);
            if (self.stateless_reply) return;
        }
    }

    /// Feeds one fragment of the expected message (`next_recv_seq`) to the
    /// reassembler and, once the message is whole, processes it — and then
    /// every queued later message that has become the expected one.
    fn takeFragment(self: *Connection12, hh: handshake.HandshakeHeader, frag: []const u8, epoch: u16, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        var done = try self.feedCurrent(hh, frag);
        var cur_epoch = epoch;
        while (true) {
            if (done) |body| {
                self.rx_from_queue = false;
                const seq = self.next_recv_seq;
                self.next_recv_seq +%= 1;
                try self.processMessage(self.rx_type, seq, body, cur_epoch, entropy, now_ms, o);
                if (self.stateless_reply) return;
            }
            // A queued fragment of the (new) expected message, fed straight
            // from the queue (the reassembler copies it) and then dropped.
            const q = self.nextQueued() orelse return;
            const e = self.rx_future[q.at..][0..q.len];
            cur_epoch = e[0];
            self.queue_used = true;
            done = try self.feedCurrent(q.hh, e[future_entry_header..]);
            self.dropQueued(q.at, q.len);
            if (done == null) self.rx_from_queue = true;
        }
    }

    /// The incoming-message reassembler (`handshake.Reassembler`, shared
    /// with the 1.3 engine): fragments in any order, duplicates allowed, a
    /// contradicting overlap refused. Rebuilt over this connection's own
    /// buffers on each call, so the struct stays freely copyable (the
    /// `handleFlight` transaction copies it).
    fn feedCurrent(self: *Connection12, hh: handshake.HandshakeHeader, frag: []const u8) HandshakeError!?[]const u8 {
        var r: handshake.Reassembler = .{
            .buf = &self.rx_msg,
            .received = &self.rx_have,
            .total_len = if (self.rx_active) @intCast(self.rx_total) else null,
            .message_seq = if (self.rx_active) self.next_recv_seq else null,
            .msg_type = self.rx_type,
            .received_bytes = self.rx_filled,
        };
        const done = try r.feed(hh, frag);
        self.rx_active = done == null;
        self.rx_type = r.msg_type;
        self.rx_total = r.total_len.?;
        self.rx_filled = r.received_bytes;
        return done;
    }

    /// Queues a fragment of a LATER message (RFC 6347 §4.2.2: an
    /// implementation MAY discard it, but SHOULD queue it if it has the
    /// buffer space). Bounded: only `max_future_ahead` messages ahead, at
    /// most `max_future_bytes` in all; a fragment that does not fit is
    /// dropped (the peer retransmits). A stateless server at `.start` keeps
    /// nothing. The bytes are unauthenticated until the Finished check, as
    /// with every epoch-0 handshake byte.
    fn stashFuture(self: *Connection12, hh: handshake.HandshakeHeader, frag: []const u8, epoch: u16) void {
        if (self.state == .start) return;
        if (hh.message_seq -% self.next_recv_seq > max_future_ahead) return;
        if (max_future_bytes - self.rx_future_len < future_entry_header + frag.len) return;
        const e = self.rx_future[self.rx_future_len..];
        e[0] = @intCast(epoch);
        handshake.encodeHeader(hh, e[1..][0..handshake.header_len]);
        @memcpy(e[future_entry_header..][0..frag.len], frag);
        self.rx_future_len += future_entry_header + frag.len;
    }

    const Queued = struct { at: usize, len: usize, hh: handshake.HandshakeHeader };

    /// The first queued fragment of the expected message, after discarding
    /// queued fragments that are now in the past.
    fn nextQueued(self: *Connection12) ?Queued {
        var i: usize = 0;
        while (i < self.rx_future_len) {
            const hh = handshake.decodeHeader(self.rx_future[i + 1 .. self.rx_future_len]) catch unreachable; // encoded by `stashFuture`
            const len = future_entry_header + hh.fragment_length;
            if (hh.message_seq == self.next_recv_seq) return .{ .at = i, .len = len, .hh = hh };
            if (messageSeqBefore(hh.message_seq, self.next_recv_seq)) {
                self.dropQueued(i, len);
            } else i += len;
        }
        return null;
    }

    /// Empties the queue, and the message in progress with it when that
    /// holds queued bytes.
    fn dropQueue(self: *Connection12) void {
        self.rx_future_len = 0;
        if (self.rx_from_queue) self.rx_active = false;
        self.rx_from_queue = false;
    }

    fn dropQueued(self: *Connection12, at: usize, len: usize) void {
        std.mem.copyForwards(u8, self.rx_future[at..], self.rx_future[at + len .. self.rx_future_len]);
        self.rx_future_len -= len;
    }

    // ── message dispatch ─────────────────────────────────────────────────

    /// Position of a message inside its flight, for the order checks.
    fn rank(role: Role, t: u8) u8 {
        return switch (role) {
            // What a client receives (from the server).
            .client => switch (t) {
                m12.HandshakeType.certificate => 1,
                m12.HandshakeType.server_key_exchange => 2,
                m12.HandshakeType.certificate_request => 3,
                m12.HandshakeType.server_hello_done => 4,
                else => 0,
            },
            .server => switch (t) {
                m12.HandshakeType.certificate => 1,
                m12.HandshakeType.client_key_exchange => 2,
                m12.HandshakeType.certificate_verify => 3,
                m12.HandshakeType.finished => 4,
                else => 0,
            },
        };
    }

    fn processMessage(self: *Connection12, t: u8, seq: u16, body: []const u8, epoch: u16, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        // Only Finished travels encrypted during the handshake.
        if ((t == m12.HandshakeType.finished) != (epoch == 1)) return error.UnexpectedMessage;
        switch (self.role) {
            .client => switch (self.state) {
                .wait_server_hello => switch (t) {
                    m12.HandshakeType.hello_verify_request => try self.clientHelloVerifyRequest(body, now_ms, o),
                    m12.HandshakeType.server_hello => {
                        try self.clientServerHello(body);
                        try self.appendTranscript(t, seq, body);
                        self.state = .wait_server_hello_done;
                        self.last_rank = 0;
                        self.timer.reset();
                    },
                    else => return error.UnexpectedMessage,
                },
                .wait_server_hello_done => {
                    const r = rank(.client, t);
                    if (r == 0 or r <= self.last_rank) return error.UnexpectedMessage;
                    self.last_rank = r;
                    const before = self.transcript_len;
                    try self.appendTranscript(t, seq, body);
                    switch (t) {
                        m12.HandshakeType.certificate => try self.clientCertificate(body, before),
                        m12.HandshakeType.server_key_exchange => try self.clientServerKeyExchange(body),
                        m12.HandshakeType.certificate_request => try self.clientCertificateRequest(body),
                        m12.HandshakeType.server_hello_done => {
                            if (body.len != 0) return error.Malformed;
                            try self.clientFinalFlight(entropy, now_ms, o);
                        },
                        else => unreachable,
                    }
                },
                .wait_server_finished => {
                    if (t != m12.HandshakeType.finished) return error.UnexpectedMessage;
                    var th: suitehash.Secret = undefined;
                    const expected = prf12.finishedVerifyData(self.suite.hash(), &self.master, false, self.transcriptHash(&th));
                    if (body.len != prf12.verify_data_len or !std.crypto.timing_safe.eql([prf12.verify_data_len]u8, expected, body[0..prf12.verify_data_len].*))
                        return error.FinishedVerifyFailed;
                    try self.appendTranscript(t, seq, body);
                    self.state = .connected;
                    self.timer.reset();
                },
                else => return error.UnexpectedMessage,
            },
            .server => switch (self.state) {
                .start => {
                    if (t != m12.HandshakeType.client_hello) return error.UnexpectedMessage;
                    try self.serverClientHello(seq, body, entropy, now_ms, o);
                },
                .wait_client_flight => {
                    const r = rank(.server, t);
                    if (r == 0 or r <= self.last_rank) return error.UnexpectedMessage;
                    // RFC 5246 §7.4.6: after a CertificateRequest the client
                    // MUST send a Certificate (possibly empty) first.
                    if (self.cert_requested and !self.got_certificate and t != m12.HandshakeType.certificate) return error.UnexpectedMessage;
                    if (!self.cert_requested and t == m12.HandshakeType.certificate) return error.UnexpectedMessage;
                    self.last_rank = r;
                    switch (t) {
                        m12.HandshakeType.certificate => {
                            const before = self.transcript_len;
                            try self.appendTranscript(t, seq, body);
                            try self.serverClientCertificate(body, before);
                        },
                        m12.HandshakeType.client_key_exchange => {
                            try self.appendTranscript(t, seq, body);
                            try self.serverClientKeyExchange(body);
                        },
                        m12.HandshakeType.certificate_verify => {
                            if (!self.client_cert_presented) return error.UnexpectedMessage;
                            try self.verifyCertificateVerify(body);
                            try self.appendTranscript(t, seq, body);
                            self.got_cv = true;
                        },
                        m12.HandshakeType.finished => {
                            if (!self.got_cke or (self.client_cert_presented and !self.got_cv)) return error.UnexpectedMessage;
                            var th: suitehash.Secret = undefined;
                            const expected = prf12.finishedVerifyData(self.suite.hash(), &self.master, true, self.transcriptHash(&th));
                            if (body.len != prf12.verify_data_len or !std.crypto.timing_safe.eql([prf12.verify_data_len]u8, expected, body[0..prf12.verify_data_len].*))
                                return error.FinishedVerifyFailed;
                            try self.appendTranscript(t, seq, body);
                            try self.serverFinalFlight(o);
                        },
                        else => unreachable,
                    }
                },
                else => return error.UnexpectedMessage,
            },
        }
    }

    // ── client ───────────────────────────────────────────────────────────

    fn offeredSuite(self: *const Connection12, s: CipherSuite12) bool {
        const kx = s.keyExchange() orelse return false;
        if (kx.isPsk() != (self.config.key_exchange == .psk)) return false;
        return std.mem.indexOfScalar(CipherSuite12, self.config.cipher_suites12, s) != null;
    }

    fn buildClientHello(self: *Connection12, buf: []u8) HandshakeError![]u8 {
        var suites: [16]u16 = undefined;
        var ns: usize = 0;
        var any_ecdhe = false;
        var any_cert = false;
        for (self.config.cipher_suites12) |s| {
            if (!self.offeredSuite(s) or ns == suites.len) continue;
            suites[ns] = @backingInt(s);
            ns += 1;
            const kx = s.keyExchange().?;
            any_ecdhe = any_ecdhe or kx.usesEcdhe();
            any_cert = any_cert or kx.usesCertificate();
        }
        var ext_buf: [512]u8 = undefined;
        var exts: [9]m12.Extension = undefined;
        var n: usize = 0;
        var used: usize = 0;
        if (any_ecdhe) {
            const g = try messages.encodeSupportedGroups(&suite12.groups12, ext_buf[used..]);
            used += g.len;
            exts[n] = .{ .ext_type = m12.ext_supported_groups, .data = g };
            exts[n + 1] = .{ .ext_type = m12.ext_ec_point_formats, .data = &m12.ec_point_formats_uncompressed };
            n += 2;
        }
        if (any_cert) {
            var schemes: [32]u16 = undefined;
            const sa = try messages.encodeSignatureAlgorithms(self.advertisedSchemes(&schemes), ext_buf[used..]);
            used += sa.len;
            exts[n] = .{ .ext_type = m12.ext_signature_algorithms, .data = sa };
            n += 1;
        }
        if (self.config.alpn_protocols.len > 0) {
            const a = try messages.encodeAlpn(self.config.alpn_protocols, ext_buf[used..]);
            used += a.len;
            exts[n] = .{ .ext_type = m12.ext_alpn, .data = a };
            n += 1;
        }
        if (self.config.srtp_profiles.len > 0) {
            const u = try messages.encodeUseSrtp(self.config.srtp_profiles, "", ext_buf[used..]);
            used += u.len;
            exts[n] = .{ .ext_type = messages.ext_use_srtp, .data = u };
            n += 1;
        }
        exts[n] = .{ .ext_type = m12.ext_extended_master_secret, .data = &.{} };
        exts[n + 1] = .{ .ext_type = m12.ext_renegotiation_info, .data = &m12.renegotiation_info_initial };
        n += 2;
        return m12.encodeClientHello(.{ .random = self.client_random, .cipher_suites = suites[0..ns], .extensions = exts[0..n] }, buf) catch |e| switch (e) {
            error.BufferTooShort => error.BufferTooShort,
            else => error.Malformed,
        };
    }

    fn sendClientHello(self: *Connection12, now_ms: u64, out: []u8) HandshakeError![]const u8 {
        const body = self.ch_body[0..self.ch_body_len];
        self.transcript_len = 0;
        try self.appendTranscript(m12.HandshakeType.client_hello, self.message_seq, body);
        self.tx_len = 0;
        try self.cacheMessage(.handshake_epoch0, m12.HandshakeType.client_hello, self.message_seq, body);
        self.message_seq +%= 1;
        var o = Out{ .buf = out };
        try self.emitFlight(&o);
        self.timer.reset();
        self.timer.arm(now_ms);
        self.state = .wait_server_hello;
        return o.slice();
    }

    fn clientHelloVerifyRequest(self: *Connection12, body: []const u8, now_ms: u64, o: *Out) HandshakeError!void {
        const hvr = m12.decodeHelloVerifyRequest(body) catch return error.Malformed;
        // RFC 6347 §4.2.1: the version is formatting only (1.0 or 1.2).
        if (hvr.version[0] != 0xfe or hvr.version[1] < 0xfd) return error.UnsupportedVersion;
        if (hvr.cookie.len == 0) return error.IllegalHelloRetryRequest;
        // RFC 6347 §4.2.1 lets a server send a new cookie; a server that
        // never accepts one would keep this client looping.
        self.hvr_count += 1;
        if (self.hvr_count > 3) return error.IllegalHelloRetryRequest;
        var ext: [24]m12.Extension = undefined;
        const old = self.ch_body[0..self.ch_body_len];
        const dec = m12.decodeClientHello(old, &ext) catch return error.Malformed;
        const off = dec.cookie_offset;
        const tail_start = off + 1 + dec.cookie.len;
        const new_len = off + 1 + hvr.cookie.len + (old.len - tail_start);
        if (new_len > max_client_hello) return error.BufferTooShort;
        var nb: [max_client_hello]u8 = undefined;
        @memcpy(nb[0..off], old[0..off]);
        nb[off] = @intCast(hvr.cookie.len);
        @memcpy(nb[off + 1 ..][0..hvr.cookie.len], hvr.cookie);
        @memcpy(nb[off + 1 + hvr.cookie.len ..][0 .. old.len - tail_start], old[tail_start..]);
        @memcpy(self.ch_body[0..new_len], nb[0..new_len]);
        self.ch_body_len = new_len;
        // RFC 6347 §4.2.1: ClientHello1 and the HelloVerifyRequest are not
        // part of the transcript; `sendClientHello` restarts it.
        const flight_out = try self.sendClientHello(now_ms, o.rest());
        o.len += flight_out.len;
    }

    fn clientServerHello(self: *Connection12, body: []const u8) HandshakeError!void {
        var ext: [16]m12.Extension = undefined;
        const sh = m12.decodeServerHello(body, &ext) catch |e| return switch (e) {
            error.DuplicateExtension => error.DuplicateExtension,
            else => error.Malformed,
        };
        if (!std.mem.eql(u8, &sh.version, &m12.version_dtls12)) return error.UnsupportedVersion;
        if (sh.compression_method != 0) return error.Malformed;
        const suite: CipherSuite12 = @fromBackingInt(sh.cipher_suite);
        if (!self.offeredSuite(suite)) return error.NoCipherSuiteOverlap;
        // RFC 8446 §4.1.3: a 1.3-capable client checks the sentinel.
        if (self.config.allows(.dtls13) and std.mem.eql(u8, sh.random[24..32], &m12.downgrade_sentinel_12)) return error.DowngradeDetected;
        var ri_ok = false;
        var ems = false;
        for (sh.extensions) |e| switch (e.ext_type) {
            m12.ext_renegotiation_info => {
                if (!std.mem.eql(u8, e.data, &m12.renegotiation_info_initial)) return error.SecureRenegotiationRequired;
                ri_ok = true;
            },
            m12.ext_extended_master_secret => {
                if (e.data.len != 0) return error.Malformed;
                ems = true;
            },
            m12.ext_ec_point_formats => if (!m12.pointFormatsIncludeUncompressed(e.data)) return error.Malformed,
            messages.ext_use_srtp => {
                // RFC 5764 §4.1.1 / §4.1.3: one profile we offered, and no
                // MKI (we sent none).
                if (self.config.srtp_profiles.len == 0) return error.Malformed;
                const ans = messages.decodeUseSrtp(e.data) catch return error.Malformed;
                if (ans.count() != 1 or ans.mki.len != 0) return error.Malformed;
                if (std.mem.indexOfScalar(u16, self.config.srtp_profiles, ans.profile(0)) == null) return error.Malformed;
                self.srtp_profile = ans.profile(0);
            },
            m12.ext_alpn => {
                if (self.config.alpn_protocols.len == 0) return error.Malformed;
                const name = messages.decodeAlpnSelected(e.data) catch return error.Malformed;
                for (self.config.alpn_protocols) |p| {
                    if (std.mem.eql(u8, p, name)) break;
                } else return error.Malformed;
                @memcpy(self.alpn[0..name.len], name);
                self.alpn_len = @intCast(name.len);
            },
            // RFC 5246 §7.4.1.4: a server MUST NOT send an extension the
            // client did not offer.
            else => return error.Malformed,
        };
        if (!ri_ok) return error.SecureRenegotiationRequired;
        if (!ems and self.config.require_extended_master_secret) return error.ExtendedMasterSecretRequired;
        self.ems = ems;
        self.suite = suite;
        self.kx = suite.keyExchange().?;
        self.server_random = sh.random;
    }

    fn clientCertificate(self: *Connection12, body: []const u8, transcript_before: usize) HandshakeError!void {
        if (!self.kx.usesCertificate()) return error.UnexpectedMessage;
        const leaf = (m12.decodeCertificateLeaf(body) catch return error.Malformed) orelse return error.PeerCertificateRequired;
        try self.checkTrust(leaf, body);
        self.peer_leaf_off = transcript_before + handshake.header_len + (@intFromPtr(leaf.ptr) - @intFromPtr(body.ptr));
        self.peer_leaf_len = leaf.len;
        self.got_certificate = true;
    }

    fn clientServerKeyExchange(self: *Connection12, body: []const u8) HandshakeError!void {
        var params_rest: []const u8 = body;
        switch (self.kx) {
            .psk => {
                const hint = m12.decodeOpaque16(body) catch return error.Malformed;
                if (hint.rest.len != 0) return error.Malformed;
                self.got_ske = true;
                return;
            },
            .ecdhe_psk => {
                const hint = m12.decodeOpaque16(body) catch return error.Malformed;
                params_rest = hint.rest;
            },
            .ecdhe_ecdsa, .ecdhe_rsa => if (!self.got_certificate) return error.UnexpectedMessage,
        }
        const d = m12.decodeEcdhParams(params_rest) catch return error.Malformed;
        if (std.mem.indexOfScalar(u16, &suite12.groups12, d.params.group) == null) return error.UnsupportedGroup;
        if (d.params.point.len != kex.expectedShareLen(d.params.group)) return error.MissingKeyShare;
        if (self.kx.usesCertificate()) {
            const signed = m12.decodeSigned(d.rest) catch return error.Malformed;
            var content: [64 + 4 + max_point_len]u8 = undefined;
            @memcpy(content[0..32], &self.client_random);
            @memcpy(content[32..64], &self.server_random);
            @memcpy(content[64..][0..d.params.raw.len], d.params.raw);
            try self.verifyPeerSignature(signed, content[0 .. 64 + d.params.raw.len], self.kx);
        } else if (d.rest.len != 0) return error.Malformed;
        self.ecdhe_group = d.params.group;
        @memcpy(self.server_point[0..d.params.point.len], d.params.point);
        self.server_point_len = d.params.point.len;
        self.got_ske = true;
    }

    fn clientCertificateRequest(self: *Connection12, body: []const u8) HandshakeError!void {
        // RFC 4279 §2: a PSK server MUST NOT send one.
        if (!self.kx.usesCertificate()) return error.UnexpectedMessage;
        const cr = m12.decodeCertificateRequest(body) catch return error.Malformed;
        self.peer_schemes_len = 0;
        var i: usize = 0;
        while (i + 2 <= cr.schemes_raw.len and self.peer_schemes_len < self.peer_schemes.len) : (i += 2) {
            self.peer_schemes[self.peer_schemes_len] = std.mem.readInt(u16, cr.schemes_raw[i..][0..2], .big);
            self.peer_schemes_len += 1;
        }
        self.cert_requested = true;
    }

    fn clientFinalFlight(self: *Connection12, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        if (self.kx.usesCertificate() and !self.got_certificate) return error.PeerCertificateRequired;
        if (self.kx.usesEcdhe() and !self.got_ske) return error.MissingKeyShare;
        self.tx_len = 0;
        var buf: [max_message_len]u8 = undefined;

        var sent_cert = false;
        if (self.cert_requested) {
            const chain: []const []const u8 = if (self.config.cert) |c| c.chain else &.{};
            const cb = m12.encodeCertificate(chain, &buf) catch return error.BufferTooShort;
            try self.sendMessage(.handshake_epoch0, m12.HandshakeType.certificate, cb);
            sent_cert = chain.len > 0;
        }

        // ClientKeyExchange + premaster.
        var pms: [2 + @max(80, max_psk_len) + 2 + max_psk_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &pms);
        var pms_len: usize = 0;
        var cke_len: usize = 0;
        var z: kex.SharedSecret = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&z));
        if (self.kx.isPsk()) {
            const id = m12.encodeOpaque16(self.config.psk_identity, &buf) catch return error.BufferTooShort;
            cke_len = id.len;
        }
        if (self.kx.usesEcdhe()) {
            var ex: kex.ServerExchange = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&ex));
            kex.serverExchange(self.ecdhe_group, self.server_point[0..self.server_point_len], source(entropy), &ex) catch return error.KeyExchangeFailed;
            z = ex.shared;
            const pt = m12.encodePoint(ex.public[0..ex.public_len], buf[cke_len..]) catch return error.BufferTooShort;
            cke_len += pt.len;
        }
        pms_len = try self.premaster(if (self.kx.usesEcdhe()) z.slice() else null, &pms);
        try self.sendMessage(.handshake_epoch0, m12.HandshakeType.client_key_exchange, buf[0..cke_len]);
        self.deriveKeys(pms[0..pms_len]);

        if (sent_cert) {
            const cert = self.config.cert.?;
            const scheme = self.selectScheme(self.peer_schemes[0..self.peer_schemes_len], null) orelse return error.NoSignatureSchemeOverlap;
            var sig: [600]u8 = undefined;
            const s = try sig12.sign(scheme, cert.private_key, self.transcript[0..self.transcript_len], source(entropy), &sig);
            const cv = m12.encodeSigned(scheme, s, &buf) catch return error.BufferTooShort;
            try self.sendMessage(.handshake_epoch0, m12.HandshakeType.certificate_verify, cv);
        }

        try self.cacheEntry(.change_cipher_spec, &.{1});
        var th: suitehash.Secret = undefined;
        const vd = prf12.finishedVerifyData(self.suite.hash(), &self.master, true, self.transcriptHash(&th));
        try self.sendMessage(.handshake_epoch1, m12.HandshakeType.finished, &vd);
        try self.emitFlight(o);
        self.timer.reset();
        self.timer.arm(now_ms);
        self.state = .wait_server_finished;
    }

    // ── server ───────────────────────────────────────────────────────────

    fn cookieFor(hr: conn13.HelloRetryConfig, dec: m12.DecodedClientHello) [cookie_len]u8 {
        var mac = std.crypto.auth.hmac.sha2.HmacSha256.init(hr.cookie_secret);
        mac.update(cookie_mac_label);
        var l: [2]u8 = undefined;
        std.mem.writeInt(u16, &l, @intCast(@min(hr.peer_binding.len, 0xffff)), .big);
        mac.update(&l);
        mac.update(hr.peer_binding);
        // RFC 6347 §4.2.1's "Client-Parameters": version, random,
        // session_id, cipher_suites, compression_method.
        mac.update(&dec.version);
        mac.update(&dec.random);
        mac.update(&.{@intCast(dec.session_id.len)});
        mac.update(dec.session_id);
        std.mem.writeInt(u16, &l, @intCast(dec.cipher_suites_raw.len), .big);
        mac.update(&l);
        mac.update(dec.cipher_suites_raw);
        mac.update(&.{@intCast(dec.compression_methods.len)});
        mac.update(dec.compression_methods);
        var out: [cookie_len]u8 = undefined;
        mac.final(&out);
        return out;
    }

    fn serverClientHello(self: *Connection12, seq: u16, body: []const u8, entropy: Entropy, now_ms: u64, o: *Out) HandshakeError!void {
        var ext: [24]m12.Extension = undefined;
        const dec = m12.decodeClientHello(body, &ext) catch |e| return switch (e) {
            error.DuplicateExtension => error.DuplicateExtension,
            error.TooManyExtensions => error.TooManyExtensions,
            else => error.Malformed,
        };
        // DTLS versions count DOWN: 1.2 is {254,253}, 1.0 {254,255}.
        if (dec.version[0] != 0xfe or dec.version[1] > 0xfd) return error.UnsupportedVersion;
        if (std.mem.indexOfScalar(u8, dec.compression_methods, 0) == null) return error.Malformed;

        if (self.config.hello_retry) |hr| {
            const want = cookieFor(hr, dec);
            const ok = dec.cookie.len == cookie_len and std.crypto.timing_safe.eql([cookie_len]u8, want, dec.cookie[0..cookie_len].*);
            if (!ok) {
                // RFC 6347 §4.2.1: an invalid cookie is treated like none —
                // answer with a HelloVerifyRequest, keep nothing, and reuse
                // the ClientHello's record sequence number.
                var hb: [3 + cookie_len]u8 = undefined;
                const hvr = m12.encodeHelloVerifyRequest(&want, &hb) catch unreachable;
                var msg: [handshake.header_len + hb.len]u8 = undefined;
                frameMessage(m12.HandshakeType.hello_verify_request, 0, hvr, &msg);
                const rec = try plaintextRecord(content_handshake, 0, self.cur_record_seq, msg[0 .. handshake.header_len + hvr.len], o.rest());
                o.len += rec.len;
                self.stateless_reply = true;
                return;
            }
            // RFC 6347 §4.2.1: the first ServerHello reuses the
            // ClientHello's record sequence number.
            self.send_seq[0] = self.cur_record_seq;
        }
        self.message_seq = seq;
        self.client_random = dec.random;
        self.transcript_len = 0;
        try self.appendTranscript(m12.HandshakeType.client_hello, seq, body);

        // Extensions.
        var client_groups: []const u8 = &.{};
        var client_schemes: []const u8 = &.{};
        var alpn_offer: ?[]const u8 = null;
        var srtp_offer: ?[]const u8 = null;
        var ems = false;
        var ri = m12.offersSuite(dec.cipher_suites_raw, m12.empty_renegotiation_info_scsv);
        for (dec.extensions) |e| switch (e.ext_type) {
            m12.ext_supported_groups => client_groups = e.data,
            m12.ext_signature_algorithms => client_schemes = e.data,
            m12.ext_extended_master_secret => ems = true,
            m12.ext_renegotiation_info => {
                if (!std.mem.eql(u8, e.data, &m12.renegotiation_info_initial)) return error.SecureRenegotiationRequired;
                ri = true;
            },
            m12.ext_alpn => alpn_offer = e.data,
            messages.ext_use_srtp => srtp_offer = e.data,
            m12.ext_ec_point_formats => if (!m12.pointFormatsIncludeUncompressed(e.data)) return error.Malformed,
            else => {},
        };
        // RFC 5746 §4.3: a server that never renegotiates MAY complete a
        // handshake with a client that signals neither the extension nor the
        // SCSV — the attack RFC 5746 closes needs a renegotiation, which this
        // module never performs. OpenSSL, wolfSSL and mbedTLS servers do
        // accept such a client; wolfSSL's own 1.2 client (Debian's build,
        // without HAVE_SECURE_RENEGOTIATION) is one. Only a non-empty
        // `renegotiation_info` (above) is refused.
        self.peer_ri = ri;
        if (!ems and self.config.require_extended_master_secret) return error.ExtendedMasterSecretRequired;
        self.ems = ems;

        var peer_groups_buf: [16]u16 = undefined;
        const peer_groups = if (client_groups.len > 0)
            messages.filterU16ListExtension(client_groups, &suite12.groups12, &peer_groups_buf) catch return error.Malformed
        else
            peer_groups_buf[0..0];
        var peer_schemes_buf: [32]u16 = undefined;
        var peer_schemes: []const u16 = &.{};
        if (client_schemes.len > 0) {
            var mine: [32]u16 = undefined;
            peer_schemes = messages.filterU16ListExtension(client_schemes, self.advertisedSchemes(&mine), &peer_schemes_buf) catch return error.Malformed;
        }

        // Suite: our preference, among what the client offered and what this
        // side can actually complete.
        var group: u16 = 0;
        var scheme: u16 = 0;
        const chosen: CipherSuite12 = for (self.config.cipher_suites12) |s| {
            if (!self.offeredSuite(s) or !m12.offersSuite(dec.cipher_suites_raw, @backingInt(s))) continue;
            const kx = s.keyExchange().?;
            if (kx.usesEcdhe()) {
                group = for (suite12.groups12) |g| {
                    if (std.mem.indexOfScalar(u16, peer_groups, g) != null) break g;
                } else continue;
            }
            if (kx.usesCertificate()) {
                scheme = self.selectScheme(peer_schemes, kx) orelse continue;
            }
            break s;
        } else return error.NoCipherSuiteOverlap;
        self.suite = chosen;
        self.kx = chosen.keyExchange().?;

        // ALPN (RFC 7301 §3.2), as the 1.3 server does.
        if (self.config.alpn_protocols.len > 0 and alpn_offer != null) {
            const offer = alpn_offer.?;
            const picked = for (self.config.alpn_protocols) |mine| {
                var it = messages.AlpnIter.init(offer) catch return error.Malformed;
                while (it.next()) |theirs| {
                    if (std.mem.eql(u8, mine, theirs)) break;
                } else continue;
                break mine;
            } else return error.NoApplicationProtocol;
            @memcpy(self.alpn[0..picked.len], picked);
            self.alpn_len = @intCast(picked.len);
        }
        // use_srtp (RFC 5764 §4.1.1), as the 1.3 server does.
        if (self.config.srtp_profiles.len > 0) {
            if (srtp_offer) |offer| {
                const so = messages.decodeUseSrtp(offer) catch return error.Malformed;
                self.srtp_profile = messages.selectSrtpProfile(self.config.srtp_profiles, so) orelse 0;
            }
        }

        source(entropy).bytes(&self.server_random);
        // RFC 8446 §4.1.3: a server that could have spoken 1.3 says so.
        if (self.config.allows(.dtls13)) self.server_random[24..32].* = m12.downgrade_sentinel_12;

        // Flight 4.
        self.tx_len = 0;
        var buf: [max_message_len]u8 = undefined;
        {
            var ext_buf: [300]u8 = undefined;
            var srtp_buf: [5]u8 = undefined;
            var exts: [5]m12.Extension = undefined;
            var n: usize = 0;
            // RFC 5746 §3.6: answered only when the client signalled it
            // (RFC 5246 §7.4.1.4: no unsolicited extensions).
            if (self.peer_ri) {
                exts[n] = .{ .ext_type = m12.ext_renegotiation_info, .data = &m12.renegotiation_info_initial };
                n += 1;
            }
            if (self.ems) {
                exts[n] = .{ .ext_type = m12.ext_extended_master_secret, .data = &.{} };
                n += 1;
            }
            if (self.kx.usesEcdhe() and client_groups.len > 0) {
                exts[n] = .{ .ext_type = m12.ext_ec_point_formats, .data = &m12.ec_point_formats_uncompressed };
                n += 1;
            }
            if (self.alpn_len > 0) {
                const a = try messages.encodeAlpn(&.{self.alpn[0..self.alpn_len]}, &ext_buf);
                exts[n] = .{ .ext_type = m12.ext_alpn, .data = a };
                n += 1;
            }
            if (self.negotiatedSrtpProfile()) |p| {
                exts[n] = .{ .ext_type = messages.ext_use_srtp, .data = try messages.encodeUseSrtp(&.{p}, "", &srtp_buf) };
                n += 1;
            }
            const sh = m12.encodeServerHello(.{ .random = self.server_random, .cipher_suite = @backingInt(self.suite), .extensions = exts[0..n] }, &buf) catch return error.BufferTooShort;
            try self.sendMessage(.handshake_epoch0, m12.HandshakeType.server_hello, sh);
        }
        if (self.kx.usesCertificate()) {
            const cb = m12.encodeCertificate(self.config.cert.?.chain, &buf) catch return error.BufferTooShort;
            try self.sendMessage(.handshake_epoch0, m12.HandshakeType.certificate, cb);
        }
        var ske_len: usize = 0;
        if (self.kx.isPsk() and (self.kx == .ecdhe_psk or self.config.psk_identity_hint.len > 0)) {
            ske_len = (m12.encodeOpaque16(self.config.psk_identity_hint, &buf) catch return error.BufferTooShort).len;
        }
        if (self.kx.usesEcdhe()) {
            var kp: kex.KeyPair = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
            kex.generate(group, source(entropy), &kp) catch return error.KeyExchangeFailed;
            @memcpy(&self.ecdhe_secret, &kp.secret);
            self.ecdhe_live = true;
            self.ecdhe_group = group;
            const params = m12.encodeEcdhParams(group, kp.public[0..kp.public_len], buf[ske_len..]) catch return error.BufferTooShort;
            if (self.kx.usesCertificate()) {
                var content: [64 + 4 + max_point_len]u8 = undefined;
                @memcpy(content[0..32], &self.client_random);
                @memcpy(content[32..64], &self.server_random);
                @memcpy(content[64..][0..params.len], params);
                var sig: [600]u8 = undefined;
                const s = try sig12.sign(scheme, self.config.cert.?.private_key, content[0 .. 64 + params.len], source(entropy), &sig);
                const signed = m12.encodeSigned(scheme, s, buf[ske_len + params.len ..]) catch return error.BufferTooShort;
                ske_len += params.len + signed.len;
            } else ske_len += params.len;
        }
        if (ske_len > 0) try self.sendMessage(.handshake_epoch0, m12.HandshakeType.server_key_exchange, buf[0..ske_len]);
        if (self.kx.usesCertificate() and self.config.request_client_cert) {
            var mine: [32]u16 = undefined;
            const cr = m12.encodeCertificateRequest(self.advertisedSchemes(&mine), &buf) catch return error.BufferTooShort;
            try self.sendMessage(.handshake_epoch0, m12.HandshakeType.certificate_request, cr);
            self.cert_requested = true;
        }
        try self.sendMessage(.handshake_epoch0, m12.HandshakeType.server_hello_done, &.{});
        try self.emitFlight(o);
        self.timer.reset();
        self.timer.arm(now_ms);
        self.state = .wait_client_flight;
        self.last_rank = 0;
    }

    fn serverClientCertificate(self: *Connection12, body: []const u8, transcript_before: usize) HandshakeError!void {
        self.got_certificate = true;
        const leaf = (m12.decodeCertificateLeaf(body) catch return error.Malformed) orelse {
            if (self.config.require_peer_cert) return error.PeerCertificateRequired;
            return;
        };
        try self.checkTrust(leaf, body);
        self.peer_leaf_off = transcript_before + handshake.header_len + (@intFromPtr(leaf.ptr) - @intFromPtr(body.ptr));
        self.peer_leaf_len = leaf.len;
        self.client_cert_presented = true;
    }

    fn serverClientKeyExchange(self: *Connection12, body: []const u8) HandshakeError!void {
        var rest = body;
        if (self.kx.isPsk()) {
            const id = m12.decodeOpaque16(body) catch return error.Malformed;
            if (!std.mem.eql(u8, id.data, self.config.psk_identity)) return error.NoMatchingPskIdentity;
            rest = id.rest;
        }
        var z: kex.SharedSecret = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&z));
        if (self.kx.usesEcdhe()) {
            const point = m12.decodePoint(rest) catch return error.Malformed;
            if (point.len != kex.expectedShareLen(self.ecdhe_group)) return error.MissingKeyShare;
            kex.sharedSecret(self.ecdhe_group, &self.ecdhe_secret, point, &z) catch return error.KeyExchangeFailed;
            std.crypto.secureZero(u8, &self.ecdhe_secret);
            self.ecdhe_live = false;
        } else if (rest.len != 0) return error.Malformed;
        var pms: [2 + @max(80, max_psk_len) + 2 + max_psk_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &pms);
        const n = try self.premaster(if (self.kx.usesEcdhe()) z.slice() else null, &pms);
        self.deriveKeys(pms[0..n]);
        self.got_cke = true;
        if (self.cert_requested and self.config.require_peer_cert and !self.client_cert_presented) return error.PeerCertificateRequired;
    }

    fn serverFinalFlight(self: *Connection12, o: *Out) HandshakeError!void {
        self.tx_len = 0;
        try self.cacheEntry(.change_cipher_spec, &.{1});
        var th: suitehash.Secret = undefined;
        const vd = prf12.finishedVerifyData(self.suite.hash(), &self.master, false, self.transcriptHash(&th));
        try self.sendMessage(.handshake_epoch1, m12.HandshakeType.finished, &vd);
        try self.emitFlight(o);
        self.timer.reset();
        self.state = .connected;
    }

    // ── shared crypto helpers ───────────────────────────────────────────

    /// RFC 4279 §2 / RFC 5489 §2 / RFC 8422 §5.10 premaster secret.
    fn premaster(self: *const Connection12, z: ?[]const u8, out: []u8) HandshakeError!usize {
        if (!self.kx.isPsk()) {
            const s = z.?;
            @memcpy(out[0..s.len], s);
            return s.len;
        }
        const psk = self.config.psk;
        if (psk.len > max_psk_len) return error.KeyExchangeFailed;
        // other_secret: N zero bytes for plain PSK, the ECDH Z for ECDHE_PSK.
        const other_len: usize = if (z) |s| s.len else psk.len;
        std.mem.writeInt(u16, out[0..2], @intCast(other_len), .big);
        if (z) |s| @memcpy(out[2..][0..s.len], s) else @memset(out[2..][0..other_len], 0);
        std.mem.writeInt(u16, out[2 + other_len ..][0..2], @intCast(psk.len), .big);
        @memcpy(out[4 + other_len ..][0..psk.len], psk);
        return 4 + other_len + psk.len;
    }

    /// Master secret (RFC 7627 when negotiated) and the key block; the
    /// client's write keys are the server's read keys and vice versa.
    fn deriveKeys(self: *Connection12, pms: []const u8) void {
        const alg = self.suite.hash();
        var sh: suitehash.Secret = undefined;
        const session_hash = self.transcriptHash(&sh);
        prf12.masterSecret(alg, pms, self.ems, &self.client_random, &self.server_random, session_hash, &self.master);
        const bulk = self.suite.bulk();
        const kl = bulk.keyLen();
        const il = bulk.fixedIvLen();
        var kb: [2 * 32 + 2 * 12]u8 = undefined;
        defer std.crypto.secureZero(u8, &kb);
        prf12.keyBlock(alg, &self.master, &self.client_random, &self.server_random, kb[0 .. 2 * kl + 2 * il]);
        var ck = record12.DirKeys{ .bulk = bulk };
        var sk = record12.DirKeys{ .bulk = bulk };
        ck.key = @splat(0);
        sk.key = @splat(0);
        ck.iv = @splat(0);
        sk.iv = @splat(0);
        @memcpy(ck.key[0..kl], kb[0..kl]);
        @memcpy(sk.key[0..kl], kb[kl..][0..kl]);
        @memcpy(ck.iv[0..il], kb[2 * kl ..][0..il]);
        @memcpy(sk.iv[0..il], kb[2 * kl + il ..][0..il]);
        switch (self.role) {
            .client => {
                self.write_keys = ck;
                self.read_keys = sk;
            },
            .server => {
                self.write_keys = sk;
                self.read_keys = ck;
            },
        }
        ck.wipe();
        sk.wipe();
        self.keys_live = true;
    }

    fn transcriptHash(self: *const Connection12, out: *suitehash.Secret) []const u8 {
        const t = self.transcript[0..self.transcript_len];
        switch (self.suite.hash()) {
            .sha256 => std.crypto.hash.sha2.Sha256.hash(t, out[0..32], .{}),
            .sha384 => std.crypto.hash.sha2.Sha384.hash(t, out[0..48], .{}),
        }
        return out[0..self.suite.hash().len()];
    }

    /// The schemes this side offers / accepts in 1.2: `Config
    /// .signature_algorithms` (minus ML-DSA, which has no TLS 1.2 code
    /// point), then the PKCS#1 v1.5 pair.
    fn advertisedSchemes(self: *const Connection12, buf: *[32]u16) []const u16 {
        var n: usize = 0;
        for (self.config.signature_algorithms) |s| {
            switch (s) {
                .mldsa44, .mldsa65, .mldsa87 => continue,
                else => {},
            }
            if (n == buf.len - sig12.pkcs1_schemes.len) break;
            buf[n] = @backingInt(s);
            n += 1;
        }
        for (sig12.pkcs1_schemes) |s| {
            buf[n] = s;
            n += 1;
        }
        return buf[0..n];
    }

    fn schemeFitsSuite(scheme: u16, kx: ?KeyExchange12) bool {
        const k = kx orelse return true;
        const rsa_scheme = sig12.isPkcs1(scheme) or (scheme >= 0x0804 and scheme <= 0x0806);
        return switch (k) {
            .ecdhe_rsa => rsa_scheme,
            .ecdhe_ecdsa => !rsa_scheme,
            else => false,
        };
    }

    /// Our first advertised scheme the peer accepts, this side's key can
    /// produce and (for a ServerKeyExchange) the suite's family allows.
    fn selectScheme(self: *const Connection12, peer: []const u16, kx: ?KeyExchange12) ?u16 {
        const cert = self.config.cert orelse return null;
        var mine: [32]u16 = undefined;
        for (self.advertisedSchemes(&mine)) |s| {
            if (std.mem.indexOfScalar(u16, peer, s) == null) continue;
            if (!schemeFitsSuite(s, kx)) continue;
            if (!sig12.canSign(cert.private_key, s)) continue;
            return s;
        }
        return null;
    }

    /// `body` is the whole Certificate message (`.chain` reads every
    /// certificate of it).
    fn checkTrust(self: *const Connection12, leaf: []const u8, body: []const u8) HandshakeError!void {
        _ = certauth.parseLeafPublicKey(leaf) catch return error.CertificateRejected;
        switch (self.config.peer_verify) {
            .none => {},
            .trust_anchor => |anchor| certauth.verifyLeafAgainstAnchor(leaf, anchor, self.config.now_sec, self.config.expected_peer_name) catch return error.CertificateRejected,
            .verify_fn => |f| f(leaf) catch return error.CertificateRejected,
            .chain => |cv| {
                var ders: [certauth.max_chain_certs][]const u8 = undefined;
                const certs = m12.decodeCertificateList(body, &ders) catch return error.CertificateRejected;
                certauth.verifyPeerChain(certs, cv.trust_anchors, self.config.now_sec, self.config.expected_peer_name, cv.required_eku, cv.revocation) catch
                    return error.CertificateRejected;
            },
        }
    }

    fn verifyPeerSignature(self: *const Connection12, signed: m12.Signed, content: []const u8, kx: ?KeyExchange12) HandshakeError!void {
        var mine: [32]u16 = undefined;
        if (std.mem.indexOfScalar(u16, self.advertisedSchemes(&mine), signed.scheme) == null) return error.SignatureSchemeNotAdvertised;
        if (!schemeFitsSuite(signed.scheme, kx)) return error.CertVerifyFailed;
        const leaf = self.transcript[self.peer_leaf_off..][0..self.peer_leaf_len];
        const pk = certauth.parseLeafPublicKey(leaf) catch return error.CertificateRejected;
        sig12.verify(signed.scheme, pk, content, signed.signature) catch return error.CertVerifyFailed;
    }

    fn verifyCertificateVerify(self: *const Connection12, body: []const u8) HandshakeError!void {
        const signed = m12.decodeSigned(body) catch return error.Malformed;
        // RFC 5246 §7.4.8: over all handshake messages so far.
        try self.verifyPeerSignature(signed, self.transcript[0..self.transcript_len], null);
    }

    // ── transcript, cache, record output ────────────────────────────────

    fn appendTranscript(self: *Connection12, t: u8, seq: u16, body: []const u8) HandshakeError!void {
        if (transcript_cap - self.transcript_len < handshake.header_len + body.len) return error.FlightTooLarge;
        frameMessage(t, seq, body, self.transcript[self.transcript_len..][0 .. handshake.header_len + body.len]);
        self.transcript_len += handshake.header_len + body.len;
    }

    fn cacheEntry(self: *Connection12, kind: TxKind, bytes: []const u8) HandshakeError!void {
        if (tx_cap - self.tx_len < 3 + bytes.len) return error.BufferTooShort;
        self.tx[self.tx_len] = @backingInt(kind);
        std.mem.writeInt(u16, self.tx[self.tx_len + 1 ..][0..2], @intCast(bytes.len), .big);
        @memcpy(self.tx[self.tx_len + 3 ..][0..bytes.len], bytes);
        self.tx_len += 3 + bytes.len;
    }

    fn cacheMessage(self: *Connection12, kind: TxKind, t: u8, seq: u16, body: []const u8) HandshakeError!void {
        if (tx_cap - self.tx_len < 3 + handshake.header_len + body.len) return error.BufferTooShort;
        self.tx[self.tx_len] = @backingInt(kind);
        std.mem.writeInt(u16, self.tx[self.tx_len + 1 ..][0..2], @intCast(handshake.header_len + body.len), .big);
        frameMessage(t, seq, body, self.tx[self.tx_len + 3 ..][0 .. handshake.header_len + body.len]);
        self.tx_len += 3 + handshake.header_len + body.len;
    }

    /// Appends one outgoing message to the transcript and the flight cache
    /// under the next `message_seq`.
    fn sendMessage(self: *Connection12, kind: TxKind, t: u8, body: []const u8) HandshakeError!void {
        try self.appendTranscript(t, self.message_seq, body);
        try self.cacheMessage(kind, t, self.message_seq, body);
        self.message_seq +%= 1;
    }

    /// (Re-)encodes the cached flight into records with fresh sequence
    /// numbers, appended to `o`. With `Config.max_datagram_len` set, a
    /// handshake message whose record would be larger is split into RFC 6347
    /// §4.2.3 fragments (`handshake.Fragmenter`, as for 1.3) so that no
    /// record exceeds it; `record.nextDatagram` then packs them.
    fn emitFlight(self: *Connection12, o: *Out) HandshakeError!void {
        var i: usize = 0;
        while (i < self.tx_len) {
            const kind: TxKind = @fromBackingInt(self.tx[i]);
            const n: usize = std.mem.readInt(u16, self.tx[i + 1 ..][0..2], .big);
            const bytes = self.tx[i + 3 ..][0..n];
            i += 3 + n;
            const limit: usize = self.config.max_datagram_len;
            // Only epoch-0 messages can need it: the one epoch-1 handshake
            // message is Finished (12 + 12 bytes), and `Config.validate`
            // keeps `limit` above its sealed record.
            if (kind != .handshake_epoch0 or limit == 0 or record.plaintext_header_len + bytes.len <= limit) {
                try self.emitRecord(kind, bytes, o);
                continue;
            }
            const frag_cap = limit - record.plaintext_header_len - handshake.header_len;
            const hh = handshake.decodeHeader(bytes) catch unreachable; // framed by `cacheMessage`
            var fr = handshake.Fragmenter.init(hh.msg_type, hh.message_seq, bytes[handshake.header_len..]);
            while (fr.pos < fr.body.len) {
                const take = @min(frag_cap, fr.body.len - fr.pos);
                const dst = o.rest();
                if (dst.len < record.plaintext_header_len + handshake.header_len + take) return error.BufferTooShort;
                const frag = fr.next(take, dst[record.plaintext_header_len..]) orelse break;
                if (self.send_seq[0] == max_send_seq) return error.SequenceNumberExhausted;
                _ = try record.encodePlaintext(.{ .content_type = content_handshake, .epoch = 0, .sequence_number = self.send_seq[0], .length = @intCast(frag.len) }, dst);
                self.send_seq[0] += 1;
                o.len += record.plaintext_header_len + frag.len;
            }
        }
    }

    /// One record of the flight: plaintext in epoch 0, sealed in epoch 1.
    fn emitRecord(self: *Connection12, kind: TxKind, bytes: []const u8, o: *Out) HandshakeError!void {
        switch (kind) {
            .handshake_epoch0, .change_cipher_spec => {
                if (self.send_seq[0] == max_send_seq) return error.SequenceNumberExhausted;
                const ct = if (kind == .change_cipher_spec) content_change_cipher_spec else content_handshake;
                const rec = try plaintextRecord(ct, 0, self.send_seq[0], bytes, o.rest());
                self.send_seq[0] += 1;
                o.len += rec.len;
            },
            .handshake_epoch1 => {
                if (self.send_seq[1] == max_send_seq) return error.SequenceNumberExhausted;
                const rec = record12.seal(&self.write_keys, 1, self.send_seq[1], content_handshake, bytes, o.rest()) catch return error.BufferTooShort;
                self.send_seq[1] += 1;
                o.len += rec.len;
            },
        }
    }
};

fn frameMessage(t: u8, seq: u16, body: []const u8, out: []u8) void {
    var hdr: [handshake.header_len]u8 = undefined;
    handshake.encodeHeader(.{ .msg_type = t, .length = @intCast(body.len), .message_seq = seq, .fragment_offset = 0, .fragment_length = @intCast(body.len) }, &hdr);
    @memcpy(out[0..handshake.header_len], &hdr);
    @memcpy(out[handshake.header_len..][0..body.len], body);
}

fn plaintextRecord(content_type: u8, epoch: u16, seq: u48, payload: []const u8, out: []u8) HandshakeError![]u8 {
    if (out.len < record.plaintext_header_len + payload.len or payload.len > std.math.maxInt(u16)) return error.BufferTooShort;
    _ = try record.encodePlaintext(.{ .content_type = content_type, .epoch = epoch, .sequence_number = seq, .length = @intCast(payload.len) }, out);
    @memcpy(out[record.plaintext_header_len..][0..payload.len], payload);
    return out[0 .. record.plaintext_header_len + payload.len];
}

/// RFC 6347 §4.2.2 `message_seq` ordering with wrap-around (a handshake
/// never gets near 2^15 messages; this just keeps the comparison total).
fn messageSeqBefore(a: u16, b: u16) bool {
    return a != b and (b -% a) < 0x8000;
}

// ── audit (whole-module mutation): private-helper pins ────────

test "audit: transcript and flight-cache appends refuse one byte over their caps and fill them exactly" {
    var c: Connection12 = .{ .role = .client, .config = auditCfg() };
    const body: [5]u8 = @splat(1);
    c.transcript_len = transcript_cap - handshake.header_len - body.len;
    try c.appendTranscript(1, 0, &body);
    try std.testing.expectEqual(@as(usize, transcript_cap), c.transcript_len);
    c.transcript_len = transcript_cap - handshake.header_len - body.len + 1;
    try std.testing.expectError(error.FlightTooLarge, c.appendTranscript(1, 0, &body));
    c.tx_len = tx_cap - 3 - body.len;
    try c.cacheEntry(.change_cipher_spec, &body);
    try std.testing.expectEqual(@as(usize, tx_cap), c.tx_len);
    c.tx_len = tx_cap - 3 - body.len + 1;
    try std.testing.expectError(error.BufferTooShort, c.cacheEntry(.change_cipher_spec, &body));
    c.tx_len = tx_cap - 3 - handshake.header_len - body.len;
    try c.cacheMessage(.handshake_epoch0, 1, 0, &body);
    try std.testing.expectEqual(@as(usize, tx_cap), c.tx_len);
    c.tx_len = tx_cap - 3 - handshake.header_len - body.len + 1;
    try std.testing.expectError(error.BufferTooShort, c.cacheMessage(.handshake_epoch0, 1, 0, &body));
}

test "audit: advertisedSchemes keeps room for the PKCS#1 pair however long the configured list is" {
    var cfg = auditCfg();
    const many: [40]certverify.SignatureScheme = @splat(.ecdsa_secp256r1_sha256);
    cfg.signature_algorithms = &many;
    const c: Connection12 = .{ .role = .client, .config = cfg };
    var buf: [32]u16 = undefined;
    const s = c.advertisedSchemes(&buf);
    try std.testing.expectEqual(@as(usize, 32), s.len);
    try std.testing.expectEqualSlices(u16, &sig12.pkcs1_schemes, s[30..]);
}

test "audit: selectScheme honours the suite family and what the key can sign" {
    var sk = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(audit_kat.server_secret_key_bytes);
    var cfg = auditCfg();
    cfg.cert = .{ .chain = &.{&audit_kat.server_cert_der}, .private_key = .{ .ecdsa_p256 = &sk } };
    cfg.signature_algorithms = &.{ .ecdsa_secp384r1_sha384, .ecdsa_secp256r1_sha256 };
    const c: Connection12 = .{ .role = .server, .config = cfg };
    const peer = [_]u16{ 0x0503, 0x0403 };
    // A P-256 key signs only ecdsa_secp256r1_sha256, whatever comes first.
    try std.testing.expectEqual(@as(?u16, 0x0403), c.selectScheme(&peer, .ecdhe_ecdsa));
    // An ECDSA key cannot serve an ECDHE_RSA suite.
    try std.testing.expectEqual(@as(?u16, null), c.selectScheme(&peer, .ecdhe_rsa));
}

test "audit: verifyPeerSignature checks the scheme was advertised and fits the suite before the signature" {
    var sk = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(audit_kat.server_secret_key_bytes);
    var cfg = auditCfg();
    cfg.signature_algorithms = &.{.ecdsa_secp256r1_sha256};
    var c: Connection12 = .{ .role = .client, .config = cfg };
    const leaf = &audit_kat.server_cert_der;
    @memcpy(c.transcript[0..leaf.len], leaf);
    c.transcript_len = leaf.len;
    c.peer_leaf_off = 0;
    c.peer_leaf_len = leaf.len;
    const content = "server key exchange params";
    var csprng = std.Random.DefaultCsprng.init(@splat(5));
    var sig_buf: [128]u8 = undefined;
    const sig = try sig12.sign(0x0403, .{ .ecdsa_p256 = &sk }, content, csprng.random(), &sig_buf);
    // Genuine: accepted for an ECDHE_ECDSA suite.
    try c.verifyPeerSignature(.{ .scheme = 0x0403, .signature = sig }, content, .ecdhe_ecdsa);
    // The same valid signature for an ECDHE_RSA suite: the family is wrong.
    try std.testing.expectError(error.CertVerifyFailed, c.verifyPeerSignature(.{ .scheme = 0x0403, .signature = sig }, content, .ecdhe_rsa));
    // A scheme this side never advertised is refused by name.
    try std.testing.expectError(error.SignatureSchemeNotAdvertised, c.verifyPeerSignature(.{ .scheme = 0x0503, .signature = sig }, content, .ecdhe_ecdsa));
}

test "audit: CertificateRequest schemes: the last one is kept, the list is capped" {
    var c: Connection12 = .{ .role = .client, .config = auditCfg() };
    c.kx = .ecdhe_ecdsa;
    var buf: [256]u8 = undefined;
    try c.clientCertificateRequest(try m12.encodeCertificateRequest(&.{0x0403}, &buf));
    try std.testing.expectEqualSlices(u16, &.{0x0403}, c.peer_schemes[0..c.peer_schemes_len]);
    var many: [40]u16 = undefined;
    for (&many, 0..) |*s, i| s.* = @intCast(0x0800 + i);
    c.cert_requested = false;
    try c.clientCertificateRequest(try m12.encodeCertificateRequest(&many, &buf));
    try std.testing.expectEqual(@as(usize, c.peer_schemes.len), c.peer_schemes_len);
    try std.testing.expectEqual(@as(u16, 0x0800 + 31), c.peer_schemes[31]);
}

test "audit: plaintextRecord takes a u16-sized payload and not one byte more" {
    const a = std.testing.allocator;
    const payload = try a.alloc(u8, 65536);
    defer a.free(payload);
    @memset(payload, 7);
    const out = try a.alloc(u8, 65536 + record.plaintext_header_len);
    defer a.free(out);
    const rec = try plaintextRecord(content_handshake, 0, 1, payload[0..65535], out);
    try std.testing.expectEqual(@as(usize, 65535 + record.plaintext_header_len), rec.len);
    try std.testing.expectError(error.BufferTooShort, plaintextRecord(content_handshake, 0, 1, payload, out));
}

test "audit: an epoch-1 flight entry at the last sequence number is refused, not wrapped" {
    var c: Connection12 = .{ .role = .client, .config = auditCfg() };
    c.write_keys = .{ .key = @splat(1), .iv = @splat(2) };
    c.send_seq[1] = max_send_seq;
    var out: [128]u8 = undefined;
    var o = Out{ .buf = &out };
    try std.testing.expectError(error.SequenceNumberExhausted, c.emitRecord(.handshake_epoch1, "finished", &o));
}

test "audit: a fragmented flight fits an output buffer of exactly its size" {
    var cfg = auditCfg();
    cfg.max_datagram_len = 100;
    var c: Connection12 = .{ .role = .client, .config = cfg };
    const body: [250]u8 = @splat(3);
    try c.cacheMessage(.handshake_epoch0, 1, 0, &body);
    var big: [1024]u8 = undefined;
    var o = Out{ .buf = &big };
    try c.emitFlight(&o);
    const need = o.len;
    try std.testing.expect(need > 250 + 3 * (record.plaintext_header_len + handshake.header_len) - 1);
    c.send_seq[0] = 0;
    var exact = Out{ .buf = big[0..need] };
    try c.emitFlight(&exact);
    try std.testing.expectEqual(need, exact.len);
}

test "audit: epoch-1 records before and after the ChangeCipherSpec" {
    var csprng = std.Random.DefaultCsprng.init(@splat(6));
    const ent: Entropy = .{ .seeded_for_test = csprng.random() };
    var c: Connection12 = .{ .role = .client, .config = auditCfg(), .state = .wait_server_finished };
    var ob: [256]u8 = undefined;
    var o = Out{ .buf = &ob };
    // Before the peer's CCS an epoch-1 record cannot be read: dropped, no error.
    const junk: [40]u8 = @splat(9);
    try c.processRecord(.{ .content_type = content_handshake, .epoch = 1, .sequence_number = 0, .length = junk.len }, &junk, ent, 0, &o);
    // One record the size of the plaintext buffer plus overhead is opened (and fails
    // authentication), not refused for size.
    c.read_epoch = 1;
    c.keys_live = true;
    c.read_keys = .{ .key = @splat(4), .iv = @splat(5) };
    var big: [max_plain + 24]u8 = @splat(0);
    try std.testing.expectError(error.DecryptionFailed, c.processRecord(.{ .content_type = content_handshake, .epoch = 1, .sequence_number = 1, .length = big.len }, &big, ent, 0, &o));
    // A genuine epoch-1 alert is reported once; its replay is dropped.
    var rb: [64]u8 = undefined;
    const alert = try record12.seal(&c.read_keys, 1, 7, content_alert, &.{ 1, 0 }, &rb);
    const hdr = try record.decodePlaintext(alert);
    try std.testing.expectError(error.ReceivedAlert, c.processRecord(hdr, alert[record.plaintext_header_len..], ent, 0, &o));
    try c.processRecord(hdr, alert[record.plaintext_header_len..], ent, 0, &o);
    // A ChangeCipherSpec under epoch 1 is a protocol violation.
    var cb: [64]u8 = undefined;
    const ccs1 = try record12.seal(&c.read_keys, 1, 8, content_change_cipher_spec, &.{1}, &cb);
    const h1 = try record.decodePlaintext(ccs1);
    try std.testing.expectError(error.UnexpectedMessage, c.processRecord(h1, ccs1[record.plaintext_header_len..], ent, 0, &o));
    // A retransmitted epoch-0 CCS after ours took effect marks a duplicate.
    c.saw_duplicate = false;
    try c.processRecord(.{ .content_type = content_change_cipher_spec, .epoch = 0, .sequence_number = 3, .length = 1 }, &.{1}, ent, 0, &o);
    try std.testing.expect(c.saw_duplicate);
    try std.testing.expectEqual(@as(u16, 1), c.read_epoch);
}

test "audit: an early epoch-0 ChangeCipherSpec is dropped, not taken for a retransmission; alerts are two bytes" {
    var csprng = std.Random.DefaultCsprng.init(@splat(7));
    const ent: Entropy = .{ .seeded_for_test = csprng.random() };
    var c: Connection12 = .{ .role = .client, .config = auditCfg(), .state = .wait_server_hello_done };
    var ob: [256]u8 = undefined;
    var o = Out{ .buf = &ob };
    try c.processRecord(.{ .content_type = content_change_cipher_spec, .epoch = 0, .sequence_number = 1, .length = 1 }, &.{1}, ent, 0, &o);
    try std.testing.expect(!c.saw_duplicate);
    try std.testing.expectEqual(@as(u16, 0), c.read_epoch);
    try std.testing.expectError(error.Malformed, c.processRecord(.{ .content_type = content_alert, .epoch = 0, .sequence_number = 2, .length = 1 }, &.{2}, ent, 0, &o));
    try std.testing.expectError(error.Malformed, c.processRecord(.{ .content_type = content_alert, .epoch = 0, .sequence_number = 3, .length = 3 }, &.{ 2, 40, 0 }, ent, 0, &o));
    try std.testing.expectEqual(@as(?[2]u8, null), c.peer_alert);
}

/// One handshake fragment: `body_len` bytes of a `total`-byte message.
fn testFragment(message_seq: u16, total: u24, body_len: u24, out: []u8) []const u8 {
    handshake.encodeHeader(.{ .msg_type = m12.HandshakeType.certificate, .length = total, .message_seq = message_seq, .fragment_offset = 0, .fragment_length = body_len }, out[0..handshake.header_len]);
    @memset(out[handshake.header_len..][0..body_len], 0x5a);
    return out[0 .. handshake.header_len + body_len];
}

test "epoch-0 replay window: only a record that advanced the handshake is recorded" {
    var csprng = std.Random.DefaultCsprng.init(@splat(9));
    const ent: Entropy = .{ .seeded_for_test = csprng.random() };
    var c: Connection12 = .{ .role = .client, .config = auditCfg(), .state = .wait_server_hello_done, .next_recv_seq = 2 };
    var ob: [256]u8 = undefined;
    var o = Out{ .buf = &ob };
    var fb: [64]u8 = undefined;
    const huge: u48 = std.math.maxInt(u48);
    const hs = content_handshake;

    // Well-formed but advancing nothing: a later message (queued), an
    // earlier one (a duplicate), an early ChangeCipherSpec, application
    // data. None of them may move the window, whatever its record number.
    const later = testFragment(3, 40, 10, &fb);
    try c.processRecord(.{ .content_type = hs, .epoch = 0, .sequence_number = huge, .length = @intCast(later.len) }, later, ent, 0, &o);
    try std.testing.expect(c.rx_future_len > 0);
    const earlier = testFragment(1, 40, 40, &fb);
    try c.processRecord(.{ .content_type = hs, .epoch = 0, .sequence_number = huge - 1, .length = @intCast(earlier.len) }, earlier, ent, 0, &o);
    try std.testing.expect(c.saw_duplicate);
    try c.processRecord(.{ .content_type = content_change_cipher_spec, .epoch = 0, .sequence_number = huge - 2, .length = 1 }, &.{1}, ent, 0, &o);
    try c.processRecord(.{ .content_type = content_application_data, .epoch = 0, .sequence_number = huge - 3, .length = 1 }, &.{1}, ent, 0, &o);
    try std.testing.expect(!c.recv_win[0].seen_any);

    // A partial fragment of the expected message is taken but not recorded,
    // even under a low record number: its bytes are as unauthenticated as
    // any (one forged byte with a huge record number would otherwise shadow
    // every genuine record).
    const cur = testFragment(2, 40, 10, &fb);
    try c.processRecord(.{ .content_type = hs, .epoch = 0, .sequence_number = 5, .length = @intCast(cur.len) }, cur, ent, 0, &o);
    try std.testing.expectEqual(@as(usize, 10), c.rx_filled);
    try std.testing.expect(!c.recv_win[0].seen_any);

    // A message that completes in one record with as many bytes as the
    // previous one changes only `next_recv_seq`: recorded as well (this one
    // is then refused by the handshake layer, which `handleFlight` rolls
    // back, window included).
    var m: Connection12 = .{ .role = .client, .config = auditCfg(), .state = .wait_server_finished, .next_recv_seq = 2, .rx_filled = 10 };
    const whole = testFragment(2, 10, 10, &fb);
    try std.testing.expectError(error.UnexpectedMessage, m.processRecord(.{ .content_type = hs, .epoch = 0, .sequence_number = 6, .length = @intCast(whole.len) }, whole, ent, 0, &o));
    try std.testing.expectEqual(@as(u16, 3), m.next_recv_seq);
    try std.testing.expectEqual(@as(usize, 10), m.rx_filled);
    try std.testing.expectEqual(@as(u48, 6), m.recv_win[0].high);

    // A genuine ChangeCipherSpec advances the read epoch: recorded too, so
    // its verbatim replay is dropped by the window instead of reaching the
    // handshake layer as a retransmission (which would resend our flight).
    var k: Connection12 = .{ .role = .client, .config = auditCfg(), .state = .wait_server_finished, .keys_live = true };
    const ccs: record.PlaintextHeader = .{ .content_type = content_change_cipher_spec, .epoch = 0, .sequence_number = 7, .length = 1 };
    try k.processRecord(ccs, &.{1}, ent, 0, &o);
    try std.testing.expectEqual(@as(u16, 1), k.read_epoch);
    try std.testing.expectEqual(@as(u48, 7), k.recv_win[0].high);
    try k.processRecord(ccs, &.{1}, ent, 0, &o);
    try std.testing.expect(!k.saw_duplicate);
    // The same ChangeCipherSpec under a new record number is a retransmission.
    try k.processRecord(.{ .content_type = content_change_cipher_spec, .epoch = 0, .sequence_number = 8, .length = 1 }, &.{1}, ent, 0, &o);
    try std.testing.expect(k.saw_duplicate);
    try std.testing.expectEqual(@as(u48, 7), k.recv_win[0].high);
}

test "epoch-0 replay window: an unauthenticated record moves the high mark at most one window width" {
    var w: Window = .{};
    w.recordUnauthenticated(epoch0_max_jump + 1);
    try std.testing.expect(!w.seen_any);
    w.recordUnauthenticated(epoch0_max_jump);
    try std.testing.expectEqual(@as(u48, epoch0_max_jump), w.high);
    w.recordUnauthenticated(3 * epoch0_max_jump + 1);
    try std.testing.expectEqual(@as(u48, epoch0_max_jump), w.high);
    w.recordUnauthenticated(2 * epoch0_max_jump);
    try std.testing.expectEqual(@as(u48, 2 * epoch0_max_jump), w.high);
    w.recordUnauthenticated(std.math.maxInt(u48));
    try std.testing.expectEqual(@as(u48, 2 * epoch0_max_jump), w.high);
    // Behind the high mark: recorded as usual (a duplicate is then refused).
    w.recordUnauthenticated(2 * epoch0_max_jump - 5);
    try std.testing.expect(!w.fresh(2 * epoch0_max_jump - 5));
}

test "audit: the future-message queue takes a fragment that fills it exactly" {
    var c: Connection12 = .{ .role = .client, .config = auditCfg(), .state = .wait_server_hello_done, .next_recv_seq = 1 };
    var frag: [max_future_bytes - future_entry_header]u8 = undefined;
    @memset(&frag, 1);
    c.stashFuture(.{ .msg_type = m12.HandshakeType.certificate, .length = frag.len, .message_seq = 2, .fragment_offset = 0, .fragment_length = frag.len }, &frag, 0);
    try std.testing.expectEqual(@as(usize, max_future_bytes), c.rx_future_len);
    c.stashFuture(.{ .msg_type = m12.HandshakeType.certificate, .length = 1, .message_seq = 3, .fragment_offset = 0, .fragment_length = 1 }, frag[0..1], 0);
    try std.testing.expectEqual(@as(usize, max_future_bytes), c.rx_future_len);
}

const audit_kat = @import("certauth_kat_vectors.zig");

fn auditCfg() Config {
    return .{ .role = .client, .versions = &.{.dtls12}, .psk_identity = "audit", .psk = "audit-psk" };
}
