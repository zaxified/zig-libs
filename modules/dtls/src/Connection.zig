// SPDX-License-Identifier: MIT

//! dtls.Connection — the public, top-level PSK-mode DTLS 1.3 client/server
//! API surface. Wires `record.zig`/`messages.zig`/`handshake.zig`/
//! `flight.zig` framing to the real `keyschedule.zig`/`aead.zig` crypto
//! core, and drives both through a real RFC 9147 §5 PSK-only handshake
//! flight engine (`startHandshake`/`handleFlight`/`poll`).
//!
//! **What is real here:** `Config.validate`, `clientInit`/`serverInit`, the
//! application-data record path — `installApplicationKeys` (derive the
//! per-direction AEAD key / static IV / sequence-number key from a
//! completed handshake's traffic secrets) plus `send`/`recv`, which perform
//! RFC 9147 §4.2 AEAD record protection AND §4.2.3 sequence-number
//! encryption over the unified record header, for the two validated
//! 12-byte-nonce suites (`aes_128_gcm_sha256`, `chacha20_poly1305_sha256`)
//! — AND the handshake flight engine itself: `startHandshake` builds and
//! sends a real ClientHello (PSK identity + binder over the running
//! transcript); `handleFlight` drives both roles through ServerHello /
//! EncryptedExtensions / Finished, verifying the PSK binder and both
//! Finished `verify_data`s with constant-time compares, deriving the full
//! RFC 8446 §7.1 key schedule (early → handshake → master → application
//! secrets) via `keyschedule.zig`, and installing application keys via the
//! existing `installApplicationKeys` once both sides are mutually
//! confirmed; `poll` retransmits the last flight on a caller-clocked timer
//! (`flight.RetransmitTimer`) if the peer's next flight hasn't arrived.
//! Proven end-to-end by a real in-memory client↔server interop test (see
//! this file's tests) — no external DTLS peer required.
//!
//! **Deliberately out of scope** (see `startHandshake`'s doc comment and
//! `root.zig` for the full list): HelloRetryRequest/cookie retry, 0-RTT,
//! session resumption, key update, and (inherited from `aead.zig`) the CCM
//! suites.

const std = @import("std");
const messages = @import("messages.zig");
const keyschedule = @import("keyschedule.zig");
const aead = @import("aead.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const flight = @import("flight.zig");
const engine = @import("engine.zig");

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

pub const HandshakeError = messages.MessageError || handshake.FrameError || handshake.ReassembleError || record.RecordError || aead.RecordProtectionError || SendError || error{
    /// `startHandshake`/`handleFlight` called from a `State` that doesn't
    /// expect it (e.g. `handleFlight` on a client not in
    /// `.wait_server_hello`, or a server that already saw a ClientHello).
    WrongState,
    UnsupportedSuite,
    /// The peer's offered cipher suites share nothing with this side's
    /// `Config.cipher_suites` (restricted to suites this module can
    /// actually protect records with — see `suiteParams`).
    NoCipherSuiteOverlap,
    /// The ClientHello's PSK identity doesn't match this `Connection`'s
    /// configured `psk_identity` (PSK mode here is single-identity; see
    /// `Config`).
    NoMatchingPskIdentity,
    /// RFC 8446 §4.2.11.2: the offered PSK binder doesn't verify against
    /// this side's PSK — either a wrong PSK or a tampered ClientHello.
    BinderVerifyFailed,
    /// RFC 8446 §4.4.4: the peer's Finished `verify_data` doesn't match —
    /// either a wrong PSK/transcript mismatch or a tampered flight.
    FinishedVerifyFailed,
    /// RFC 8446 §4.1.4 HelloRetryRequest was detected (the ServerHello
    /// `random` matched the magic constant) — this engine implements the
    /// psk_ke happy path only, not the cookie/retry round trip.
    HelloRetryRequestUnsupported,
    /// A decoded handshake message had the wrong `msg_type`/content type
    /// for the state the connection is in.
    UnexpectedMessage,
    /// A peer sent a handshake message across more than one DTLS fragment.
    /// This engine only ever SENDS single-fragment messages (they're all
    /// small enough), and only ever RECEIVES single-fragment messages from
    /// itself in the loopback tests; genuine multi-datagram reassembly
    /// across `handleFlight` calls is out of scope (`handshake.zig`'s
    /// `Reassembler` is still exercised — see `reassembleFragment` below —
    /// just not carried across calls).
    FragmentedMessageUnsupported,
};

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

/// Per-epoch record-layer sequence-number bookkeeping (send + receive-side
/// reconstruction window state) — the handshake epochs' analogue of
/// `Connection`'s own `send_seq`/`recv_max_seq`/`recv_seen_any` fields,
/// which are reserved for the application epoch.
const EpochSeqState = struct {
    send_seq: u48 = 0,
    recv_max_seq: u48 = 0,
    recv_seen_any: bool = false,
};

/// The DTLS 1.3 `handshake` content type (RFC 8446 §5.2's inner-plaintext
/// content-type byte for handshake messages, as opposed to
/// `content_type_application_data` above).
const content_type_handshake: u8 = 22;

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

    // ── handshake-in-progress state (RFC 9147 §5 flight engine) ─────────
    /// Running transcript hash (RFC 8446 §4.4.1, TLS-style 4-byte-header
    /// framing — see `engine.zig`).
    transcript: engine.Transcript = .{},
    /// Handshake-epoch (epoch 2) record-protection keys — mirrors
    /// `write_keys`/`read_keys` above but for the {EncryptedExtensions,
    /// Finished} flight rather than application data.
    hs_write_keys: DirKeys = .{},
    hs_read_keys: DirKeys = .{},
    /// RFC 8446 §7.1 handshake traffic secrets (`"c hs traffic"`/`"s hs
    /// traffic"`). Persisted (not just used once) because a Finished is
    /// computed/verified later, once the transcript has moved on.
    hs_traffic_client: [32]u8 = undefined,
    hs_traffic_server: [32]u8 = undefined,
    /// Application traffic secrets, derived as soon as the transcript
    /// reaches "through the server's Finished" — but only INSTALLED
    /// (`installApplicationKeys`) once the handshake is mutually
    /// confirmed. The client confirms immediately (having just verified
    /// the server's Finished) and installs right away; the server stashes
    /// these here until the client's Finished verifies.
    pending_ap_client: [32]u8 = undefined,
    pending_ap_server: [32]u8 = undefined,
    /// Per-epoch record sequence-number bookkeeping for the two handshake
    /// epochs (epoch 0: ClientHello/ServerHello; epoch 2:
    /// EncryptedExtensions/Finished) — kept separate from the application
    /// epoch's `send_seq`/`recv_max_seq`/`recv_seen_any` above.
    hs0: EpochSeqState = .{},
    hs2: EpochSeqState = .{},
    /// RFC 9147 §5.7 retransmission: the last flight WE sent, cached
    /// verbatim so `poll` can resend it unchanged on timeout.
    last_flight: [1500]u8 = undefined,
    last_flight_len: usize = 0,
    retransmit_timer: flight.RetransmitTimer = flight.RetransmitTimer.init(1000, 60_000),
    /// RFC 9147 §7 flight bookkeeping (`flight.FlightTracker`) for the
    /// records of the flight currently awaiting acknowledgement.
    /// Acknowledgement here is IMPLICIT (receipt of the peer's next
    /// expected flight clears it), matching RFC 9147 §7's own framing of
    /// ACKs as needed only when a peer would otherwise have no way to
    /// infer receipt — not required on this engine's synchronous
    /// request/immediate-response happy path.
    pending_flight_buf: [4]flight.RecordNumber = undefined,
    pending_flight_count: usize = 0,

    pub const InitError = ConfigError;

    pub fn clientInit(config: Config) InitError!Connection {
        try config.validate();
        return .{ .role = .client, .config = config };
    }

    pub fn serverInit(config: Config) InitError!Connection {
        try config.validate();
        return .{ .role = .server, .config = config };
    }

    /// The result of one `handleFlight` step.
    pub const HandshakeResult = struct {
        /// Bytes to send back to the peer for this step — may be empty
        /// (e.g. once `done` and no further flight is needed).
        out: []const u8,
        /// `true` once THIS call has driven the connection to `.connected`.
        done: bool,
    };

    /// Client-only: builds and sends flight 1 (RFC 9147 §5.3) — a
    /// ClientHello offering `config.psk_identity` under `psk_ke` (no DHE,
    /// no certificates), with a real RFC 8446 §4.2.11.2 PSK binder computed
    /// over the transcript. `random` supplies the ClientHello's 32-byte
    /// `random` field (std 0.16 removed `std.crypto.random`, so — like the
    /// rest of this collection — the caller provides a `std.Random`);
    /// `now_ms` arms the retransmission timer `poll` later checks.
    /// Transitions `.start` -> `.wait_server_hello`.
    pub fn startHandshake(self: *Connection, random: std.Random, now_ms: u64, out: []u8) HandshakeError![]const u8 {
        if (self.role != .client) return error.WrongState;
        if (self.state != .start) return error.WrongState;

        var ch_body_buf: [512]u8 = undefined;
        const ch_body = try self.buildClientHello(random, &ch_body_buf);
        self.transcript.append(@intFromEnum(messages.HandshakeType.client_hello), ch_body);

        var frag_buf: [512 + handshake.header_len]u8 = undefined;
        const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.client_hello), self.message_seq, ch_body, &frag_buf);
        self.message_seq +%= 1;

        const ch_seq = self.hs0.send_seq;
        const record_bytes = try self.writeEpoch0Record(fragment, out);
        self.markFlightSent(&.{.{ .epoch = 0, .sequence_number = ch_seq }});
        try self.cacheFlight(record_bytes, now_ms);

        self.state = .wait_server_hello;
        return record_bytes;
    }

    /// Both roles: feeds an incoming (possibly multi-record-coalesced)
    /// datagram to the handshake engine and returns whatever this side
    /// needs to send in response (`HandshakeResult.out`, possibly empty).
    /// `random` is only consulted on the server's `.start` step (the
    /// ServerHello `random`); harmless to pass on the client path too.
    /// Errors are always typed (a wrong PSK, a tampered record, an
    /// out-of-order message, ...) — never a panic.
    pub fn handleFlight(self: *Connection, datagram: []const u8, random: std.Random, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        return switch (self.role) {
            .server => self.handleFlightServer(datagram, random, now_ms, out),
            .client => self.handleFlightClient(datagram, now_ms, out),
        };
    }

    /// Caller-clocked retransmission (RFC 9147 §5.7): if this side is
    /// mid-handshake, still has a cached last-sent flight, and
    /// `retransmit_timer` has expired as of `now_ms`, re-emits that flight
    /// verbatim (doubling the backoff) into `out` and returns it; `null`
    /// otherwise. Never blocks, never sleeps — `now_ms` is entirely
    /// caller-supplied, matching `flight.zig`'s fake-clock-testable style.
    pub fn poll(self: *Connection, now_ms: u64, out: []u8) HandshakeError!?[]const u8 {
        if (self.state == .connected or self.state == .start) return null;
        if (self.last_flight_len == 0) return null;
        if (!self.retransmit_timer.isExpired(now_ms)) return null;
        if (out.len < self.last_flight_len) return error.BufferTooShort;
        @memcpy(out[0..self.last_flight_len], self.last_flight[0..self.last_flight_len]);
        self.retransmit_timer.onTimeout(now_ms);
        return out[0..self.last_flight_len];
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

    // ── handshake flight engine (RFC 9147 §5, PSK-only) ──────────────────

    /// Builds the ClientHello BODY (post-handshake-header) into `body_buf`:
    /// random || empty session id || `config.cipher_suites` ||
    /// {psk_key_exchange_modes=[psk_ke], pre_shared_key} — the latter MUST
    /// be the last extension (RFC 8446 §4.2.11) since its binder covers
    /// everything before it. Patches in the REAL PSK binder in place of a
    /// same-length placeholder once the (still-empty-so-far) transcript's
    /// truncated hash is known (RFC 8446 §4.2.11.2).
    fn buildClientHello(self: *Connection, random: std.Random, body_buf: []u8) HandshakeError![]u8 {
        var random_bytes: [32]u8 = undefined;
        random.bytes(&random_bytes);

        var cs_arr: [8]u16 = undefined;
        if (self.config.cipher_suites.len > cs_arr.len) return error.BufferTooShort;
        for (self.config.cipher_suites, 0..) |cs, i| cs_arr[i] = @intFromEnum(cs);
        const cs_list = cs_arr[0..self.config.cipher_suites.len];

        var modes_buf: [4]u8 = undefined;
        const modes_ext = try messages.encodePskKeyExchangeModes(&.{.psk_ke}, &modes_buf);

        // 32-byte (SHA-256) placeholder binder, patched below.
        var placeholder_binder = [_]u8{0} ** 32;
        var psk_buf: [128]u8 = undefined;
        const identities = [_]messages.PskIdentity{.{ .identity = self.config.psk_identity, .obfuscated_ticket_age = 0 }};
        const binders = [_][]const u8{&placeholder_binder};
        const psk_ext_data = try messages.encodeOfferedPsks(.{ .identities = &identities, .binders = &binders }, &psk_buf);

        const exts = [_]messages.Extension{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.psk_key_exchange_modes), .data = modes_ext },
            .{ .ext_type = @intFromEnum(messages.ExtensionType.pre_shared_key), .data = psk_ext_data },
        };

        const ch_full = try messages.encodeClientHello(.{
            .random = random_bytes,
            .legacy_session_id = &.{},
            .cipher_suites = cs_list,
            .extensions = &exts,
        }, body_buf);

        // RFC 8446 §4.2.11.2: binder = HMAC(finished_key,
        // Transcript-Hash(Truncate(ClientHello1))). `psk_ext_data`'s layout
        // (written above) is `ids... || binders_len(2) || len(1) ||
        // binder(32)` — the trailing 33 bytes are exactly the one binder
        // entry, so Truncate() is "drop the last 33 bytes of ch_full".
        const binder_len: usize = 1 + 32;
        if (ch_full.len < binder_len) return error.Malformed;
        const truncated = ch_full[0 .. ch_full.len - binder_len];
        const binder_th = self.transcript.wouldBeHash(@intFromEnum(messages.HandshakeType.client_hello), ch_full.len, truncated);

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const eh = emptySha256Hash();
        const es = keyschedule.earlySecret(Hkdf, self.config.psk);
        const bk = keyschedule.binderKey(Hkdf, es, &eh);
        const binder = keyschedule.pskBinder(Hkdf, Hmac, bk, &binder_th);
        @memcpy(ch_full[ch_full.len - 32 ..], &binder);

        return ch_full;
    }

    /// Wraps `fragment_bytes` (a `handshake.zig` fragment: 12-byte header +
    /// body) in a legacy `record.PlaintextHeader` record (RFC 9147 §4,
    /// `content_type_handshake`, epoch 0 — the format ClientHello/
    /// ServerHello use, before any record protection exists) and appends
    /// it to `out`. Advances `hs0.send_seq`.
    fn writeEpoch0Record(self: *Connection, fragment_bytes: []const u8, out: []u8) HandshakeError![]const u8 {
        const hdr = record.PlaintextHeader{
            .content_type = content_type_handshake,
            .epoch = 0,
            .sequence_number = self.hs0.send_seq,
            .length = std.math.cast(u16, fragment_bytes.len) orelse return error.BufferTooShort,
        };
        const hdr_slice = record.encodePlaintext(hdr, out) catch return error.BufferTooShort;
        if (out.len < hdr_slice.len + fragment_bytes.len) return error.BufferTooShort;
        @memcpy(out[hdr_slice.len..][0..fragment_bytes.len], fragment_bytes);
        self.hs0.send_seq +%= 1;
        return out[0 .. hdr_slice.len + fragment_bytes.len];
    }

    /// The handshake-epoch (epoch 2) analogue of `send`: AEAD-protects
    /// `fragment_bytes` (content_type = handshake = 22) with `hs_write_keys`
    /// under a `record.UnifiedHeader`, using and advancing `hs2.send_seq`.
    /// Used for {EncryptedExtensions, Finished}.
    fn protectHandshakeMessage(self: *Connection, fragment_bytes: []const u8, out: []u8) HandshakeError![]const u8 {
        const params = suiteParams(self.suite) orelse return error.UnsupportedSuite;

        var inner_buf: [1500]u8 = undefined;
        if (fragment_bytes.len + 1 > inner_buf.len) return error.BufferTooShort;
        @memcpy(inner_buf[0..fragment_bytes.len], fragment_bytes);
        inner_buf[fragment_bytes.len] = content_type_handshake;
        const inner = inner_buf[0 .. fragment_bytes.len + 1];

        const ct_len = inner.len + params.tag_len;
        const seq_len: record.SeqNumLen = if (self.hs2.send_seq <= 0xff) .short else .long;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;

        const hdr = record.UnifiedHeader{
            .epoch_low = 2,
            .seq_len = seq_len,
            .seq_wire = @truncate(self.hs2.send_seq),
            .cid = null,
            .length = @intCast(ct_len),
        };
        const hdr_slice = record.encodeUnified(hdr, out) catch return error.BufferTooShort;
        const hdr_len = hdr_slice.len;
        if (out.len < hdr_len + ct_len) return error.BufferTooShort;

        const n = protectDispatch(self.suite, self.hs_write_keys, 2, self.hs2.send_seq, inner, out[0..hdr_len], out[hdr_len..]) catch
            return error.BufferTooShort;
        std.debug.assert(n == ct_len);

        const seq_off: usize = 1;
        try snMaskDispatch(self.suite, self.hs_write_keys, out[hdr_len..][0..16], out[seq_off..][0..seq_bytes_n]);

        self.hs2.send_seq +%= 1;
        return out[0 .. hdr_len + ct_len];
    }

    /// The handshake-epoch (epoch 2) analogue of `recv`: un-protects one
    /// record from the FRONT of `record_bytes` (trailing bytes, if any —
    /// e.g. a following coalesced record — are ignored, bounded by the
    /// record's own explicit length field) with `hs_read_keys`, verifies
    /// the recovered inner content type is `content_type_handshake`, and
    /// returns the recovered fragment bytes (12-byte handshake header +
    /// body) written into `out`.
    fn unprotectHandshakeMessage(self: *Connection, record_bytes: []const u8, out: []u8) HandshakeError![]const u8 {
        const dec = record.decodeUnified(record_bytes, 0) catch return error.Malformed;
        const seq_len = dec.hdr.seq_len;
        const seq_bytes_n: usize = if (seq_len == .short) 1 else 2;
        const hdr_len = dec.consumed;
        const seq_off: usize = 1;

        const ct = if (dec.hdr.length) |l| blk: {
            if (record_bytes.len < hdr_len + l) return error.Malformed;
            break :blk record_bytes[hdr_len..][0..l];
        } else record_bytes[hdr_len..];
        if (ct.len < 16) return error.RecordTooShort;

        var hdr_buf: [16]u8 = undefined;
        if (hdr_len > hdr_buf.len) return error.Malformed;
        @memcpy(hdr_buf[0..hdr_len], record_bytes[0..hdr_len]);
        try snMaskDispatch(self.suite, self.hs_read_keys, ct[0..16], hdr_buf[seq_off..][0..seq_bytes_n]);

        const wire_low: u16 = if (seq_len == .short)
            hdr_buf[seq_off]
        else
            std.mem.readInt(u16, hdr_buf[seq_off..][0..2], .big);
        const largest = if (self.hs2.recv_seen_any) self.hs2.recv_max_seq else 0;
        const full_seq = record.reconstructSequenceNumber(largest, seq_len, wire_low);

        const body_len = unprotectDispatch(self.suite, self.hs_read_keys, 2, full_seq, ct, hdr_buf[0..hdr_len], out) catch
            return error.DecryptionFailed;
        if (body_len == 0) return error.Malformed;

        var end = body_len;
        while (end > 0 and out[end - 1] == 0) end -= 1;
        if (end == 0) return error.Malformed;
        const ctype = out[end - 1];
        if (ctype != content_type_handshake) return error.UnexpectedMessage;

        if (!self.hs2.recv_seen_any or full_seq > self.hs2.recv_max_seq) {
            self.hs2.recv_max_seq = full_seq;
            self.hs2.recv_seen_any = true;
        }
        return out[0 .. end - 1];
    }

    /// RFC 9147 §7 flight bookkeeping: records the given (epoch, seq) pairs
    /// as "sent, awaiting acknowledgement" via `flight.FlightTracker`,
    /// reusing `pending_flight_buf` as that tracker's backing storage (a
    /// fresh `FlightTracker` is constructed each call rather than stored,
    /// since it holds a slice that would dangle across a `Connection` move
    /// — see the field's doc comment).
    fn markFlightSent(self: *Connection, records: []const flight.RecordNumber) void {
        var t = flight.FlightTracker.init(&self.pending_flight_buf);
        for (records) |rn| t.markSent(rn) catch break; // never overflows: <= 3 records/flight here
        self.pending_flight_count = t.count;
    }

    /// Marks the whole outstanding flight as acknowledged — called when the
    /// peer's next expected flight arrives (implicit ACK-by-progression).
    fn clearFlightTracker(self: *Connection) void {
        self.pending_flight_count = 0;
    }

    /// Caches `bytes` as the last flight WE sent (for `poll` to retransmit)
    /// and (re)arms `retransmit_timer` from `now_ms`.
    fn cacheFlight(self: *Connection, bytes: []const u8, now_ms: u64) HandshakeError!void {
        if (bytes.len > self.last_flight.len) return error.BufferTooShort;
        @memcpy(self.last_flight[0..bytes.len], bytes);
        self.last_flight_len = bytes.len;
        self.retransmit_timer.reset();
        self.retransmit_timer.arm(now_ms);
    }

    fn handleFlightServer(self: *Connection, datagram: []const u8, random: std.Random, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        return switch (self.state) {
            .start => self.serverProcessClientHello(datagram, random, now_ms, out),
            .wait_finished => self.serverProcessClientFinished(datagram),
            else => error.WrongState,
        };
    }

    /// Server flight 1 (RFC 9147 §5.4): consumes a ClientHello (verifying
    /// its PSK binder), selects a cipher suite, and sends flight 2 —
    /// ServerHello (epoch 0) coalesced with {EncryptedExtensions, Finished}
    /// (epoch 2, AEAD-protected under the freshly-derived handshake traffic
    /// keys). Derives (but does not yet install) the application traffic
    /// secrets. Transitions `.start` -> `.wait_finished`.
    fn serverProcessClientHello(self: *Connection, datagram: []const u8, random: std.Random, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        const ch_rec = record.decodePlaintext(datagram) catch return error.Malformed;
        if (ch_rec.content_type != content_type_handshake) return error.UnexpectedMessage;
        if (datagram.len < record.plaintext_header_len + ch_rec.length) return error.Malformed;
        const ch_fragment = datagram[record.plaintext_header_len..][0..ch_rec.length];

        var msg_buf: [512]u8 = undefined;
        var received_buf: [512]bool = undefined;
        const parsed = try reassembleFragment(ch_fragment, &msg_buf, &received_buf);
        if (parsed.msg_type != @intFromEnum(messages.HandshakeType.client_hello)) return error.UnexpectedMessage;
        const ch_body = parsed.body;

        var ext_buf: [8]messages.Extension = undefined;
        const dec = messages.decodeClientHello(ch_body, &ext_buf) catch return error.Malformed;

        var psk_ext: ?messages.Extension = null;
        for (dec.extensions) |e| {
            if (e.ext_type == @intFromEnum(messages.ExtensionType.pre_shared_key)) psk_ext = e;
        }
        const psk_data = (psk_ext orelse return error.NoMatchingPskIdentity).data;

        var ids_buf: [4]messages.PskIdentity = undefined;
        var binders_buf: [4][]const u8 = undefined;
        const offered = messages.decodeOfferedPsks(psk_data, &ids_buf, &binders_buf) catch return error.Malformed;
        if (offered.identities.len == 0 or offered.binders.len == 0) return error.NoMatchingPskIdentity;
        if (!std.mem.eql(u8, offered.identities[0].identity, self.config.psk_identity)) return error.NoMatchingPskIdentity;
        const binder0 = offered.binders[0];
        if (binder0.len != 32) return error.Malformed;

        // RFC 8446 §4.2.11.2 truncation point: right after the binders
        // list's 2-byte length prefix, i.e. right before this (first, only)
        // binder entry's own 1-byte length prefix. `binder0` aliases
        // `ch_body` (no-copy decoding all the way down — see messages.zig),
        // so its address gives the exact byte offset without assuming
        // anything about extension count/order.
        const truncate_at = (@intFromPtr(binder0.ptr) - 1) - @intFromPtr(ch_body.ptr);
        if (truncate_at > ch_body.len) return error.Malformed;
        const truncated = ch_body[0..truncate_at];

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const eh = emptySha256Hash();
        const es = keyschedule.earlySecret(Hkdf, self.config.psk);
        const bk = keyschedule.binderKey(Hkdf, es, &eh);
        const binder_th = self.transcript.wouldBeHash(@intFromEnum(messages.HandshakeType.client_hello), ch_body.len, truncated);
        const expected_binder = keyschedule.pskBinder(Hkdf, Hmac, bk, &binder_th);
        if (!std.crypto.timing_safe.eql([32]u8, expected_binder, binder0[0..32].*)) return error.BinderVerifyFailed;

        var selected: ?CipherSuite = null;
        for (self.config.cipher_suites) |want| {
            var it = messages.CipherSuiteIter{ .raw = dec.cipher_suites_raw };
            while (it.next()) |offered_cs| {
                if (offered_cs == @intFromEnum(want) and suiteParams(want) != null) {
                    selected = want;
                    break;
                }
            }
            if (selected != null) break;
        }
        const suite = selected orelse return error.NoCipherSuiteOverlap;

        // Binder verified: commit the (now-authenticated) ClientHello.
        self.transcript.append(@intFromEnum(messages.HandshakeType.client_hello), ch_body);
        self.suite = suite;

        var random_bytes: [32]u8 = undefined;
        random.bytes(&random_bytes);
        var sel_id_buf: [2]u8 = undefined;
        messages.encodeSelectedIdentity(0, &sel_id_buf);
        const sh_exts = [_]messages.Extension{
            .{ .ext_type = @intFromEnum(messages.ExtensionType.pre_shared_key), .data = &sel_id_buf },
        };
        var sh_body_buf: [128]u8 = undefined;
        const sh_body = messages.encodeServerHello(.{
            .random = random_bytes,
            .legacy_session_id_echo = dec.legacy_session_id,
            .cipher_suite = @intFromEnum(suite),
            .extensions = &sh_exts,
        }, &sh_body_buf) catch return error.BufferTooShort;
        self.transcript.append(@intFromEnum(messages.HandshakeType.server_hello), sh_body);

        var sh_frag_buf: [128 + handshake.header_len]u8 = undefined;
        const sh_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), self.message_seq, sh_body, &sh_frag_buf);
        self.message_seq +%= 1;
        const sh_seq = self.hs0.send_seq;
        var cursor: usize = 0;
        {
            const sh_record = try self.writeEpoch0Record(sh_fragment, out[cursor..]);
            cursor += sh_record.len;
        }

        // RFC 8446 §7.1: handshake traffic secrets, over the transcript
        // through ServerHello.
        const th_through_sh = self.transcript.currentHash();
        const hs_secret = keyschedule.deriveHandshakeSecret(Hkdf, es, &eh, null);
        const hst = keyschedule.deriveHandshakeTrafficSecrets(Hkdf, hs_secret, &th_through_sh);
        self.hs_traffic_client = hst.client;
        self.hs_traffic_server = hst.server;
        const params = suiteParams(suite) orelse return error.UnsupportedSuite;
        self.hs_write_keys = deriveDir(Hkdf, params, hst.server);
        self.hs_read_keys = deriveDir(Hkdf, params, hst.client);

        var ee_body_buf: [8]u8 = undefined;
        const ee_body = messages.encodeEncryptedExtensions(&.{}, &ee_body_buf) catch return error.BufferTooShort;
        self.transcript.append(@intFromEnum(messages.HandshakeType.encrypted_extensions), ee_body);
        var ee_frag_buf: [8 + handshake.header_len]u8 = undefined;
        const ee_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.encrypted_extensions), self.message_seq, ee_body, &ee_frag_buf);
        self.message_seq +%= 1;
        const ee_seq = self.hs2.send_seq;
        {
            const ee_record = try self.protectHandshakeMessage(ee_fragment, out[cursor..]);
            cursor += ee_record.len;
        }

        const finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, hst.server);
        const th_before_finished = self.transcript.currentHash();
        const verify_data = keyschedule.computeFinishedVerifyData(Hmac, finished_key, &th_before_finished);
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), &verify_data);
        var fin_frag_buf: [32 + handshake.header_len]u8 = undefined;
        const fin_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.finished), self.message_seq, &verify_data, &fin_frag_buf);
        self.message_seq +%= 1;
        const fin_seq = self.hs2.send_seq;
        {
            const fin_record = try self.protectHandshakeMessage(fin_fragment, out[cursor..]);
            cursor += fin_record.len;
        }

        const ms = keyschedule.deriveMasterSecret(Hkdf, hs_secret, &eh);
        const th_through_server_finished = self.transcript.currentHash();
        const ap = keyschedule.deriveApplicationTrafficSecrets(Hkdf, ms, &th_through_server_finished);
        self.pending_ap_client = ap.client;
        self.pending_ap_server = ap.server;

        self.markFlightSent(&.{
            .{ .epoch = 0, .sequence_number = sh_seq },
            .{ .epoch = 2, .sequence_number = ee_seq },
            .{ .epoch = 2, .sequence_number = fin_seq },
        });
        try self.cacheFlight(out[0..cursor], now_ms);
        self.state = .wait_finished;
        return .{ .out = out[0..cursor], .done = false };
    }

    /// Server flight 3 (implicit): consumes the client's Finished, verifies
    /// its `verify_data`, and installs the application traffic secrets
    /// derived earlier. Transitions `.wait_finished` -> `.connected`.
    fn serverProcessClientFinished(self: *Connection, datagram: []const u8) HandshakeError!HandshakeResult {
        var plain_buf: [128]u8 = undefined;
        const fragment = try self.unprotectHandshakeMessage(datagram, &plain_buf);

        var msg_buf: [64]u8 = undefined;
        var received_buf: [64]bool = undefined;
        const parsed = try reassembleFragment(fragment, &msg_buf, &received_buf);
        if (parsed.msg_type != @intFromEnum(messages.HandshakeType.finished)) return error.UnexpectedMessage;
        const fin = messages.decodeFinished(parsed.body);
        if (fin.verify_data.len != 32) return error.Malformed;

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, self.hs_traffic_client);
        const th = self.transcript.currentHash(); // through the server's own Finished
        const expected = keyschedule.computeFinishedVerifyData(Hmac, finished_key, &th);
        if (!std.crypto.timing_safe.eql([32]u8, expected, fin.verify_data[0..32].*)) return error.FinishedVerifyFailed;
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), fin.verify_data);

        try self.installApplicationKeys(self.suite, self.pending_ap_client, self.pending_ap_server);
        self.clearFlightTracker();
        self.retransmit_timer.reset();
        self.last_flight_len = 0;
        return .{ .out = &.{}, .done = true };
    }

    /// Client side of flights 2+3 (RFC 9147 §5.4/§5.5): consumes ServerHello
    /// + EncryptedExtensions + server Finished (coalesced in `datagram`),
    /// derives the handshake and (from the transcript through the server's
    /// Finished) application traffic secrets, verifies the server's
    /// Finished, sends the client's own Finished, and installs application
    /// keys immediately (the client needs no further confirmation once it
    /// has verified the server). Transitions `.wait_server_hello` ->
    /// `.connected`.
    fn handleFlightClient(self: *Connection, datagram: []const u8, now_ms: u64, out: []u8) HandshakeError!HandshakeResult {
        if (self.state != .wait_server_hello) return error.WrongState;

        const sh_rec = record.decodePlaintext(datagram) catch return error.Malformed;
        if (sh_rec.content_type != content_type_handshake) return error.UnexpectedMessage;
        if (datagram.len < record.plaintext_header_len + sh_rec.length) return error.Malformed;
        var pos: usize = record.plaintext_header_len + sh_rec.length;
        const sh_fragment = datagram[record.plaintext_header_len..][0..sh_rec.length];

        var sh_msg_buf: [256]u8 = undefined;
        var sh_received_buf: [256]bool = undefined;
        const sh_parsed = try reassembleFragment(sh_fragment, &sh_msg_buf, &sh_received_buf);
        if (sh_parsed.msg_type != @intFromEnum(messages.HandshakeType.server_hello)) return error.UnexpectedMessage;

        var ext_buf: [8]messages.Extension = undefined;
        const sh_dec = messages.decodeServerHello(sh_parsed.body, &ext_buf) catch return error.Malformed;
        if (messages.isHelloRetryRequest(sh_dec.random)) return error.HelloRetryRequestUnsupported;

        const suite = cipherSuiteFromU16(sh_dec.cipher_suite) orelse return error.UnsupportedSuite;
        if (suiteParams(suite) == null) return error.UnsupportedSuite;
        var offered_ok = false;
        for (self.config.cipher_suites) |cs| {
            if (cs == suite) offered_ok = true;
        }
        if (!offered_ok) return error.NoCipherSuiteOverlap;
        self.suite = suite;

        self.transcript.append(@intFromEnum(messages.HandshakeType.server_hello), sh_parsed.body);
        self.clearFlightTracker(); // the ClientHello flight is now implicitly ACKed
        self.retransmit_timer.reset();

        const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
        const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
        const eh = emptySha256Hash();
        const es = keyschedule.earlySecret(Hkdf, self.config.psk);
        const hs_secret = keyschedule.deriveHandshakeSecret(Hkdf, es, &eh, null);
        const th_through_sh = self.transcript.currentHash();
        const hst = keyschedule.deriveHandshakeTrafficSecrets(Hkdf, hs_secret, &th_through_sh);
        self.hs_traffic_client = hst.client;
        self.hs_traffic_server = hst.server;
        const params = suiteParams(suite).?;
        self.hs_write_keys = deriveDir(Hkdf, params, hst.client);
        self.hs_read_keys = deriveDir(Hkdf, params, hst.server);

        if (pos >= datagram.len) return error.Malformed;
        var ee_plain_buf: [128]u8 = undefined;
        const ee_fragment = try self.unprotectHandshakeMessage(datagram[pos..], &ee_plain_buf);
        pos += try recordWireLen(datagram[pos..]);
        var ee_msg_buf: [64]u8 = undefined;
        var ee_received_buf: [64]bool = undefined;
        const ee_parsed = try reassembleFragment(ee_fragment, &ee_msg_buf, &ee_received_buf);
        if (ee_parsed.msg_type != @intFromEnum(messages.HandshakeType.encrypted_extensions)) return error.UnexpectedMessage;
        self.transcript.append(@intFromEnum(messages.HandshakeType.encrypted_extensions), ee_parsed.body);

        if (pos >= datagram.len) return error.Malformed;
        var fin_plain_buf: [128]u8 = undefined;
        const fin_fragment = try self.unprotectHandshakeMessage(datagram[pos..], &fin_plain_buf);
        var fin_msg_buf: [64]u8 = undefined;
        var fin_received_buf: [64]bool = undefined;
        const fin_parsed = try reassembleFragment(fin_fragment, &fin_msg_buf, &fin_received_buf);
        if (fin_parsed.msg_type != @intFromEnum(messages.HandshakeType.finished)) return error.UnexpectedMessage;
        const server_fin = messages.decodeFinished(fin_parsed.body);
        if (server_fin.verify_data.len != 32) return error.Malformed;

        const server_finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, hst.server);
        const th_before_server_finished = self.transcript.currentHash();
        const expected_server_vd = keyschedule.computeFinishedVerifyData(Hmac, server_finished_key, &th_before_server_finished);
        if (!std.crypto.timing_safe.eql([32]u8, expected_server_vd, server_fin.verify_data[0..32].*)) return error.FinishedVerifyFailed;
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), server_fin.verify_data);

        const ms = keyschedule.deriveMasterSecret(Hkdf, hs_secret, &eh);
        const th_through_server_finished = self.transcript.currentHash();
        const ap = keyschedule.deriveApplicationTrafficSecrets(Hkdf, ms, &th_through_server_finished);

        const client_finished_key = keyschedule.deriveFinishedKey(Hkdf, 32, hst.client);
        const client_vd = keyschedule.computeFinishedVerifyData(Hmac, client_finished_key, &th_through_server_finished);
        self.transcript.append(@intFromEnum(messages.HandshakeType.finished), &client_vd);

        var fin_frag_buf: [32 + handshake.header_len]u8 = undefined;
        const client_fin_fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.finished), self.message_seq, &client_vd, &fin_frag_buf);
        self.message_seq +%= 1;
        const client_fin_seq = self.hs2.send_seq;
        const client_fin_record = try self.protectHandshakeMessage(client_fin_fragment, out);
        self.markFlightSent(&.{.{ .epoch = 2, .sequence_number = client_fin_seq }});

        try self.installApplicationKeys(suite, ap.client, ap.server);
        _ = now_ms; // the client needs no further retransmission once connected

        return .{ .out = client_fin_record, .done = true };
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

// ── handshake flight engine: free (Connection-agnostic) helpers ─────────

/// Safe wire-integer -> `CipherSuite` conversion. `CipherSuite` is an
/// EXHAUSTIVE enum (no `_` catch-all arm), so `@enumFromInt` on a
/// peer-controlled, possibly-unknown u16 would be a safety-checked panic —
/// exactly the kind of "typed error, never a panic" this module's tests
/// enforce everywhere else. A plain `switch` on the concrete values is the
/// non-panicking equivalent.
fn cipherSuiteFromU16(v: u16) ?CipherSuite {
    return switch (v) {
        @intFromEnum(CipherSuite.aes_128_gcm_sha256) => .aes_128_gcm_sha256,
        @intFromEnum(CipherSuite.chacha20_poly1305_sha256) => .chacha20_poly1305_sha256,
        @intFromEnum(CipherSuite.aes_128_ccm_sha256) => .aes_128_ccm_sha256,
        @intFromEnum(CipherSuite.aes_128_ccm_8_sha256) => .aes_128_ccm_8_sha256,
        else => null,
    };
}

/// `Sha256("")` — RFC 8446 §7.1's "empty transcript hash", needed at
/// several key-schedule points (`binderKey`, `deriveHandshakeSecret`,
/// `deriveMasterSecret`) that logically derive from "no messages yet".
fn emptySha256Hash() [32]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &h, .{});
    return h;
}

/// Frames `body` as a single-fragment `handshake.zig` message (12-byte
/// header + the whole body in one fragment — every message this engine
/// sends comfortably fits `frag_out`, so `Fragmenter.next` always succeeds
/// on its first call). Does not touch the record layer.
fn frameHandshakeMessage(msg_type: u8, message_seq: u16, body: []const u8, frag_out: []u8) HandshakeError![]const u8 {
    var fragmenter = handshake.Fragmenter.init(msg_type, message_seq, body);
    const max_len = if (frag_out.len > handshake.header_len) frag_out.len - handshake.header_len else 0;
    return fragmenter.next(max_len, frag_out) orelse return error.BufferTooShort;
}

/// Reassembles ONE `handshake.zig` fragment (this engine never splits a
/// message across more than one fragment, so `Reassembler.feed`'s first
/// call always either completes the message or — if `fragment_bytes` lied
/// about covering the whole declared length — the message is incomplete,
/// which this engine treats as `error.FragmentedMessageUnsupported` rather
/// than waiting for a fragment that will never come).
fn reassembleFragment(
    fragment_bytes: []const u8,
    msg_buf: []u8,
    received_buf: []bool,
) HandshakeError!struct { msg_type: u8, body: []const u8, message_seq: u16 } {
    const hdr = handshake.decodeHeader(fragment_bytes) catch return error.Malformed;
    if (fragment_bytes.len < handshake.header_len + hdr.fragment_length) return error.Malformed;
    const frag_body = fragment_bytes[handshake.header_len..][0..hdr.fragment_length];
    if (hdr.length > msg_buf.len) return error.BufferTooShort;

    var reasm = handshake.Reassembler.init(msg_buf[0..hdr.length], received_buf[0..hdr.length]);
    const complete = (reasm.feed(hdr, frag_body) catch return error.Malformed) orelse
        return error.FragmentedMessageUnsupported;
    return .{ .msg_type = hdr.msg_type, .body = complete, .message_seq = hdr.message_seq };
}

/// The total on-wire length (header + explicit-length content) of ONE
/// `record.UnifiedHeader` record starting at the front of `buf` — used to
/// step a cursor over a datagram carrying several coalesced records. This
/// engine always encodes an explicit `length` (never the
/// "rest of the datagram" form), so a missing length is malformed input.
fn recordWireLen(buf: []const u8) HandshakeError!usize {
    const dec = record.decodeUnified(buf, 0) catch return error.Malformed;
    const len = dec.hdr.length orelse return error.Malformed;
    if (buf.len < dec.consumed + len) return error.Malformed;
    return dec.consumed + len;
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

fn testRandom(csprng: *std.Random.DefaultCsprng) std.Random {
    return csprng.random();
}

test "startHandshake: server role is rejected (typed error, not a panic)" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var server = try Connection.serverInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x01} ** 32);
    var out: [1500]u8 = undefined;
    try testing.expectError(error.WrongState, server.startHandshake(testRandom(&csprng), 0, &out));
}

test "startHandshake: wrong state (already mid-handshake) is rejected" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x02} ** 32);
    var out: [1500]u8 = undefined;
    _ = try client.startHandshake(testRandom(&csprng), 0, &out);
    try testing.expectError(error.WrongState, client.startHandshake(testRandom(&csprng), 0, &out));
}

test "startHandshake: real ClientHello bytes, not a stub — real DTLS 1.3 flight sent" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "s3cr3t", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x03} ** 32);
    var out: [1500]u8 = undefined;
    const ch = try client.startHandshake(testRandom(&csprng), 0, &out);
    try testing.expectEqual(State.wait_server_hello, client.state);
    // Legacy DTLSPlaintext header: content_type=22 (handshake), epoch=0.
    try testing.expectEqual(@as(u8, 22), ch[0]);
    try testing.expect(ch.len > record.plaintext_header_len + handshake.header_len);
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

// ── handshake flight engine: the mandatory oracle ────────────────────────
//
// No external DTLS peer is required or used here: two `Connection`s (one
// client, one server) drive each other's flights entirely in memory —
// client.startHandshake -> server.handleFlight -> client.handleFlight ->
// server.handleFlight — until BOTH report `.done`/`.connected`. This is
// the real proof the flight engine is correct: PSK binder verified, both
// Finished `verify_data`s verified, identical keys derived on both sides
// purely from the shared PSK + the (independently, identically computed)
// transcript, and the existing validated `send`/`recv` application-data
// path works over the freshly-installed keys afterward.

/// Drives `client`/`server` (both already `clientInit`/`serverInit`, both
/// still `.start`) through a complete PSK handshake, alternating `buf1`/
/// `buf2` as scratch so no step's input aliases its own output buffer.
fn driveHandshake(client: *Connection, server: *Connection, rnd: std.Random, buf1: []u8, buf2: []u8) !void {
    const ch = try client.startHandshake(rnd, 0, buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, buf2);
    try testing.expect(!flight2.done);
    try testing.expectEqual(State.wait_finished, server.state);

    const client_fin = try client.handleFlight(flight2.out, rnd, 0, buf1);
    try testing.expect(client_fin.done);
    try testing.expectEqual(State.connected, client.state);

    const server_result = try server.handleFlight(client_fin.out, rnd, 0, buf2);
    try testing.expect(server_result.done);
    try testing.expectEqual(State.connected, server.state);
}

fn loopbackHandshake(suite: CipherSuite) !void {
    const psk_identity = "device-042";
    const psk = "a-shared-pre-shared-key";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{suite} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{suite} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x10} ** 32);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    try driveHandshake(&client, &server, testRandom(&csprng), &buf1, &buf2);

    try testing.expectEqual(suite, client.suite);
    try testing.expectEqual(suite, server.suite);

    // Both sides must have derived IDENTICAL directional application keys
    // — the real proof that the independently-computed transcripts (and
    // therefore the whole key schedule) agree byte-for-byte.
    try testing.expectEqualSlices(u8, client.write_keys.key[0..client.write_keys.key_len], server.read_keys.key[0..server.read_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.write_keys.iv, &server.read_keys.iv);
    try testing.expectEqualSlices(u8, client.read_keys.key[0..client.read_keys.key_len], server.write_keys.key[0..server.write_keys.key_len]);
    try testing.expectEqualSlices(u8, &client.read_keys.iv, &server.write_keys.iv);

    // Application-data round trip, BOTH directions, through the existing,
    // already-validated `send`/`recv` record path — over the keys THIS
    // handshake installed (not hand-derived, as the older
    // `roundtripSuite` self-consistency tests above do).
    var wire: [256]u8 = undefined;
    var plain: [256]u8 = undefined;
    const msg1 = "hello from client, post-handshake";
    const rec1 = try client.send(msg1, &wire);
    const got1 = try server.recv(rec1, &plain);
    try testing.expectEqualSlices(u8, msg1, got1);

    var wire2: [256]u8 = undefined;
    const msg2 = "hello from server, post-handshake";
    const rec2 = try server.send(msg2, &wire2);
    const got2 = try client.recv(rec2, &plain);
    try testing.expectEqualSlices(u8, msg2, got2);

    // Tamper -> DecryptionFailed, never a panic.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..rec1.len], rec1);
    tampered[rec1.len - 1] ^= 0x80;
    try testing.expectError(error.DecryptionFailed, server.recv(tampered[0..rec1.len], &plain));
}

test "handshake: full client<->server loopback interop — AES-128-GCM" {
    try loopbackHandshake(.aes_128_gcm_sha256);
}

test "handshake: full client<->server loopback interop — ChaCha20-Poly1305" {
    try loopbackHandshake(.chacha20_poly1305_sha256);
}

test "handshake: wrong PSK -> binder verify fails (typed error, not a panic)" {
    const psk_identity = "device-1";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = "correct-psk", .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = "WRONG-psk", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x20} ** 32);
    const rnd = testRandom(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    try testing.expectError(error.BinderVerifyFailed, server.handleFlight(ch, rnd, 0, &buf2));
}

test "handshake: mismatched PSK identity -> typed error, not a panic" {
    const cfg_client = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = "device-OTHER", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x23} ** 32);
    const rnd = testRandom(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    try testing.expectError(error.NoMatchingPskIdentity, server.handleFlight(ch, rnd, 0, &buf2));
}

test "handshake: corrupted ServerHello -> typed error, not a panic" {
    const psk_identity = "device-1";
    const psk = "shared-secret";
    const cfg = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var server = try Connection.serverInit(.{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} });
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x21} ** 32);
    const rnd = testRandom(&csprng);
    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch = try client.startHandshake(rnd, 0, &buf1);
    const flight2 = try server.handleFlight(ch, rnd, 0, &buf2);

    var corrupted: [1500]u8 = undefined;
    @memcpy(corrupted[0..flight2.out.len], flight2.out);
    // Flip a byte inside the legacy PlaintextHeader's `length` field
    // (bytes 11..13 — see `record.PlaintextHeader`/`encodePlaintext`).
    corrupted[11] ^= 0xFF;

    try testing.expectError(error.Malformed, client.handleFlight(corrupted[0..flight2.out.len], rnd, 0, &buf1));
}

test "handshake: HelloRetryRequest random is detected and rejected (typed error)" {
    const cfg = Config{ .role = .client, .psk_identity = "device-1", .psk = "shared", .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x40} ** 32);
    const rnd = testRandom(&csprng);
    var buf1: [1500]u8 = undefined;
    _ = try client.startHandshake(rnd, 0, &buf1);

    // Hand-build a structurally valid ServerHello whose `random` is the
    // RFC 8446 §4.1.3 HelloRetryRequest magic value — this engine
    // implements the psk_ke happy path only, not cookie/retry.
    var sh_body_buf: [128]u8 = undefined;
    const sh_body = try messages.encodeServerHello(.{
        .random = messages.hello_retry_request_random,
        .legacy_session_id_echo = &.{},
        .cipher_suite = @intFromEnum(CipherSuite.aes_128_gcm_sha256),
        .extensions = &.{},
    }, &sh_body_buf);

    var frag_buf: [128 + handshake.header_len]u8 = undefined;
    const fragment = try frameHandshakeMessage(@intFromEnum(messages.HandshakeType.server_hello), 0, sh_body, &frag_buf);

    var record_buf: [200]u8 = undefined;
    const hdr = record.PlaintextHeader{ .content_type = content_type_handshake, .epoch = 0, .sequence_number = 0, .length = @intCast(fragment.len) };
    const hdr_slice = try record.encodePlaintext(hdr, &record_buf);
    @memcpy(record_buf[hdr_slice.len..][0..fragment.len], fragment);
    const datagram = record_buf[0 .. hdr_slice.len + fragment.len];

    var buf2: [1500]u8 = undefined;
    try testing.expectError(error.HelloRetryRequestUnsupported, client.handleFlight(datagram, rnd, 0, &buf2));
}

test "handshake: server handleFlight rejects the wrong state" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var server = try Connection.serverInit(cfg);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x50} ** 32);
    var out: [64]u8 = undefined;
    // `server` is `.start`ed but this call pretends it's already past
    // `.wait_finished` by driving it there via a bogus (empty) datagram
    // first would itself error — simpler: directly assert a state this
    // engine never lets `.start` accept, by using `.connected` state.
    server.state = .connected;
    try testing.expectError(error.WrongState, server.handleFlight("x", testRandom(&csprng), 0, &out));
}

test "poll: nothing to retransmit before a handshake starts or after it connects" {
    const cfg = Config{ .role = .client, .psk_identity = "id", .psk = "secret" };
    var client = try Connection.clientInit(cfg);
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(999_999, &out));

    client.state = .connected;
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(999_999, &out));
}

test "handshake: dropped ClientHello retransmits via poll (fake clock), then completes" {
    const psk_identity = "device-1";
    const psk = "shared-secret";
    const cfg_client = Config{ .role = .client, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    const cfg_server = Config{ .role = .server, .psk_identity = psk_identity, .psk = psk, .cipher_suites = &.{.aes_128_gcm_sha256} };
    var client = try Connection.clientInit(cfg_client);
    var server = try Connection.serverInit(cfg_server);
    var csprng = std.Random.DefaultCsprng.init([_]u8{0x30} ** 32);
    const rnd = testRandom(&csprng);

    var buf1: [1500]u8 = undefined;
    var buf2: [1500]u8 = undefined;

    const ch1 = try client.startHandshake(rnd, 0, &buf1); // "sent" at t=0, then DROPPED
    var ch1_copy: [1500]u8 = undefined;
    @memcpy(ch1_copy[0..ch1.len], ch1);

    // Before the initial 1000ms timeout: nothing to retransmit yet.
    try testing.expectEqual(@as(?[]const u8, null), try client.poll(500, &buf2));
    // At/after the deadline: the SAME ClientHello bytes come back.
    const ch2 = (try client.poll(1000, &buf2)).?;
    try testing.expectEqualSlices(u8, ch1_copy[0..ch1.len], ch2);

    // Deliver the RETRANSMITTED copy — the handshake completes normally.
    const flight2 = try server.handleFlight(ch2, rnd, 1000, &buf1);
    const client_fin = try client.handleFlight(flight2.out, rnd, 1000, &buf2);
    try testing.expect(client_fin.done);
    const server_done = try server.handleFlight(client_fin.out, rnd, 1000, &buf1);
    try testing.expect(server_done.done);

    try testing.expectEqual(State.connected, client.state);
    try testing.expectEqual(State.connected, server.state);
}
