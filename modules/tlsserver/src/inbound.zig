// SPDX-License-Identifier: MIT

//! tlsserver.inbound — the receive side of the record layer over a byte
//! stream: records cut from the input, plaintext or protected, turned into
//! whole handshake messages, alerts and application data, with every
//! framing rule of RFC 8446 §5 that does not need the handshake state.
//!
//! - **Records** (§5.1): the outer type must be one of the four, the
//!   version `0x03XX`, a non-`application_data` record non-empty, a
//!   plaintext record at most 2^14 octets and a protected one at most
//!   2^14 + 256 — checked as soon as the header is in, before the body is
//!   waited for.
//! - **Handshake messages** are joined across records (`Joiner`) and split
//!   when one record holds several. Handshake data must not be interleaved
//!   with other record types, and a key change must fall on a message
//!   boundary (`installRx`).
//! - **Compatibility mode** (§5, Appendix D.4): a plaintext
//!   `change_cipher_spec` of the single octet 0x01, after the first
//!   ClientHello and before the client's Finished, is dropped — at most
//!   `max_compat_ccs` times (rustls: one per ClientHello).
//! - **Alerts** go through `alert.classify`; a plaintext alert is accepted
//!   after the keys changed only until the first protected record has been
//!   opened (rustls: a client that cannot read the ServerHello alerts in the
//!   clear).
//! - **Application data** is refused until the engine sets `app_data_ok`
//!   (after the client's Finished), or `early_data_ok` (0-RTT taken, until
//!   the client's EndOfEarlyData).
//!
//! Choices where RFC 8446 names no alert follow rustls 0.23: an unknown
//! outer type, a non-`0x03XX` version and an empty plaintext handshake or
//! alert record are `decode_error`, a key change with handshake data pending
//! is `unexpected_message`.
//!
//! Sans-I/O: `next` reads from the caller's receive buffer and says how
//! many octets it has finished with; protected records are opened in place.

const std = @import("std");
const record = @import("record.zig");
const zeroize = @import("zeroize.zig").zeroize;
const alert = @import("alert.zig");

const header_len = record.header_len;

/// One handshake message: type, body, and the four-octet header in front of
/// it (`raw` = header ‖ body, the octets the transcript hashes).
pub const HandshakeMessage = struct {
    msg_type: u8,
    body: []const u8,
    raw: []const u8,
};

/// The default cap on one handshake message's body (rustls
/// `MAX_HANDSHAKE_SIZE`): a ClientHello or a client certificate chain
/// larger than 64 KiB is refused.
pub const default_max_message = 0xffff;

pub const JoinError = error{
    /// A handshake message longer than the joiner's cap (rustls
    /// `HandshakePayloadTooLarge`: `decode_error`).
    HandshakeTooLarge,
};

/// Joins handshake fragments into whole messages in a caller-supplied
/// buffer. Messages are delivered in order by `next`; the slices alias the
/// buffer and stay valid until the following `push`.
pub const Joiner = struct {
    buf: []u8,
    /// The first octet not yet delivered.
    start: usize = 0,
    /// One past the last octet held.
    end: usize = 0,
    /// One past the last octet ever written since `init` / `reset`: what
    /// `reset` zeroes (compaction leaves old octets behind `end`).
    dirty: usize = 0,

    /// The buffer length `init` needs for messages up to `max_message`
    /// octets: one whole message plus one more record's worth of fragment,
    /// so a push never has to be refused for room.
    pub fn bufferLen(max_message: usize) usize {
        return 4 + max_message + record.max_plaintext_len;
    }

    pub fn init(buf: []u8) Joiner {
        std.debug.assert(buf.len >= bufferLen(0));
        return .{ .buf = buf };
    }

    pub fn maxMessage(self: *const Joiner) usize {
        return self.buf.len - bufferLen(0);
    }

    /// No octet held: neither a partial message nor an undelivered one.
    pub fn isEmpty(self: *const Joiner) bool {
        return self.start == self.end;
    }

    /// Append one record's handshake content (≤ 2^14 octets). Call only
    /// when `next` has returned null: every complete message delivered.
    pub fn push(self: *Joiner, fragment: []const u8) JoinError!void {
        std.debug.assert(fragment.len <= record.max_plaintext_len);
        const held = self.end - self.start;
        if (self.start != 0) {
            std.mem.copyForwards(u8, self.buf[0..held], self.buf[self.start..self.end]);
            self.start = 0;
            self.end = held;
        }
        // What is held is less than one whole message, and that message is
        // within the cap (`next` checked its header), so a fragment fits.
        std.debug.assert(held < 4 + self.maxMessage());
        @memcpy(self.buf[held..][0..fragment.len], fragment);
        self.end = held + fragment.len;
        self.dirty = @max(self.dirty, self.end);
    }

    /// The next whole message, or null if the held octets end in a partial
    /// one (or there are none).
    pub fn next(self: *Joiner) JoinError!?HandshakeMessage {
        const held = self.buf[self.start..self.end];
        if (held.len < 4) return null;
        const len = std.mem.readInt(u24, held[1..4], .big);
        if (len > self.maxMessage()) return error.HandshakeTooLarge;
        if (held.len < 4 + @as(usize, len)) return null;
        const raw = held[0 .. 4 + @as(usize, len)];
        self.start += raw.len;
        return .{ .msg_type = raw[0], .body = raw[4..], .raw = raw };
    }

    /// Zero every octet written and forget them (client certificates and
    /// Finished messages need not outlive the connection).
    pub fn reset(self: *Joiner) void {
        zeroize(self.buf[0..self.dirty]);
        self.start = 0;
        self.end = 0;
        self.dirty = 0;
    }
};

/// How many compatibility-mode `change_cipher_spec` records are dropped
/// (rustls `allowed_middlebox_ccs`: one after each ClientHello, and there
/// are at most two ClientHellos).
pub const max_compat_ccs = 2;

pub const Error = error{
    /// RFC 8446 `unexpected_message`.
    UnexpectedMessage,
    /// `decode_error`: a malformed record header or alert.
    DecodeError,
    /// `record_overflow`.
    RecordOverflow,
    /// `bad_record_mac`.
    BadRecordMac,
    /// `illegal_parameter` (an alert of unknown level).
    IllegalParameter,
    /// `decode_error`: a handshake message over the joiner's cap.
    HandshakeTooLarge,
    /// The receive sequence number reached 2^64 − 1 (`internal_error`; the
    /// peer must KeyUpdate long before).
    SequenceExhausted,
    /// The peer sent a fatal alert (`Inbound.peer_alert`), or closed before
    /// the handshake finished. Nothing is sent back.
    PeerAborted,
};

/// The alert to send for an `Error`, or null when none is due.
pub fn alertFor(err: Error) ?alert.Description {
    return switch (err) {
        error.UnexpectedMessage => .unexpected_message,
        error.DecodeError, error.HandshakeTooLarge => .decode_error,
        error.RecordOverflow => .record_overflow,
        error.BadRecordMac => .bad_record_mac,
        error.IllegalParameter => .illegal_parameter,
        error.SequenceExhausted => .internal_error,
        error.PeerAborted => null,
    };
}

pub const Event = union(enum) {
    /// No whole record is buffered: read more and call again.
    need_more,
    /// A whole handshake message (aliases the joiner's buffer; valid until
    /// the next `next`).
    handshake: HandshakeMessage,
    /// Decrypted application data (aliases the caller's buffer, inside the
    /// octets counted by `consumed`: use it before discarding them). May be
    /// empty.
    app_data: []u8,
    /// close_notify after the handshake. Nothing more is read.
    peer_closed,
};

pub const Result = struct {
    event: Event,
    /// Octets at the front of the buffer this call is done with; the caller
    /// discards them (after using an `app_data` slice).
    consumed: usize,
};

pub const Inbound = struct {
    joiner: Joiner,
    rx: record.Protection = undefined,
    /// A receive key is installed: records must be protected.
    protected: bool = false,
    /// A protected record has been opened under some key.
    decrypted_any: bool = false,
    /// A handshake message has been delivered (the first ClientHello).
    handshake_seen: bool = false,
    /// The engine verified the client's Finished: application data and
    /// close_notify are accepted, compatibility CCS no longer is.
    app_data_ok: bool = false,
    /// The engine took the client's early data: application data under the
    /// receive key installed (the client's early secret) is delivered.
    early_data_ok: bool = false,
    closed: bool = false,
    /// One compatibility CCS per ClientHello the engine accepts: the engine
    /// adds one when it sends a HelloRetryRequest (at most
    /// `max_compat_ccs`).
    ccs_left: u8 = 1,
    warnings: u8 = 0,
    /// The description of the alert behind `error.PeerAborted`.
    peer_alert: ?alert.Description = null,
    /// Rejected 0-RTT: protected records that fail to open are dropped
    /// while their ciphertext fits this budget, until one opens (RFC 8446
    /// §4.2.10, trial decryption; rustls drops up to 16 KiB when no early
    /// data was ever offered). Set by the engine with the receive key —
    /// or, after a HelloRetryRequest, before any: then `application_data`
    /// records are dropped unopened until the second ClientHello.
    skip_early: usize = 0,
    /// QUIC (RFC 9001 §4): handshake data arrives as CRYPTO data, straight
    /// into `joiner` (`Server.quicFeed`); `installRx` installs no key.
    quic: bool = false,

    pub fn init(joiner_buf: []u8) Inbound {
        return .{ .joiner = .init(joiner_buf) };
    }

    /// Switch the receive direction to `traffic_secret` (the client's
    /// handshake or application secret, or a KeyUpdate). Refused if any
    /// handshake octet is held — a message that started under the old key
    /// cannot end under the new one, and nothing sent under the old key may
    /// be read under the new one (RFC 8446 §5.1).
    pub fn installRx(self: *Inbound, suite: record.CipherSuite, traffic_secret: []const u8) (Error || record.InitError)!void {
        if (!self.joiner.isEmpty()) return error.UnexpectedMessage;
        // QUIC: the key is the QUIC stack's; only the alignment matters.
        if (self.quic) return;
        if (self.protected) self.rx.wipe();
        // Not "protected" by a wiped (all-zero) key if `init` refuses.
        self.protected = false;
        try self.rx.init(suite, traffic_secret);
        self.protected = true;
    }

    pub fn wipe(self: *Inbound) void {
        if (self.protected) self.rx.wipe();
        self.protected = false;
        self.joiner.reset();
    }

    /// Process `buf` (the received octets not yet consumed) up to the next
    /// event. Whole records are taken from the front; protected ones are
    /// decrypted in place. An error is fatal for the connection: send
    /// `alertFor(err)` if it is non-null, then close.
    pub fn next(self: *Inbound, buf: []u8) Error!Result {
        var at: usize = 0;
        while (true) {
            if (self.closed) return .{ .event = .peer_closed, .consumed = at };
            if (try self.joiner.next()) |m| {
                self.handshake_seen = true;
                return .{ .event = .{ .handshake = m }, .consumed = at };
            }
            const rest = buf[at..];
            if (rest.len < header_len) return .{ .event = .need_more, .consumed = at };
            const h = record.parseHeader(rest[0..header_len]);
            try self.checkHeader(h);
            const n = header_len + @as(usize, h.length);
            if (rest.len < n) return .{ .event = .need_more, .consumed = at };
            at += n;
            if (try self.dispatch(rest[0..n], h)) |ev| return .{ .event = ev, .consumed = at };
        }
    }

    fn checkHeader(self: *const Inbound, h: record.Header) Error!void {
        switch (h.content_type) {
            .change_cipher_spec, .alert, .handshake, .application_data => {},
            else => return error.DecodeError,
        }
        if (h.legacy_version & 0xff00 != 0x0300) return error.DecodeError;
        if (h.length == 0 and h.content_type != .application_data) return error.DecodeError;
        // Early data skipped after a HelloRetryRequest is ciphertext too,
        // though no receive key is installed yet.
        const limit: usize = if (h.content_type == .application_data and (self.protected or self.skip_early != 0))
            record.max_ciphertext_len
        else
            record.max_plaintext_len;
        if (h.length > limit) return error.RecordOverflow;
    }

    /// Handshake data is held but incomplete: any other record type now is
    /// interleaving (RFC 8446 §5.1).
    fn notInterleaved(self: *const Inbound) Error!void {
        if (!self.joiner.isEmpty()) return error.UnexpectedMessage;
    }

    fn dispatch(self: *Inbound, rec: []u8, h: record.Header) Error!?Event {
        const body = rec[header_len..];
        if (!self.protected or h.content_type != .application_data) {
            switch (h.content_type) {
                .handshake => {
                    if (self.protected) return error.UnexpectedMessage;
                    try self.joiner.push(body);
                    return null;
                },
                .change_cipher_spec => {
                    try self.notInterleaved();
                    // RFC 8446 §5: after the first ClientHello, before the
                    // peer's Finished, exactly the octet 0x01.
                    if (!self.handshake_seen or self.app_data_ok) return error.UnexpectedMessage;
                    if (body.len != 1 or body[0] != 0x01) return error.UnexpectedMessage;
                    if (self.ccs_left == 0) return error.UnexpectedMessage;
                    self.ccs_left -= 1;
                    return null;
                },
                .alert => {
                    if (self.protected and (self.decrypted_any or body.len > 2)) return error.UnexpectedMessage;
                    try self.notInterleaved();
                    return try self.onAlert(body);
                },
                // Plaintext application data: only early data the client
                // sent with a ClientHello answered by a HelloRetryRequest
                // (no receive key yet), within `skip_early`. Otherwise
                // never (no 0-RTT; after the handshake every record is
                // protected).
                .application_data => {
                    // An empty record costs one octet: none are free.
                    const cost = @max(h.length, 1);
                    if (self.skip_early >= cost and self.joiner.isEmpty()) {
                        self.skip_early -= cost;
                        return null;
                    }
                    return error.UnexpectedMessage;
                },
                else => unreachable, // checkHeader
            }
        }
        const o = self.rx.open(rec) catch |err| return switch (err) {
            error.BadRecordMac => if (self.skip_early >= h.length and self.joiner.isEmpty()) {
                // An early-data record under the key the client used for
                // 0-RTT: skip it (`open` left the sequence number alone).
                self.skip_early -= h.length;
                return null;
            } else error.BadRecordMac,
            error.RecordOverflow => error.RecordOverflow,
            error.MissingContentType => error.UnexpectedMessage,
            error.SequenceExhausted => error.SequenceExhausted,
            // Exactly one record of type application_data was cut above.
            error.BadRecordLength, error.UnexpectedRecordType => unreachable,
        };
        self.decrypted_any = true;
        // The first record that opens ends the early data.
        self.skip_early = 0;
        switch (o.content_type) {
            .handshake => {
                // RFC 8446 §5.4: no zero-length handshake content.
                if (o.content.len == 0) return error.UnexpectedMessage;
                try self.joiner.push(o.content);
                return null;
            },
            .alert => {
                try self.notInterleaved();
                if (o.content.len == 0) return error.UnexpectedMessage;
                return try self.onAlert(o.content);
            },
            .application_data => {
                try self.notInterleaved();
                if (!self.app_data_ok and !self.early_data_ok) return error.UnexpectedMessage;
                return .{ .app_data = o.content };
            },
            // A protected change_cipher_spec, or an unknown inner type.
            else => return error.UnexpectedMessage,
        }
    }

    fn onAlert(self: *Inbound, content: []const u8) Error!?Event {
        const a = alert.parse(content) catch return error.DecodeError;
        switch (alert.classify(a, self.app_data_ok, &self.warnings)) {
            .peer_closed => {
                self.closed = true;
                return .peer_closed;
            },
            .ignore => return null,
            .peer_aborted => |d| {
                self.peer_alert = d;
                return error.PeerAborted;
            },
            .reply => |d| return switch (d) {
                .illegal_parameter => error.IllegalParameter,
                .decode_error => error.DecodeError,
                else => error.UnexpectedMessage,
            },
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Builds a byte stream of records for the tests.
const Stream = struct {
    buf: [4 * record.max_record_len]u8 = undefined,
    len: usize = 0,

    fn plain(s: *Stream, ct: record.ContentType, content: []const u8) void {
        record.writeHeader(s.buf[s.len..][0..header_len], ct, @intCast(content.len));
        @memcpy(s.buf[s.len + header_len ..][0..content.len], content);
        s.len += header_len + content.len;
    }

    fn sealed(s: *Stream, tx: *record.Protection, ct: record.ContentType, content: []const u8) void {
        @memcpy(s.buf[s.len + header_len ..][0..content.len], content);
        const r = tx.seal(s.buf[s.len..], content.len, ct, 0) catch unreachable;
        s.len += r.len;
    }

    fn bytes(s: *Stream) []u8 {
        return s.buf[0..s.len];
    }
};

fn hsMsg(comptime t: u8, comptime body: []const u8) [4 + body.len]u8 {
    var m: [4 + body.len]u8 = undefined;
    m[0] = t;
    std.mem.writeInt(u24, m[1..4], body.len, .big);
    @memcpy(m[4..], body);
    return m;
}

var joiner_storage: [Joiner.bufferLen(default_max_message)]u8 = undefined;

fn expectHandshake(r: Result, t: u8, body: []const u8) !void {
    try testing.expect(r.event == .handshake);
    try testing.expectEqual(t, r.event.handshake.msg_type);
    try testing.expectEqualSlices(u8, body, r.event.handshake.body);
}

test "one record, several handshake messages; one message, several records" {
    var in: Inbound = .init(&joiner_storage);
    var s: Stream = .{};
    const a = hsMsg(1, "client hello");
    const b = hsMsg(2, "x");
    s.plain(.handshake, &(a ++ b));
    var r = try in.next(s.bytes());
    try expectHandshake(r, 1, "client hello");
    try testing.expectEqualSlices(u8, &a, r.event.handshake.raw);
    try testing.expectEqual(s.len, r.consumed);
    r = try in.next(s.bytes()[r.consumed..]);
    try expectHandshake(r, 2, "x");
    try testing.expectEqual(@as(usize, 0), r.consumed);
    r = try in.next(s.bytes()[s.len..]);
    try testing.expect(r.event == .need_more);

    // A 40,000-octet message in three records, the header itself split.
    var big: [4 + 40_000]u8 = undefined;
    big[0] = 11;
    std.mem.writeInt(u24, big[1..4], 40_000, .big);
    for (big[4..], 0..) |*x, i| x.* = @truncate(i *% 7);
    var in2: Inbound = .init(&joiner_storage);
    var s2: Stream = .{};
    s2.plain(.handshake, big[0..2]);
    s2.plain(.handshake, big[2..16_000]);
    s2.plain(.handshake, big[16_000..30_000]);
    s2.plain(.handshake, big[30_000..]);
    // Fed 997 octets at a time (cutting headers and bodies) the result is the same.
    var fed: usize = 0;
    var off: usize = 0;
    while (true) {
        fed = @min(fed + 997, s2.len);
        r = try in2.next(s2.bytes()[off..fed]);
        off += r.consumed;
        if (r.event == .handshake) break;
        try testing.expect(r.event == .need_more);
        try testing.expect(fed < s2.len);
    }
    try expectHandshake(r, 11, big[4..]);
    try testing.expectEqual(s2.len, off);
}

test "record header checks: type, version, empty, size — before the body arrives" {
    var in: Inbound = .init(&joiner_storage);
    try testing.expectError(error.DecodeError, in.next(@constCast(&[_]u8{ 24, 3, 3, 0, 1 })));
    try testing.expectError(error.DecodeError, in.next(@constCast(&[_]u8{ 22, 2, 0, 0, 1 })));
    try testing.expectError(error.DecodeError, in.next(@constCast(&[_]u8{ 22, 3, 3, 0, 0 })));
    try testing.expectError(error.DecodeError, in.next(@constCast(&[_]u8{ 21, 3, 3, 0, 0 })));
    try testing.expectError(error.RecordOverflow, in.next(@constCast(&[_]u8{ 22, 3, 1, 0x40, 0x01 })));
    // Any 0x03XX version is accepted (0x0301 in a first ClientHello).
    var ok = [_]u8{ 22, 3, 1, 0x40, 0x00 };
    try testing.expect((try in.next(&ok)).event == .need_more);
}

test "interleaving: an alert or CCS inside a fragmented handshake message" {
    const m = hsMsg(1, "abcdefgh");
    inline for (.{ record.ContentType.alert, record.ContentType.change_cipher_spec }) |ct| {
        var in: Inbound = .init(&joiner_storage);
        in.handshake_seen = true;
        var s: Stream = .{};
        s.plain(.handshake, m[0..6]);
        s.plain(ct, if (ct == .alert) &.{ 2, 40 } else &.{1});
        s.plain(.handshake, m[6..]);
        try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()));
    }
}

test "compatibility CCS: dropped after a ClientHello, refused before, malformed or too often" {
    var in: Inbound = .init(&joiner_storage);
    var s: Stream = .{};
    s.plain(.change_cipher_spec, &.{1});
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()));

    in = .init(&joiner_storage);
    s = .{};
    const ch = hsMsg(1, "hello");
    s.plain(.handshake, &ch);
    s.plain(.change_cipher_spec, &.{1});
    s.plain(.change_cipher_spec, &.{1});
    const two_ccs = s.len;
    s.plain(.change_cipher_spec, &.{1});
    in.ccs_left = max_compat_ccs;
    const r = try in.next(s.bytes());
    try expectHandshake(r, 1, "hello");
    // Two dropped silently...
    const after = try in.next(s.bytes()[r.consumed..two_ccs]);
    try testing.expect(after.event == .need_more);
    try testing.expectEqual(two_ccs - r.consumed, after.consumed);
    // ... the third refused.
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()[two_ccs..]));
    try testing.expectEqual(@as(u8, 0), in.ccs_left);

    in = .init(&joiner_storage);
    in.handshake_seen = true;
    s = .{};
    s.plain(.change_cipher_spec, &.{2});
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()));
    s = .{};
    s.plain(.change_cipher_spec, &.{ 1, 1 });
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()));
    in.app_data_ok = true;
    s = .{};
    s.plain(.change_cipher_spec, &.{1});
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()));
}

test "protected: records open in place; plaintext handshake and app data refused" {
    const secret: [32]u8 = @splat(0x5a);
    var tx: record.Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &secret);
    var in: Inbound = .init(&joiner_storage);
    try in.installRx(.aes_128_gcm_sha256, &secret);

    var s: Stream = .{};
    const fin = hsMsg(20, "verify-data-32-octets...........");
    s.sealed(&tx, .handshake, fin[0..10]);
    s.sealed(&tx, .handshake, fin[10..]);
    // A plaintext CCS between protected records is still dropped.
    in.handshake_seen = true;
    s.plain(.change_cipher_spec, &.{1});
    s.sealed(&tx, .application_data, "early");
    var r = try in.next(s.bytes());
    try expectHandshake(r, 20, fin[4..]);
    var off = r.consumed;
    // Application data before app_data_ok (no 0-RTT).
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()[off..]));

    // After the Finished it flows; the slice aliases the input.
    var in2: Inbound = .init(&joiner_storage);
    try in2.installRx(.aes_128_gcm_sha256, &secret);
    in2.app_data_ok = true;
    var tx2: record.Protection = undefined;
    try tx2.init(.aes_128_gcm_sha256, &secret);
    s = .{};
    s.sealed(&tx2, .application_data, "GET /");
    s.sealed(&tx2, .application_data, "");
    s.sealed(&tx2, .alert, &alert.Alert.close_notify.encode());
    s.sealed(&tx2, .application_data, "ignored after close");
    r = try in2.next(s.bytes());
    try testing.expectEqualStrings("GET /", r.event.app_data);
    try testing.expect(@intFromPtr(r.event.app_data.ptr) == @intFromPtr(&s.buf[header_len]));
    off = r.consumed;
    r = try in2.next(s.bytes()[off..]);
    try testing.expectEqual(@as(usize, 0), r.event.app_data.len);
    off += r.consumed;
    r = try in2.next(s.bytes()[off..]);
    try testing.expect(r.event == .peer_closed);
    off += r.consumed;
    r = try in2.next(s.bytes()[off..]);
    try testing.expect(r.event == .peer_closed);
    try testing.expectEqual(@as(usize, 0), r.consumed);

    // A plaintext handshake record under protection.
    var in3: Inbound = .init(&joiner_storage);
    try in3.installRx(.aes_128_gcm_sha256, &secret);
    s = .{};
    s.plain(.handshake, &fin);
    try testing.expectError(error.UnexpectedMessage, in3.next(s.bytes()));
    // Plaintext application data before any key.
    var in4: Inbound = .init(&joiner_storage);
    s = .{};
    s.plain(.application_data, "x");
    try testing.expectError(error.UnexpectedMessage, in4.next(s.bytes()));
}

test "protected: tampered record is bad_record_mac; empty handshake, protected CCS, unknown inner type" {
    const secret: [32]u8 = @splat(0x6b);
    const cases = [_]struct { ct: record.ContentType, content: []const u8, err: Error }{
        .{ .ct = .handshake, .content = "", .err = error.UnexpectedMessage },
        .{ .ct = .alert, .content = "", .err = error.UnexpectedMessage },
        .{ .ct = .change_cipher_spec, .content = &.{1}, .err = error.UnexpectedMessage },
        .{ .ct = @fromBackingInt(99), .content = "x", .err = error.UnexpectedMessage },
        .{ .ct = .alert, .content = &.{ 2, 40, 0 }, .err = error.DecodeError },
    };
    for (cases) |c| {
        var tx: record.Protection = undefined;
        try tx.init(.chacha20_poly1305_sha256, &secret);
        var in: Inbound = .init(&joiner_storage);
        try in.installRx(.chacha20_poly1305_sha256, &secret);
        var s: Stream = .{};
        s.sealed(&tx, c.ct, c.content);
        try testing.expectError(c.err, in.next(s.bytes()));
    }
    var tx: record.Protection = undefined;
    try tx.init(.chacha20_poly1305_sha256, &secret);
    var in: Inbound = .init(&joiner_storage);
    try in.installRx(.chacha20_poly1305_sha256, &secret);
    var s: Stream = .{};
    s.sealed(&tx, .handshake, "abc");
    s.buf[header_len + 1] ^= 1;
    try testing.expectError(error.BadRecordMac, in.next(s.bytes()));
    try testing.expectEqual(alert.Description.bad_record_mac, alertFor(error.BadRecordMac).?);
}

test "plaintext alerts: before keys, and after them until the first record is opened" {
    // A fatal alert from the peer.
    var in: Inbound = .init(&joiner_storage);
    var s: Stream = .{};
    s.plain(.alert, &alert.Alert.fatal(.protocol_version).encode());
    try testing.expectError(error.PeerAborted, in.next(s.bytes()));
    try testing.expectEqual(alert.Description.protocol_version, in.peer_alert.?);
    try testing.expectEqual(@as(?alert.Description, null), alertFor(error.PeerAborted));

    // close_notify before the handshake is an abort, not a close.
    in = .init(&joiner_storage);
    s = .{};
    s.plain(.alert, &alert.Alert.close_notify.encode());
    try testing.expectError(error.PeerAborted, in.next(s.bytes()));

    // Under a receive key, before anything was opened: accepted in the clear.
    const secret: [32]u8 = @splat(0x7c);
    in = .init(&joiner_storage);
    try in.installRx(.aes_128_gcm_sha256, &secret);
    s = .{};
    s.plain(.alert, &alert.Alert.fatal(.bad_certificate).encode());
    try testing.expectError(error.PeerAborted, in.next(s.bytes()));
    try testing.expectEqual(alert.Description.bad_certificate, in.peer_alert.?);

    // ... but not once a protected record has been opened.
    var tx: record.Protection = undefined;
    try tx.init(.aes_128_gcm_sha256, &secret);
    in = .init(&joiner_storage);
    try in.installRx(.aes_128_gcm_sha256, &secret);
    s = .{};
    const fin = hsMsg(20, "f");
    s.sealed(&tx, .handshake, &fin);
    s.plain(.alert, &alert.Alert.fatal(.bad_certificate).encode());
    const r = try in.next(s.bytes());
    try expectHandshake(r, 20, "f");
    try testing.expectError(error.UnexpectedMessage, in.next(s.bytes()[r.consumed..]));

    // A warning other than user_canceled is answered with decode_error; an
    // unknown level with illegal_parameter; a malformed alert is decode_error.
    in = .init(&joiner_storage);
    s = .{};
    s.plain(.alert, &.{ 1, 42 });
    try testing.expectError(error.DecodeError, in.next(s.bytes()));
    in = .init(&joiner_storage);
    s = .{};
    s.plain(.alert, &.{ 7, 40 });
    try testing.expectError(error.IllegalParameter, in.next(s.bytes()));
    in = .init(&joiner_storage);
    s = .{};
    s.plain(.alert, &.{2});
    try testing.expectError(error.DecodeError, in.next(s.bytes()));
}

test "key change: refused with handshake data pending, partial or whole" {
    const secret: [32]u8 = @splat(0x01);
    const ch = hsMsg(1, "hello");
    const extra = hsMsg(20, "early finished");
    // ClientHello and another message in one plaintext record: the second
    // would be read under the wrong key.
    var in: Inbound = .init(&joiner_storage);
    var s: Stream = .{};
    s.plain(.handshake, &(ch ++ extra));
    const r = try in.next(s.bytes());
    try expectHandshake(r, 1, "hello");
    try testing.expectError(error.UnexpectedMessage, in.installRx(.aes_128_gcm_sha256, &secret));
    // A partial message.
    in = .init(&joiner_storage);
    s = .{};
    s.plain(.handshake, &(ch ++ extra[0..3].*));
    _ = try in.next(s.bytes());
    try testing.expect((try in.next(s.bytes()[s.len..])).event == .need_more);
    try testing.expectError(error.UnexpectedMessage, in.installRx(.aes_128_gcm_sha256, &secret));
    // Aligned: accepted.
    in = .init(&joiner_storage);
    s = .{};
    s.plain(.handshake, &ch);
    _ = try in.next(s.bytes());
    try in.installRx(.aes_128_gcm_sha256, &secret);
    in.wipe();
}

test "rejected early data: records that fail to open are skipped within the budget, until one opens" {
    const hs_secret: [32]u8 = @splat(0x21);
    const early_secret: [32]u8 = @splat(0x22);
    var hs_tx: record.Protection = undefined;
    try hs_tx.init(.aes_128_gcm_sha256, &hs_secret);
    var early_tx: record.Protection = undefined;
    try early_tx.init(.aes_128_gcm_sha256, &early_secret);
    var s: Stream = .{};
    s.sealed(&early_tx, .application_data, "0-RTT request one");
    s.sealed(&early_tx, .application_data, "0-RTT request two");
    const fin = hsMsg(20, "finished");
    s.sealed(&hs_tx, .handshake, &fin);
    const after_fin = s.len;
    s.sealed(&early_tx, .application_data, "too late");

    var in: Inbound = .init(&joiner_storage);
    try in.installRx(.aes_128_gcm_sha256, &hs_secret);
    in.skip_early = 1000;
    const r = try in.next(s.bytes());
    try expectHandshake(r, 20, "finished");
    try testing.expectEqual(after_fin, r.consumed);
    try testing.expectEqual(@as(usize, 0), in.skip_early);
    // After a record opened, a failing one is a failure again.
    try testing.expectError(error.BadRecordMac, in.next(s.bytes()[after_fin..]));

    // Over the budget: refused.
    var in2: Inbound = .init(&joiner_storage);
    try in2.installRx(.aes_128_gcm_sha256, &hs_secret);
    in2.skip_early = 40; // less than the two records' 2 x 34 octets
    try testing.expectError(error.BadRecordMac, in2.next(s.bytes()));
    // Without a budget nothing is skipped.
    var in3: Inbound = .init(&joiner_storage);
    try in3.installRx(.aes_128_gcm_sha256, &hs_secret);
    try testing.expectError(error.BadRecordMac, in3.next(s.bytes()));
}

test "after a HelloRetryRequest: plaintext early data is skipped within the budget, before any key" {
    var s: Stream = .{};
    s.plain(.application_data, &(@as([30]u8, @splat(0x99))));
    s.plain(.application_data, &(@as([30]u8, @splat(0x98))));
    const ch2 = hsMsg(1, "second hello");
    s.plain(.handshake, &ch2);

    var in: Inbound = .init(&joiner_storage);
    in.handshake_seen = true;
    in.skip_early = 60;
    const r = try in.next(s.bytes());
    try expectHandshake(r, 1, "second hello");
    try testing.expectEqual(@as(usize, 0), in.skip_early);
    // Over the budget, or without one: unexpected_message.
    var in2: Inbound = .init(&joiner_storage);
    in2.skip_early = 59;
    try testing.expectError(error.UnexpectedMessage, in2.next(s.bytes()));
    var in3: Inbound = .init(&joiner_storage);
    try testing.expectError(error.UnexpectedMessage, in3.next(s.bytes()));
    // Empty records are not free: each costs one octet of the budget.
    var empties: Stream = .{};
    for (0..3) |_| empties.plain(.application_data, "");
    var in6: Inbound = .init(&joiner_storage);
    in6.skip_early = 2;
    try testing.expectError(error.UnexpectedMessage, in6.next(empties.bytes()));
    // Early data is ciphertext: a record up to 2^14 + 256 is skippable,
    // one past the budget unexpected (not record_overflow).
    var big: [record.header_len + record.max_plaintext_len + 1]u8 = @splat(0x77);
    big[0..5].* = .{ 23, 3, 3, 0x40, 0x01 };
    var in4: Inbound = .init(&joiner_storage);
    in4.skip_early = record.max_plaintext_len;
    try testing.expectError(error.UnexpectedMessage, in4.next(&big));
    var in5: Inbound = .init(&joiner_storage);
    in5.skip_early = record.max_plaintext_len + 1;
    try testing.expectEqual(Event.need_more, (try in5.next(&big)).event);
}

test "joiner: reset zeroes what compaction left behind" {
    var b: [Joiner.bufferLen(100)]u8 = @splat(0);
    var j: Joiner = .init(&b);
    var m: [104]u8 = @splat(0xaa);
    m[0] = 1;
    m[1] = 0;
    m[2] = 0;
    m[3] = 100;
    try j.push(&(m ++ [_]u8{ 2, 0 }));
    _ = (try j.next()).?;
    try j.push(&.{ 0, 1, 0xbb }); // compacts the 2 held octets to the front
    try testing.expectEqual(@as(u8, 2), (try j.next()).?.msg_type);
    j.reset();
    for (b) |x| try testing.expectEqual(@as(u8, 0), x);
}

test "joiner: a message over the cap is refused from its header alone" {
    var small: [Joiner.bufferLen(100)]u8 = undefined;
    var in: Inbound = .init(&small);
    var s: Stream = .{};
    s.plain(.handshake, &.{ 1, 0, 0, 101 });
    try testing.expectError(error.HandshakeTooLarge, in.next(s.bytes()));
    var in2: Inbound = .init(&small);
    s = .{};
    var m: [104]u8 = @splat(0);
    m[0] = 1;
    m[3] = 100;
    s.plain(.handshake, &m);
    try expectHandshake(try in2.next(s.bytes()), 1, m[4..]);
}
