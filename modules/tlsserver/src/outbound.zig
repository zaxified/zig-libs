// SPDX-License-Identifier: MIT

//! tlsserver.outbound — the send side of the record layer: content written
//! straight into the record buffer, then framed — fragmented at
//! `max_fragment` (2^14 unless set lower) and,
//! once a send key is installed, sealed — in place.
//!
//! Usage: write up to `slot().len` octets of content into `slot()`, then
//! `commit(type, n)`; the records accumulate in `pending()` until the caller
//! sends them and `discard`s what went out. A message longer than a fragment is
//! split across records by moving its tail apart in the buffer (last
//! fragment first), so it is never copied to a second buffer.
//!
//! The last `alert_reserve` octets of the buffer are kept for one alert:
//! however full the application leaves it, a fatal alert or close_notify
//! can still be queued (only `.alert` content may use them).
//!
//! No padding is added (RFC 8446 §5.4 leaves it to policy; rustls pads
//! nothing either).

const std = @import("std");
const record = @import("record.zig");

const header_len = record.header_len;

pub const Error = error{
    /// The buffer cannot hold the records: the caller sized it too small for
    /// a flight (`Outbound` never grows), or did not drain it.
    OutputFull,
    /// The send sequence number is exhausted (`record.SealError`).
    SequenceExhausted,
};

/// Room for one sealed alert: header, two octets, inner type, tag.
pub const alert_reserve = header_len + 2 + 1 + record.tag_len;

/// The smallest `max_fragment` (BoringSSL's floor for
/// `SSL_set_max_send_fragment`).
pub const min_fragment: u16 = 512;

pub const Outbound = struct {
    buf: []u8,
    /// Records framed and not yet discarded: `buf[0..len]`.
    len: usize = 0,
    tx: record.Protection = undefined,
    protected: bool = false,
    /// The largest record content sent (rustls `max_fragment_size`,
    /// BoringSSL `SSL_set_max_send_fragment`); set it before the first
    /// `slot`, within [`min_fragment`, 2^14].
    max_fragment: u16 = record.max_plaintext_len,

    pub fn init(buf: []u8) Outbound {
        return .{ .buf = buf };
    }

    /// Overhead one record adds to its content.
    fn overhead(self: *const Outbound) usize {
        return if (self.protected) header_len + 1 + record.tag_len else header_len;
    }

    /// Where the next content goes. Its length bounds what `commit` can
    /// frame (fragmentation overhead included, conservatively).
    pub fn slot(self: *Outbound) []u8 {
        const free = (self.buf.len - self.len) -| alert_reserve;
        if (free <= header_len) return self.buf[self.buf.len..];
        // Content n needs n + ceil(n / max_fragment) * overhead; reserve
        // for the worst case of the free space.
        const per = @as(usize, self.max_fragment) + self.overhead();
        const records = (free + per - 1) / per;
        const usable = free -| records * self.overhead();
        return self.buf[self.len + header_len ..][0..usable];
    }

    /// Frame the `n` octets at the start of `slot()` as `content_type`
    /// records. Content over `max_fragment` is split; `n == 0` makes one empty record
    /// (legal for application data only — the caller's to know). Only an
    /// alert may use the `alert_reserve`.
    pub fn commit(self: *Outbound, content_type: record.ContentType, n: usize) Error!void {
        const max: usize = self.max_fragment;
        const o = self.overhead();
        const k = if (n == 0) 1 else (n + max - 1) / max;
        const keep: usize = if (content_type == .alert) 0 else alert_reserve;
        const room = (self.buf.len - self.len) -| keep;
        if (room < n + k * o) return error.OutputFull;
        const base = self.len + header_len;
        // Move fragments apart, last first: each one's destination is at or
        // past its source and past every earlier fragment's source.
        var i = k;
        while (i > 1) {
            i -= 1;
            const clen = @min(max, n - i * max);
            const src = base + i * max;
            const dst = self.len + i * (max + o) + header_len;
            std.mem.copyBackwards(u8, self.buf[dst..][0..clen], self.buf[src..][0..clen]);
        }
        for (0..k) |j| {
            const clen = if (n == 0) 0 else @min(max, n - j * max);
            const r = self.buf[self.len..];
            if (self.protected) {
                const sealed = self.tx.seal(r, clen, content_type, 0) catch |err| return switch (err) {
                    error.SequenceExhausted => error.SequenceExhausted,
                    // Space and size were checked above.
                    error.BufferTooSmall, error.RecordOverflow => unreachable,
                };
                self.len += sealed.len;
            } else {
                record.writeHeader(r[0..header_len], content_type, @intCast(clen));
                self.len += header_len + clen;
            }
        }
    }

    /// Copy `data` in and frame it (for short, already-built content: an
    /// alert, a CCS).
    pub fn write(self: *Outbound, content_type: record.ContentType, data: []const u8) Error!void {
        // Not through `slot`, which leaves out the alert reserve; `commit`
        // checks the room exactly.
        if (self.buf.len - self.len < header_len + data.len) return error.OutputFull;
        @memcpy(self.buf[self.len + header_len ..][0..data.len], data);
        try self.commit(content_type, data.len);
    }

    pub fn pending(self: *const Outbound) []const u8 {
        return self.buf[0..self.len];
    }

    /// The caller sent the first `n` pending octets.
    pub fn discard(self: *Outbound, n: usize) void {
        std.debug.assert(n <= self.len);
        std.mem.copyForwards(u8, self.buf[0 .. self.len - n], self.buf[n..self.len]);
        self.len -= n;
    }

    /// Protect every later record under `traffic_secret` (sequence 0).
    pub fn installTx(self: *Outbound, suite: record.CipherSuite, traffic_secret: []const u8) record.InitError!void {
        if (self.protected) self.tx.wipe();
        try self.tx.init(suite, traffic_secret);
        self.protected = true;
    }

    /// Zero the send key; records already framed stay pending.
    pub fn wipeKey(self: *Outbound) void {
        if (self.protected) self.tx.wipe();
        self.protected = false;
    }

    /// Zero the send key and every octet of the buffer.
    pub fn wipe(self: *Outbound) void {
        if (self.protected) self.tx.wipe();
        self.protected = false;
        std.crypto.secureZero(u8, self.buf);
        self.len = 0;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "plaintext: one record, then a message split over three" {
    var b: [3 * record.max_record_len]u8 = undefined;
    var o: Outbound = .init(&b);
    const s = o.slot();
    @memcpy(s[0..3], "abc");
    try o.commit(.handshake, 3);
    try testing.expectEqualSlices(u8, &.{ 22, 3, 3, 0, 3, 'a', 'b', 'c' }, o.pending());

    const n = 2 * record.max_plaintext_len + 100;
    const s2 = o.slot();
    for (s2[0..n], 0..) |*x, i| x.* = @truncate(i *% 13);
    try o.commit(.handshake, n);
    // Read the records back.
    var at: usize = 8;
    var got: usize = 0;
    while (at < o.len) {
        const h = record.parseHeader(o.pending()[at..][0..5]);
        try testing.expectEqual(record.ContentType.handshake, h.content_type);
        try testing.expect(h.length <= record.max_plaintext_len);
        for (o.pending()[at + 5 ..][0..h.length], got..) |x, i| try testing.expectEqual(@as(u8, @truncate(i *% 13)), x);
        got += h.length;
        at += 5 + h.length;
    }
    try testing.expectEqual(n, got);
    try testing.expectEqual(o.len, at);
}

test "protected: fragments seal in place and open back in order" {
    const secret: [48]u8 = @splat(0x42);
    var b: [3 * record.max_record_len]u8 = undefined;
    var o: Outbound = .init(&b);
    try o.installTx(.aes_256_gcm_sha384, &secret);
    var rx: record.Protection = undefined;
    try rx.init(.aes_256_gcm_sha384, &secret);
    const n = 2 * record.max_plaintext_len + 7;
    const s = o.slot();
    try testing.expect(s.len >= n);
    for (s[0..n], 0..) |*x, i| x.* = @truncate(i *% 31 +% 5);
    try o.commit(.handshake, n);
    try o.commit(.application_data, 0);
    var copy: [b.len]u8 = undefined;
    @memcpy(copy[0..o.len], o.pending());
    var at: usize = 0;
    var got: usize = 0;
    var records: usize = 0;
    while (at < o.len) : (records += 1) {
        const h = record.parseHeader(copy[at..][0..5]);
        const opened = try rx.open(copy[at..][0 .. 5 + h.length]);
        if (records < 3) {
            try testing.expectEqual(record.ContentType.handshake, opened.content_type);
            for (opened.content, got..) |x, i| try testing.expectEqual(@as(u8, @truncate(i *% 31 +% 5)), x);
            got += opened.content.len;
        } else {
            try testing.expectEqual(record.ContentType.application_data, opened.content_type);
            try testing.expectEqual(@as(usize, 0), opened.content.len);
        }
        at += 5 + h.length;
    }
    try testing.expectEqual(@as(usize, 4), records);
    try testing.expectEqual(n, got);
}

test "a lower max_fragment splits records at it" {
    const secret: [32]u8 = @splat(7);
    var b: [4096]u8 = undefined;
    var o: Outbound = .init(&b);
    o.max_fragment = min_fragment;
    try o.installTx(.aes_128_gcm_sha256, &secret);
    var rx: record.Protection = undefined;
    try rx.init(.aes_128_gcm_sha256, &secret);
    const n = 2 * min_fragment + 1;
    const s = o.slot();
    for (s[0..n], 0..) |*x, i| x.* = @truncate(i);
    try o.commit(.application_data, n);
    var copy: [b.len]u8 = undefined;
    @memcpy(copy[0..o.len], o.pending());
    var at: usize = 0;
    var lens: [3]usize = undefined;
    var k: usize = 0;
    while (at < o.len) : (k += 1) {
        const h = record.parseHeader(copy[at..][0..5]);
        const opened = try rx.open(copy[at..][0 .. 5 + h.length]);
        for (opened.content, k * min_fragment..) |x, i| try testing.expectEqual(@as(u8, @truncate(i)), x);
        lens[k] = opened.content.len;
        at += 5 + h.length;
    }
    try testing.expectEqualSlices(usize, &.{ min_fragment, min_fragment, 1 }, lens[0..k]);
    // What `slot` offers, `commit` frames — with each fragment's overhead.
    o.len = 0;
    const all = o.slot();
    try testing.expect(all.len > 4 * min_fragment);
    try o.commit(.application_data, all.len);
    try testing.expect(o.len <= b.len - alert_reserve);
}

test "slot never promises more than commit can frame; full buffer is OutputFull" {
    var b: [100]u8 = undefined;
    var o: Outbound = .init(&b);
    const secret: [32]u8 = @splat(1);
    try o.installTx(.chacha20_poly1305_sha256, &secret);
    const s = o.slot();
    // One record: 100 octets less the alert reserve, header, type octet and
    // tag.
    try testing.expectEqual(@as(usize, 100 - alert_reserve - 22), s.len);
    try o.commit(.application_data, s.len);
    try testing.expectEqual(@as(usize, 100 - alert_reserve), o.len);
    try testing.expectEqual(@as(usize, 0), o.slot().len);
    try testing.expectError(error.OutputFull, o.commit(.application_data, 0));
    try testing.expectError(error.OutputFull, o.write(.handshake, &.{ 24, 0, 0, 1, 0 }));
    // The reserve takes exactly one alert.
    try o.write(.alert, &.{ 2, 10 });
    try testing.expectEqual(@as(usize, 100), o.len);
    try testing.expectError(error.OutputFull, o.write(.alert, &.{ 2, 10 }));
    o.discard(40);
    try testing.expectEqual(@as(usize, 60), o.len);
    try testing.expectError(error.OutputFull, o.commit(.application_data, 50));
    o.wipe();
    for (b) |x| try testing.expectEqual(@as(u8, 0), x);
}
