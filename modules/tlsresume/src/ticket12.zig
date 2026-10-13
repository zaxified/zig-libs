// SPDX-License-Identifier: MIT

//! tlsresume.ticket12 — TLS 1.2 session tickets (RFC 5077): the
//! NewSessionTicket handshake body (§3.3) and the SessionTicket ClientHello
//! extension (§3.2, type 35).
//!
//! **Sealing is reused as-is.** The `ticket` bytes ARE a `stek.StekRing.seal`
//! blob. The TLS engine serializes its own 1.2 session state (master secret,
//! cipher suite, extended-master-secret flag, ...) exactly as it does for
//! TLS 1.3 and seals it with the ring; this file only frames the result.
//!
//! **RFC 5077 §4's recommended ticket format is NOT adopted, on purpose.** It
//! prescribes `key_name || IV || AES-128-CBC(state) || HMAC-SHA-256`, i.e.
//! CBC plus a separate MAC. The ring's `key_id || nonce || ct || tag` is a
//! single AES-256-GCM AEAD with the key id authenticated as AAD: no padding
//! oracle, no MAC-then-encrypt ordering to get wrong. §4 is a "recommended"
//! format only; the ticket is opaque to the client (§3.3), so any
//! server-private format interoperates.

const std = @import("std");
const ticket = @import("ticket.zig");

pub const EncodeError = ticket.EncodeError;
pub const DecodeError = ticket.DecodeError;

/// The SessionTicket extension type (RFC 5077 §3.2, IANA "session_ticket").
pub const extension_type: u16 = 35;

/// What a ClientHello `SessionTicket` extension carries (RFC 5077 §3.2).
pub const ClientExtension = enum {
    /// Empty extension data: the client supports tickets and has none; the
    /// server may send a NewSessionTicket.
    supports_new,
    /// Non-empty extension data: a ticket to open with `StekRing.open`.
    offers_ticket,
};

/// Classify the `extension_data` of a ClientHello SessionTicket extension:
/// empty means the client supports tickets, non-empty is a ticket to open.
pub fn classifyClientExtension(data: []const u8) ClientExtension {
    return if (data.len == 0) .supports_new else .offers_ticket;
}

/// RFC 5077 §3.3 NewSessionTicket handshake body (TLS 1.2):
/// `uint32 ticket_lifetime_hint; opaque ticket<0..2^16-1>`. A zero-length
/// ticket is legal: §3.3 has a server that announced the SessionTicket
/// extension in its ServerHello and then decides against issuing one send
/// exactly that, and the client must then keep no ticket (`isWithdrawal`).
pub const NewSessionTicket12 = struct {
    /// Advisory lifetime in seconds (0 = unspecified, §3.3).
    lifetime_hint_s: u32,
    /// The opaque ticket (a `StekRing.seal` blob).
    ticket: []const u8,

    /// Bytes `encode` writes for this value (4 + 2 + ticket.len).
    pub fn encodedLen(self: NewSessionTicket12) usize {
        return 4 + 2 + self.ticket.len;
    }

    /// Encode to `out` and return the written slice. `BufferTooSmall` if
    /// `out` is short, or if the ticket is longer than 65535 bytes (not
    /// representable as `opaque ticket<0..2^16-1>`).
    pub fn encode(self: NewSessionTicket12, out: []u8) EncodeError![]u8 {
        if (self.ticket.len > std.math.maxInt(u16)) return error.BufferTooSmall;
        const n = self.encodedLen();
        if (out.len < n) return error.BufferTooSmall;
        std.mem.writeInt(u32, out[0..4], self.lifetime_hint_s, .big);
        std.mem.writeInt(u16, out[4..6], @intCast(self.ticket.len), .big);
        @memcpy(out[6..n], self.ticket);
        return out[0..n];
    }

    /// Decode a handshake body. `Malformed` on a short head, a length that
    /// overruns `bytes`, or trailing bytes. The
    /// returned `ticket` aliases `bytes`.
    pub fn decode(bytes: []const u8) DecodeError!NewSessionTicket12 {
        if (bytes.len < 6) return error.Malformed;
        const len = std.mem.readInt(u16, bytes[4..6], .big);
        if (bytes.len != 6 + @as(usize, len)) return error.Malformed;
        return .{
            .lifetime_hint_s = std.mem.readInt(u32, bytes[0..4], .big),
            .ticket = bytes[6..],
        };
    }

    /// True for the zero-length ticket of RFC 5077 §3.3: the server
    /// withdrew the ticket it announced; the client keeps none.
    pub fn isWithdrawal(self: NewSessionTicket12) bool {
        return self.ticket.len == 0;
    }
};

const testing = std.testing;

test "NewSessionTicket12: RFC 5077 shape byte-exact" {
    var buf: [16]u8 = undefined;
    const t = NewSessionTicket12{ .lifetime_hint_s = 7200, .ticket = "abc" };
    const wire = try t.encode(&buf);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x1c, 0x20, 0x00, 0x03, 0x61, 0x62, 0x63 }, wire);
    try testing.expectEqual(@as(usize, 9), t.encodedLen());
    const back = try NewSessionTicket12.decode(wire);
    try testing.expectEqual(@as(u32, 7200), back.lifetime_hint_s);
    try testing.expectEqualSlices(u8, "abc", back.ticket);
}

test "NewSessionTicket12: max-size ticket round trip" {
    const big = [_]u8{0x5a} ** 65535;
    var buf: [65535 + 6]u8 = undefined;
    const wire = try (NewSessionTicket12{ .lifetime_hint_s = 1, .ticket = &big }).encode(&buf);
    const back = try NewSessionTicket12.decode(wire);
    try testing.expectEqual(@as(usize, 65535), back.ticket.len);
}

test "NewSessionTicket12: encode errors" {
    var small: [8]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, (NewSessionTicket12{ .lifetime_hint_s = 0, .ticket = "abc" }).encode(&small));
    const huge = [_]u8{0} ** 65536;
    var big: [65536 + 6]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, (NewSessionTicket12{ .lifetime_hint_s = 0, .ticket = &huge }).encode(&big));
}

test "NewSessionTicket12: every malformed shape" {
    const M = error.Malformed;
    try testing.expectError(M, NewSessionTicket12.decode(&.{}));
    try testing.expectError(M, NewSessionTicket12.decode(&.{ 0, 0, 0, 0, 0 })); // short head
    try testing.expectError(M, NewSessionTicket12.decode(&.{ 0, 0, 0, 0, 0, 3, 1, 2 })); // overrun
    try testing.expectError(M, NewSessionTicket12.decode(&.{ 0, 0, 0, 0, 0, 1, 1, 2 })); // trailing
    try testing.expectError(M, NewSessionTicket12.decode(&.{ 0, 0, 0, 0, 0, 0, 1 })); // empty + trailing
}

test "NewSessionTicket12: the zero-length ticket of RFC 5077 §3.3 is a withdrawal, not an error" {
    var buf: [8]u8 = undefined;
    const wire = try (NewSessionTicket12{ .lifetime_hint_s = 0, .ticket = "" }).encode(&buf);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0 }, wire);
    const back = try NewSessionTicket12.decode(wire);
    try testing.expect(back.isWithdrawal());
    try testing.expect(!(NewSessionTicket12{ .lifetime_hint_s = 0, .ticket = "x" }).isWithdrawal());
}

test "classifyClientExtension and extension_type" {
    try testing.expectEqual(@as(u16, 35), extension_type);
    try testing.expectEqual(ClientExtension.supports_new, classifyClientExtension(""));
    try testing.expectEqual(ClientExtension.offers_ticket, classifyClientExtension("x"));
}

test "ticket bytes are a StekRing blob (seal -> frame -> decode -> open)" {
    const stek = @import("stek.zig");
    var ring = stek.DefaultRing.init();
    ring.rotate(3, &([_]u8{0x42} ** stek.key_length), 0);
    var blob: [64]u8 = undefined;
    const sealed = try ring.seal("tls12 session state", [_]u8{1} ** stek.nonce_length, &blob);
    var wire: [80]u8 = undefined;
    const msg = try (NewSessionTicket12{ .lifetime_hint_s = 600, .ticket = sealed }).encode(&wire);
    const dec = try NewSessionTicket12.decode(msg);
    var out: [64]u8 = undefined;
    try testing.expectEqualSlices(u8, "tls12 session state", try ring.open(dec.ticket, &out));
}
