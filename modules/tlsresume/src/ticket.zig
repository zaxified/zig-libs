// SPDX-License-Identifier: MIT

//! tlsresume.ticket — the NewSessionTicket handshake message body (RFC 8446
//! §4.6.1), pure wire codec: real, no crypto, KAT-validated byte-for-byte
//! against RFC 8448 §3 ("Simple 1-RTT Handshake"'s NewSessionTicket trace).
//!
//! Wire shape (RFC 8446 §4.6.1):
//!
//! ```
//! struct {
//!     uint32 ticket_lifetime;
//!     uint32 ticket_age_add;
//!     opaque ticket_nonce<0..255>;
//!     opaque ticket<1..2^16-1>;
//!     Extension extensions<0..2^16-2>;
//! } NewSessionTicket;
//!
//! struct {
//!     ExtensionType extension_type;
//!     opaque extension_data<0..2^16-1>;
//! } Extension;
//! ```
//!
//! `ticket` itself is opaque per the RFC ("the contents ... are entirely up
//! to the server" — §4.6.1) — this module's own opaque-ticket format is
//! `stek.zig`'s STEK-sealed blob, but `ticket.zig` never looks inside it;
//! decode just hands the bytes back as a slice. The one extension this
//! module names is `early_data` (§4.2.10, extension type 42) carrying
//! `max_early_data_size` — the only NewSessionTicket extension RFC 8446
//! itself defines.
//!
//! This file does NOT include the 4-byte generic handshake-message header
//! (`msg_type(1) || length(3)`, RFC 8446 §4) — `encode`/`decode` operate on
//! the NewSessionTicket BODY only, so this codec is reusable regardless of
//! how the engine frames handshake messages (its own `handshake.zig`-style
//! layer, if any). See the tests for how to strip/prepend that header
//! against the RFC 8448 trace.

const std = @import("std");

/// RFC 8446 §4.2.10: the `early_data` extension type, used inside
/// NewSessionTicket to advertise `max_early_data_size` (0-RTT support for
/// tickets issued off this connection).
pub const early_data_extension_type: u16 = 42;

/// One `Extension` (RFC 8446 §4) — generic type + opaque data. Only
/// `early_data` is interpreted by name in this module (`maxEarlyDataSize`);
/// any other extension type round-trips as opaque bytes.
pub const Extension = struct {
    ext_type: u16,
    data: []const u8,
};

pub const EncodeError = error{BufferTooSmall};
pub const DecodeError = error{Malformed};

pub const NewSessionTicket = struct {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
    extensions: []const Extension = &.{},

    /// Encode the NewSessionTicket BODY (no handshake-message header) into
    /// `out`. Returns the written slice, or `error.BufferTooSmall`.
    pub fn encode(self: NewSessionTicket, out: []u8) EncodeError![]u8 {
        // 4 (lifetime) + 4 (age_add) + 1+nonce + 2+ticket + 2+extensions.
        var ext_len: usize = 0;
        for (self.extensions) |e| ext_len += 2 + 2 + e.data.len;
        const total = 4 + 4 + 1 + self.ticket_nonce.len + 2 + self.ticket.len + 2 + ext_len;
        if (out.len < total) return error.BufferTooSmall;

        var w: usize = 0;
        std.mem.writeInt(u32, out[w..][0..4], self.ticket_lifetime, .big);
        w += 4;
        std.mem.writeInt(u32, out[w..][0..4], self.ticket_age_add, .big);
        w += 4;

        out[w] = @intCast(self.ticket_nonce.len);
        w += 1;
        @memcpy(out[w..][0..self.ticket_nonce.len], self.ticket_nonce);
        w += self.ticket_nonce.len;

        std.mem.writeInt(u16, out[w..][0..2], @intCast(self.ticket.len), .big);
        w += 2;
        @memcpy(out[w..][0..self.ticket.len], self.ticket);
        w += self.ticket.len;

        std.mem.writeInt(u16, out[w..][0..2], @intCast(ext_len), .big);
        w += 2;
        for (self.extensions) |e| {
            std.mem.writeInt(u16, out[w..][0..2], e.ext_type, .big);
            w += 2;
            std.mem.writeInt(u16, out[w..][0..2], @intCast(e.data.len), .big);
            w += 2;
            @memcpy(out[w..][0..e.data.len], e.data);
            w += e.data.len;
        }
        std.debug.assert(w == total);
        return out[0..total];
    }

    /// Decode a NewSessionTicket BODY from `bytes` (no handshake-message
    /// header). All returned slices (`ticket_nonce`, `ticket`, each
    /// extension's `data`) are views into `bytes` — the caller owns
    /// `bytes`'s lifetime, nothing is copied or allocated. `extensions`
    /// views into a caller-supplied scratch array (`ext_buf`) since this
    /// module allocates nothing; `ext_buf` must have room for every
    /// extension present or `error.Malformed` (`TooManyExtensions`-shaped,
    /// folded into `Malformed` to keep the error set small per
    /// CONVENTIONS.md's typed-error style) is returned.
    pub fn decode(bytes: []const u8, ext_buf: []Extension) DecodeError!NewSessionTicket {
        var r: usize = 0;
        if (bytes.len < 4 + 4 + 1) return error.Malformed;
        const ticket_lifetime = std.mem.readInt(u32, bytes[r..][0..4], .big);
        r += 4;
        const ticket_age_add = std.mem.readInt(u32, bytes[r..][0..4], .big);
        r += 4;

        const nonce_len = bytes[r];
        r += 1;
        if (bytes.len < r + nonce_len) return error.Malformed;
        const ticket_nonce = bytes[r..][0..nonce_len];
        r += nonce_len;

        if (bytes.len < r + 2) return error.Malformed;
        const ticket_len = std.mem.readInt(u16, bytes[r..][0..2], .big);
        r += 2;
        if (ticket_len == 0) return error.Malformed; // opaque ticket<1..2^16-1>
        if (bytes.len < r + ticket_len) return error.Malformed;
        const ticket = bytes[r..][0..ticket_len];
        r += ticket_len;

        if (bytes.len < r + 2) return error.Malformed;
        const ext_total_len = std.mem.readInt(u16, bytes[r..][0..2], .big);
        r += 2;
        if (bytes.len < r + ext_total_len) return error.Malformed;
        const ext_end = r + ext_total_len;

        var n_ext: usize = 0;
        while (r < ext_end) {
            if (ext_end - r < 4) return error.Malformed;
            const ext_type = std.mem.readInt(u16, bytes[r..][0..2], .big);
            r += 2;
            const data_len = std.mem.readInt(u16, bytes[r..][0..2], .big);
            r += 2;
            if (ext_end - r < data_len) return error.Malformed;
            if (n_ext >= ext_buf.len) return error.Malformed;
            ext_buf[n_ext] = .{ .ext_type = ext_type, .data = bytes[r..][0..data_len] };
            n_ext += 1;
            r += data_len;
        }
        if (r != ext_end) return error.Malformed;
        if (r != bytes.len) return error.Malformed; // no trailing garbage

        return .{
            .ticket_lifetime = ticket_lifetime,
            .ticket_age_add = ticket_age_add,
            .ticket_nonce = ticket_nonce,
            .ticket = ticket,
            .extensions = ext_buf[0..n_ext],
        };
    }

    /// If an `early_data` extension (type 42) is present, its
    /// `max_early_data_size` (RFC 8446 §4.2.10); `null` if this ticket does
    /// not offer 0-RTT.
    pub fn maxEarlyDataSize(self: NewSessionTicket) ?u32 {
        for (self.extensions) |e| {
            if (e.ext_type == early_data_extension_type and e.data.len == 4) {
                return std.mem.readInt(u32, e.data[0..4], .big);
            }
        }
        return null;
    }
};

/// Build an `early_data` extension (RFC 8446 §4.2.10) advertising
/// `max_size`. `buf` must be at least 4 bytes; the returned `Extension`'s
/// `data` views into it.
pub fn earlyDataExtension(max_size: u32, buf: *[4]u8) Extension {
    std.mem.writeInt(u32, buf, max_size, .big);
    return .{ .ext_type = early_data_extension_type, .data = buf[0..] };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexToOwned(comptime n: usize, s: []const u8) [n]u8 {
    @setEvalBranchQuota(10_000);
    var out: [n]u8 = undefined;
    var buf: [n * 2]u8 = undefined; // s may contain spaces/newlines; strip them first
    var j: usize = 0;
    for (s) |c| {
        if (c == ' ' or c == '\n' or c == '\r' or c == '\t') continue;
        buf[j] = c;
        j += 1;
    }
    _ = std.fmt.hexToBytes(&out, buf[0..j]) catch unreachable;
    return out;
}

// RFC 8448 §3 "Simple 1-RTT Handshake" — the NewSessionTicket handshake
// message (205 octets incl. the 4-byte handshake header). Fetched from
// https://www.rfc-editor.org/rfc/rfc8448 §3, the record whose plaintext
// starts `04 00 00 c9` (msg_type=new_session_ticket, length=0x00c9=201).
const rfc8448_new_session_ticket_message = hexToOwned(205,
    \\04 00 00 c9 00 00 00 1e fa d6 aa c5 02 00 00 00 b2 2c 03 5d
    \\82 93 59 ee 5f f7 af 4e c9 00 00 00 00 26 2a 64 94 dc 48 6d
    \\2c 8a 34 cb 33 fa 90 bf 1b 00 70 ad 3c 49 88 83 c9 36 7c 09
    \\a2 be 78 5a bc 55 cd 22 60 97 a3 a9 82 11 72 83 f8 2a 03 a1
    \\43 ef d3 ff 5d d3 6d 64 e8 61 be 7f d6 1d 28 27 db 27 9c ce
    \\14 50 77 d4 54 a3 66 4d 4e 6d a4 d2 9e e0 37 25 a6 a4 da fc
    \\d0 fc 67 d2 ae a7 05 29 51 3e 3d a2 67 7f a5 90 6c 5b 3f 7d
    \\8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb f2 97 b5 ae a6 17 64
    \\6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41 ef 5f 7d e6 50 5e
    \\5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57 00 08 00 2a 00
    \\04 00 00 04 00
);

test "RFC 8448 §3: decode the real NewSessionTicket wire message (byte-exact)" {
    // Strip the 4-byte generic handshake header (msg_type || u24 length);
    // this module's codec operates on the BODY only.
    const msg = rfc8448_new_session_ticket_message;
    try testing.expectEqual(@as(u8, 0x04), msg[0]); // new_session_ticket
    const body_len = (@as(u24, msg[1]) << 16) | (@as(u24, msg[2]) << 8) | msg[3];
    try testing.expectEqual(@as(u24, 201), body_len);
    const body = msg[4..];
    try testing.expectEqual(@as(usize, 201), body.len);

    var ext_buf: [4]Extension = undefined;
    const nst = try NewSessionTicket.decode(body, &ext_buf);

    try testing.expectEqual(@as(u32, 30), nst.ticket_lifetime);
    try testing.expectEqual(@as(u32, 0xfad6aac5), nst.ticket_age_add);
    try testing.expectEqualSlices(u8, &hexToOwned(2, "00 00"), nst.ticket_nonce);
    try testing.expectEqual(@as(usize, 178), nst.ticket.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x2c, 0x03, 0x5d, 0x82 }, nst.ticket[0..4]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x93, 0x93, 0x4a, 0xe4, 0xd3, 0x57 }, nst.ticket[nst.ticket.len - 6 ..]);

    try testing.expectEqual(@as(usize, 1), nst.extensions.len);
    try testing.expectEqual(early_data_extension_type, nst.extensions[0].ext_type);
    try testing.expectEqualSlices(u8, &hexToOwned(4, "00 00 04 00"), nst.extensions[0].data);
    try testing.expectEqual(@as(u32, 1024), nst.maxEarlyDataSize().?);
}

test "encode/decode round-trip: matches the RFC 8448 wire bytes exactly" {
    var ed_buf: [4]u8 = undefined;
    const ext = earlyDataExtension(1024, &ed_buf);
    const nonce = hexToOwned(2, "00 00");
    const ticket_body = rfc8448_new_session_ticket_message[4 + 4 + 4 + 1 + 2 + 2 ..][0..178];
    // ticket_body offset: header(4) + lifetime(4) + age_add(4) + nonce_len(1)
    // + nonce(2) + ticket_len(2) = 17; recompute precisely below instead of
    // trusting arithmetic in a comment.
    const ticket_off = 4 + 4 + 4 + 1 + nonce.len + 2;
    try testing.expectEqual(@as(usize, 17), ticket_off);
    const ticket = rfc8448_new_session_ticket_message[ticket_off..][0..178];
    try testing.expectEqualSlices(u8, ticket, ticket_body);

    const nst = NewSessionTicket{
        .ticket_lifetime = 30,
        .ticket_age_add = 0xfad6aac5,
        .ticket_nonce = &nonce,
        .ticket = ticket,
        .extensions = &.{ext},
    };
    var out: [512]u8 = undefined;
    const encoded = try nst.encode(&out);
    try testing.expectEqualSlices(u8, rfc8448_new_session_ticket_message[4..], encoded);
}

test "decode: malformed inputs (truncated / trailing garbage) are typed errors" {
    var ext_buf: [4]Extension = undefined;
    try testing.expectError(error.Malformed, NewSessionTicket.decode(&.{ 0, 0 }, &ext_buf));

    // Truncated mid-ticket-nonce.
    const truncated = rfc8448_new_session_ticket_message[4..][0..10];
    try testing.expectError(error.Malformed, NewSessionTicket.decode(truncated, &ext_buf));

    // Trailing garbage byte appended after a structurally valid message.
    var with_garbage: [220]u8 = undefined;
    const body = rfc8448_new_session_ticket_message[4..];
    @memcpy(with_garbage[0..body.len], body);
    with_garbage[body.len] = 0xFF;
    try testing.expectError(error.Malformed, NewSessionTicket.decode(with_garbage[0 .. body.len + 1], &ext_buf));
}

test "decode: zero-length ticket is rejected (opaque ticket<1..2^16-1>)" {
    var ext_buf: [1]Extension = undefined;
    // lifetime(4) age_add(4) nonce_len=0(1) ticket_len=0(2) ext_len=0(2)
    const bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.Malformed, NewSessionTicket.decode(&bytes, &ext_buf));
}

test "encode: BufferTooSmall on an undersized destination" {
    const nst = NewSessionTicket{
        .ticket_lifetime = 1,
        .ticket_age_add = 2,
        .ticket_nonce = "n",
        .ticket = "ticket-bytes",
    };
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, nst.encode(&tiny));
}

test "maxEarlyDataSize: null when no early_data extension is present" {
    const nst = NewSessionTicket{
        .ticket_lifetime = 1,
        .ticket_age_add = 2,
        .ticket_nonce = "",
        .ticket = "t",
    };
    try testing.expect(nst.maxEarlyDataSize() == null);
}
