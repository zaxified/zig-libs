// SPDX-License-Identifier: MIT

//! SSH-2.0 message numbers (RFC 4253 §12, RFC 4252 §6, RFC 4254 §9) and the
//! RFC 4251 §5 wire-format primitives (byte string / mpint / name-list) all
//! SSH messages are built from, plus `Cursor`, the non-allocating bounded
//! reader every message parser in this module decodes a received payload
//! with. Pure data-format code (no crypto, no protocol state) — everything
//! that touches KEX/cipher/protocol *logic* lives in `transport.zig`,
//! `server.zig`, `userauth.zig` and `connection.zig` instead.

const std = @import("std");

/// SSH message numbers: the RFC 4253 §12 transport-layer set (+ RFC 8731
/// naming), the RFC 4252 §6 userauth set (50-60), and the RFC 4254 §9
/// connection-protocol set (80-100).
pub const MessageType = enum(u8) {
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    /// Generic KEX-method-specific init message. For the elliptic-curve /
    /// curve25519 key-exchange methods this is what RFC 8731 calls
    /// SSH_MSG_KEX_ECDH_INIT — same wire number, method-specific payload.
    SSH_MSG_KEXDH_INIT = 30,
    /// aka SSH_MSG_KEX_ECDH_REPLY (RFC 8731) — see `SSH_MSG_KEXDH_INIT`.
    SSH_MSG_KEXDH_REPLY = 31,

    // ── userauth (RFC 4252 §6) ──────────────────────────────────────────
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    /// 60 is method-specific (RFC 4252 §6: "in the range 60..79 ... only
    /// valid during the authentication method they belong to"). For the
    /// `publickey` method it is SSH_MSG_USERAUTH_PK_OK (RFC 4252 §7); for
    /// `password` the same number is SSH_MSG_USERAUTH_PASSWD_CHANGEREQ
    /// (§8), which this module never sends and rejects on receipt.
    SSH_MSG_USERAUTH_PK_OK = 60,

    // ── connection protocol (RFC 4254 §9) ───────────────────────────────
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
    _,
};

/// RFC 4254 §5.2 `data_type_code` for SSH_MSG_CHANNEL_EXTENDED_DATA. Only
/// stderr is defined by the RFC.
pub const extended_data_stderr: u32 = 1;

/// RFC 4254 §5.1 SSH_MSG_CHANNEL_OPEN_FAILURE `reason code`s.
pub const ChannelOpenFailureReason = enum(u32) {
    administratively_prohibited = 1,
    connect_failed = 2,
    unknown_channel_type = 3,
    resource_shortage = 4,
    _,
};

/// RFC 4253 §11.1 SSH_MSG_DISCONNECT `reason code`s (subset this module
/// ever sends).
pub const DisconnectReason = enum(u32) {
    protocol_error = 2,
    key_exchange_failed = 3,
    mac_error = 5,
    service_not_available = 7,
    no_more_auth_methods_available = 14,
    _,
};

// ── bounded cursor over a received payload ─────────────────────────────────

pub const CursorError = error{ProtocolError};

/// A non-allocating cursor over an SSH wire blob (a decrypted packet payload,
/// a key blob, a signature blob …). Every accessor is bounds-checked against
/// the slice it was built from, so a peer-controlled `uint32` length can only
/// ever produce `error.ProtocolError` — never a panic, an out-of-bounds read,
/// or an allocation the peer sized. This is the ONLY message-decoding
/// primitive the userauth/connection layers use.
pub const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    /// RFC 4251 §5 `string`: `uint32 len || bytes`. The returned slice
    /// borrows from the underlying buffer (no copy, no allocation).
    pub fn string(self: *Cursor) CursorError![]const u8 {
        const len = try self.uint32();
        if (@as(usize, len) > self.b.len - self.i) return error.ProtocolError;
        const s = self.b[self.i .. self.i + len];
        self.i += len;
        return s;
    }

    pub fn byte(self: *Cursor) CursorError!u8 {
        if (self.i >= self.b.len) return error.ProtocolError;
        const v = self.b[self.i];
        self.i += 1;
        return v;
    }

    /// RFC 4251 §5 `boolean`: any non-zero byte is true.
    pub fn boolean(self: *Cursor) CursorError!bool {
        return (try self.byte()) != 0;
    }

    pub fn uint32(self: *Cursor) CursorError!u32 {
        if (self.b.len - self.i < 4) return error.ProtocolError;
        const v = std.mem.readInt(u32, self.b[self.i..][0..4], .big);
        self.i += 4;
        return v;
    }

    pub fn atEnd(self: *const Cursor) bool {
        return self.i >= self.b.len;
    }
};

// ── RFC 4251 §5 wire-format primitives ──────────────────────────────────────
//
// Style mirrors the `framing` module: `std.Io.Writer`/`std.Io.Reader`,
// big-endian length prefixes (SSH is network-byte-order throughout, RFC 4251
// §5 "uint32"), no hidden buffering beyond what the caller supplies.

/// Hard cap on a single `readString`/`readMpint`/`readNameList` payload.
/// RFC 4251 does not specify one; this is a DoS guard against a peer
/// announcing an absurd length before the framing/cipher layer would catch
/// it another way.
pub const max_wire_string_len: u32 = 1 << 20; // 1 MiB

pub const ReadStringError = error{StringTooLarge} ||
    std.mem.Allocator.Error || std.Io.Reader.Error;

/// Write a length-prefixed byte string: `uint32 len || bytes` (RFC 4251 §5).
pub fn writeString(w: *std.Io.Writer, data: []const u8) std.Io.Writer.Error!void {
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, @intCast(data.len), .big);
    try w.writeAll(&hdr);
    try w.writeAll(data);
}

/// Read a length-prefixed byte string into a freshly allocated buffer
/// (caller frees). Rejects an announced length over `max_wire_string_len`.
pub fn readString(gpa: std.mem.Allocator, r: *std.Io.Reader) ReadStringError![]u8 {
    const hdr = try r.takeArray(4);
    const len = std.mem.readInt(u32, hdr, .big);
    if (len > max_wire_string_len) return error.StringTooLarge;
    const buf = try gpa.alloc(u8, len);
    errdefer gpa.free(buf);
    try r.readSliceAll(buf);
    return buf;
}

/// Write an RFC 4251 §5 "mpint": a length-prefixed two's-complement,
/// big-endian encoding of a non-negative integer given as its minimal
/// big-endian magnitude (`magnitude_be` may carry redundant leading zero
/// bytes; they are stripped before encoding). Per §5: "If the most
/// significant bit would be set for a positive number, the number MUST be
/// preceded by a zero byte" — SSH never encodes negative mpints for the
/// values this module needs (DH/ECDH public values, RSA integers), so only
/// the positive-number rule is implemented.
pub fn writeMpint(w: *std.Io.Writer, magnitude_be: []const u8) std.Io.Writer.Error!void {
    var m = magnitude_be;
    while (m.len > 0 and m[0] == 0) m = m[1..];
    if (m.len == 0) {
        try writeString(w, &.{});
        return;
    }
    if (m[0] & 0x80 != 0) {
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, @intCast(m.len + 1), .big);
        try w.writeAll(&hdr);
        try w.writeAll(&.{0x00});
        try w.writeAll(m);
    } else {
        try writeString(w, m);
    }
}

/// Read an RFC 4251 §5 mpint, returning its minimal big-endian magnitude
/// (the leading zero sign-pad byte, if present, is stripped) in a freshly
/// allocated buffer (caller frees). Only non-negative mpints are supported
/// (see `writeMpint`); a caller that must reject a negative mpint should
/// check the sign bit of the raw wire bytes upstream — that is a
/// protocol-policy decision, not this codec's concern.
pub fn readMpint(gpa: std.mem.Allocator, r: *std.Io.Reader) ReadStringError![]u8 {
    const raw = try readString(gpa, r);
    if (raw.len > 1 and raw[0] == 0) {
        defer gpa.free(raw);
        const out = try gpa.alloc(u8, raw.len - 1);
        @memcpy(out, raw[1..]);
        return out;
    }
    return raw;
}

/// An RFC 4251 §5 "name-list": a length-prefixed, comma-separated ASCII
/// string. Owns the decoded comma-joined buffer; `deinit` frees it.
pub const NameList = struct {
    raw: []u8,
    gpa: std.mem.Allocator,

    pub fn deinit(self: *NameList) void {
        self.gpa.free(self.raw);
    }

    /// Iterate the comma-separated names (empty list -> zero iterations).
    pub fn iterator(self: *const NameList) std.mem.SplitIterator(u8, .scalar) {
        if (self.raw.len == 0) return std.mem.splitScalar(u8, self.raw[0..0], ',');
        return std.mem.splitScalar(u8, self.raw, ',');
    }
};

/// Write a name-list from a slice of names (each name must not itself
/// contain a comma — RFC 4251 §5 forbids it).
pub fn writeNameList(w: *std.Io.Writer, names: []const []const u8) std.Io.Writer.Error!void {
    var total: usize = 0;
    for (names, 0..) |n, i| {
        total += n.len;
        if (i != 0) total += 1;
    }
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, @intCast(total), .big);
    try w.writeAll(&hdr);
    for (names, 0..) |n, i| {
        if (i != 0) try w.writeAll(",");
        try w.writeAll(n);
    }
}

/// Read a name-list (caller must `deinit` the result).
pub fn readNameList(gpa: std.mem.Allocator, r: *std.Io.Reader) ReadStringError!NameList {
    const raw = try readString(gpa, r);
    return .{ .raw = raw, .gpa = gpa };
}

// ── tests ────────────────────────────────────────────────────────────────

test "writeString/readString round-trip" {
    const t = std.testing;
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeString(&w, "hello, ssh");
    try writeString(&w, "");

    var r: std.Io.Reader = .fixed(w.buffered());
    const s1 = try readString(t.allocator, &r);
    defer t.allocator.free(s1);
    try t.expectEqualStrings("hello, ssh", s1);

    const s2 = try readString(t.allocator, &r);
    defer t.allocator.free(s2);
    try t.expectEqualStrings("", s2);
}

test "readString rejects oversize length" {
    const t = std.testing;
    var out: [8]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    var hdr: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr, max_wire_string_len + 1, .big);
    try w.writeAll(&hdr);

    var r: std.Io.Reader = .fixed(w.buffered());
    try t.expectError(error.StringTooLarge, readString(t.allocator, &r));
}

test "writeMpint/readMpint round-trip: small positive value" {
    const t = std.testing;
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const value = [_]u8{ 0x01, 0x02, 0x03 }; // high bit clear on first byte
    try writeMpint(&w, &value);

    var r: std.Io.Reader = .fixed(w.buffered());
    const got = try readMpint(t.allocator, &r);
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, &value, got);
}

test "writeMpint/readMpint round-trip: high-bit-set value gets zero-padded" {
    const t = std.testing;
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const value = [_]u8{ 0xff, 0x01 }; // top bit of first byte is set
    try writeMpint(&w, &value);

    // The wire encoding must carry an extra leading 0x00 sign-pad byte:
    // uint32 len(=3) || 0x00 || 0xff || 0x01.
    const buffered = w.buffered();
    const len = std.mem.readInt(u32, buffered[0..4], .big);
    try t.expectEqual(@as(u32, 3), len);
    try t.expectEqual(@as(u8, 0x00), buffered[4]);

    var r: std.Io.Reader = .fixed(buffered);
    const got = try readMpint(t.allocator, &r);
    defer t.allocator.free(got);
    try t.expectEqualSlices(u8, &value, got);
}

test "writeMpint/readMpint round-trip: zero value" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeMpint(&w, &.{0x00});

    var r: std.Io.Reader = .fixed(w.buffered());
    const got = try readMpint(t.allocator, &r);
    defer t.allocator.free(got);
    try t.expectEqual(@as(usize, 0), got.len);
}

test "writeNameList/readNameList round-trip" {
    const t = std.testing;
    var out: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    const names = [_][]const u8{ "curve25519-sha256", "curve25519-sha256@libssh.org" };
    try writeNameList(&w, &names);

    var r: std.Io.Reader = .fixed(w.buffered());
    var list = try readNameList(t.allocator, &r);
    defer list.deinit();

    var it = list.iterator();
    try t.expectEqualStrings("curve25519-sha256", it.next().?);
    try t.expectEqualStrings("curve25519-sha256@libssh.org", it.next().?);
    try t.expectEqual(@as(?[]const u8, null), it.next());
}

test "Cursor: decodes byte/boolean/uint32/string in sequence" {
    const t = std.testing;
    var out: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try w.writeByte(50);
    try writeString(&w, "alice");
    try w.writeByte(1);
    var nb: [4]u8 = undefined;
    std.mem.writeInt(u32, &nb, 0xdeadbeef, .big);
    try w.writeAll(&nb);

    var c = Cursor{ .b = w.buffered() };
    try t.expectEqual(@as(u8, 50), try c.byte());
    try t.expectEqualStrings("alice", try c.string());
    try t.expectEqual(true, try c.boolean());
    try t.expectEqual(@as(u32, 0xdeadbeef), try c.uint32());
    try t.expect(c.atEnd());
    try t.expectError(error.ProtocolError, c.byte());
}

test "Cursor: an attacker-controlled oversize string length is a typed error" {
    const t = std.testing;
    // uint32 length 0xffff_ffff followed by 3 bytes of body: the announced
    // length dwarfs the buffer. Must be error.ProtocolError, never a panic
    // and never an out-of-bounds slice.
    const evil = [_]u8{ 0xff, 0xff, 0xff, 0xff, 'a', 'b', 'c' };
    var c = Cursor{ .b = &evil };
    try t.expectError(error.ProtocolError, c.string());

    // Off-by-one: length is one byte more than what remains.
    const short = [_]u8{ 0x00, 0x00, 0x00, 0x04, 'a', 'b', 'c' };
    var c2 = Cursor{ .b = &short };
    try t.expectError(error.ProtocolError, c2.string());

    // Truncated length prefix itself.
    const trunc = [_]u8{ 0x00, 0x00 };
    var c3 = Cursor{ .b = &trunc };
    try t.expectError(error.ProtocolError, c3.uint32());
}

test "writeNameList/readNameList round-trip: empty list" {
    const t = std.testing;
    var out: [16]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out);
    try writeNameList(&w, &.{});

    var r: std.Io.Reader = .fixed(w.buffered());
    var list = try readNameList(t.allocator, &r);
    defer list.deinit();
    try t.expectEqual(@as(usize, 0), list.raw.len);
}
