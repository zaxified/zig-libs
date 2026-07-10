// SPDX-License-Identifier: MIT

//! SSH-2.0 message numbers (RFC 4253 §12) and the RFC 4251 §5 wire-format
//! primitives (byte string / mpint / name-list) all SSH messages are built
//! from. The wire helpers below are pure data-format code (no crypto, no
//! protocol state) so they are implemented for real, not stubbed — everything
//! that touches KEX/cipher/protocol *logic* lives in `transport.zig` instead
//! and stays `@panic("TODO(agent): ...")` until the crypto-implementation
//! pass.

const std = @import("std");

/// SSH message numbers (RFC 4253 §12 "Message Numbers" + RFC 8731 naming).
/// Transport-layer subset only — userauth (RFC 4252, numbers 50-79) and
/// connection-protocol/channel (RFC 4254, numbers 90-100+) message numbers
/// belong to the later parts of this module and are not listed here yet.
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
    _,
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
