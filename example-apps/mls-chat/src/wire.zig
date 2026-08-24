// SPDX-License-Identifier: MIT

//! The envelope between a client and the relay. **Not** part of MLS: RFC 9420
//! specifies no transport and says so deliberately, so every byte below is
//! this application's own invention and any other framing would do.
//!
//! Length-prefixed frames come from the `framing` module; what this file adds
//! is the one-byte kind and the fields inside a frame. The fields are binary
//! rather than JSON because every interesting payload here is an MLS wire
//! object — base64 inside JSON would cost a third more bytes to carry
//! ciphertext that nothing in the path can read anyway.
//!
//! **What the relay may look at**, and the reason this envelope exists in this
//! shape: the kind, the member name on a `publish`/`fetch`, and the group id.
//! Nothing else. The `msg` field of a `handshake`, `proposal`, `welcome` or
//! `app` frame is copied to the other subscribers byte for byte and is never
//! decoded — the relay holds no key that could decode it.

const std = @import("std");
const framing = @import("framing");

/// Generous for chat, and far below `framing`'s 1 MiB default: a Welcome
/// carrying a large ratchet tree is the biggest thing on this wire.
pub const max_frame: u32 = 256 * 1024;

pub const limits: framing.Limits = .{ .max_frame = max_frame };

pub const Kind = enum(u8) {
    /// client → relay: "here is my KeyPackage, under this name".
    publish = 1,
    /// client → relay: "give me the KeyPackage published under this name".
    fetch = 2,
    /// relay → client: the answer to `fetch`; empty `msg` means unknown.
    key_package = 3,
    /// client → relay: "subscribe me to this group's fan-out".
    join = 4,
    /// either direction: an `MLSMessage(PublicMessage)` carrying a Commit.
    handshake = 5,
    /// either direction: an `MLSMessage(Welcome)`.
    welcome = 6,
    /// either direction: `MLSMessage(PrivateMessage)` — an application
    /// message.
    app = 7,
    /// relay → client: human-readable status text. Never protocol-bearing.
    note = 8,
    /// either direction: an `MLSMessage(PublicMessage)` carrying a Proposal
    /// that no Commit covers yet. Separate from `handshake` because the
    /// receiver does a different thing with it — caches it — and a frame kind
    /// that means "one of two things, look inside to see which" is how a
    /// relay ends up parsing MLS.
    proposal = 9,

    fn from(byte: u8) ?Kind {
        return switch (byte) {
            1...9 => @enumFromInt(byte),
            else => null,
        };
    }
};

/// A decoded frame. The slices point INTO the caller's frame buffer, so they
/// live exactly as long as it does — the relay forwards without copying and
/// the client parses before reading the next frame.
pub const Frame = struct {
    kind: Kind,
    /// Member name on `publish`/`fetch`/`key_package`; empty otherwise.
    name: []const u8 = &.{},
    /// Group id on `join`/`handshake`/`welcome`/`app`; empty otherwise.
    group: []const u8 = &.{},
    /// The MLS bytes, or the note text.
    msg: []const u8 = &.{},
};

pub const Error = error{ MalformedFrame, UnknownKind };

fn putField(list: *std.ArrayList(u8), gpa: std.mem.Allocator, bytes: []const u8) !void {
    var len: [4]u8 = undefined;
    std.mem.writeInt(u32, &len, @intCast(bytes.len), .little);
    try list.appendSlice(gpa, &len);
    try list.appendSlice(gpa, bytes);
}

fn takeField(rest: *[]const u8) Error![]const u8 {
    if (rest.len < 4) return Error.MalformedFrame;
    const n = std.mem.readInt(u32, rest.*[0..4], .little);
    rest.* = rest.*[4..];
    if (rest.len < n) return Error.MalformedFrame;
    const out = rest.*[0..n];
    rest.* = rest.*[n..];
    return out;
}

/// Encodes one frame's payload (without the outer length prefix). Caller owns.
pub fn encodeAlloc(gpa: std.mem.Allocator, frame: Frame) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    try list.append(gpa, @intFromEnum(frame.kind));
    try putField(&list, gpa, frame.name);
    try putField(&list, gpa, frame.group);
    try putField(&list, gpa, frame.msg);
    return list.toOwnedSlice(gpa);
}

pub fn decode(payload: []const u8) Error!Frame {
    if (payload.len < 1) return Error.MalformedFrame;
    const kind = Kind.from(payload[0]) orelse return Error.UnknownKind;
    var rest = payload[1..];
    const name = try takeField(&rest);
    const group = try takeField(&rest);
    const msg = try takeField(&rest);
    // Trailing bytes are a malformed frame, not something to ignore: a
    // parser that skips what it does not understand is how two versions of a
    // protocol quietly disagree.
    if (rest.len != 0) return Error.MalformedFrame;
    return .{ .kind = kind, .name = name, .group = group, .msg = msg };
}

/// Encode and write one frame.
pub fn send(gpa: std.mem.Allocator, w: *std.Io.Writer, frame: Frame) !void {
    const payload = try encodeAlloc(gpa, frame);
    defer gpa.free(payload);
    try framing.writeFrame(w, payload, limits);
    try w.flush();
}

/// Read one frame into `buf` and decode it. The returned `Frame` borrows
/// `buf`, so the next call invalidates it.
pub fn recv(r: *std.Io.Reader, buf: []u8) !Frame {
    const payload = try framing.readFrame(r, buf, limits);
    return decode(payload);
}
