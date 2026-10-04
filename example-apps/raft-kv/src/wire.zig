// SPDX-License-Identifier: MIT

//! Frames on the wire. One TCP connection carries exactly one frame.
//! Peer messages are ONE-WAY: the sender connects, writes one `.rpc` frame and
//! closes; responses travel as ordinary messages on a connection of their own,
//! so the receiver must be told who sent a frame. Client commands are
//! request/response: one request frame, one response frame.
//!
//! Length-prefixed frames come from the `framing` module; what this file adds
//! is the payload layout inside a frame:
//!
//!   peer frame   := Kind.rpc(1) ++ from(u32 LE) ++ raft.Message wire bytes
//!   client frame := kind(1) ++ body
//!
//! The raft message bytes are the `raft` module's OWN encoding
//! (`Message.encode`) — this app invents no consensus message format. A log
//! entry's payload is the module's `Entry.data`: the KV operation blob below.

const std = @import("std");
const framing = @import("framing");

pub const limits: framing.Limits = .{ .max_frame = 1 << 20 };

pub const max_key = 1024;
pub const max_value = 64 * 1024;

/// frame[0] — request kinds.
pub const Kind = enum(u8) {
    /// Peer message: from(u32 LE) ++ the raft module's wire bytes.
    rpc = 0x01,
    c_put = 0x10,
    c_get = 0x11,
    c_del = 0x12,
    /// Any node answers from its LOCAL applied state — explicitly not
    /// linearizable; exists so an observer (and the smoke test) can see what
    /// a follower has applied.
    c_dump = 0x13,
    _,
};

/// frame[0] — response kinds.
pub const Resp = enum(u8) {
    ok = 0x20,
    /// Not the leader; body carries the sender's best guess of who is
    /// (`no_vote` when it has none). The client retries there.
    redirect = 0x21,
    notfound = 0x22,
    err = 0x23,
    dump = 0x24,
    _,
};

// ── state-machine operations (the `Entry.data` of a log entry) ─────────

pub const Op = enum(u8) { set = 0, del = 1 };

/// op(1) | klen(u16) | key | value(rest)
pub fn encodeOp(gpa: std.mem.Allocator, op: Op, key: []const u8, value: []const u8) ![]u8 {
    const blob = try gpa.alloc(u8, 3 + key.len + value.len);
    blob[0] = @intFromEnum(op);
    std.mem.writeInt(u16, blob[1..3], @intCast(key.len), .little);
    @memcpy(blob[3..][0..key.len], key);
    @memcpy(blob[3 + key.len ..], value);
    return blob;
}

pub const DecodedOp = struct { op: Op, key: []const u8, value: []const u8 };

pub fn decodeOp(blob: []const u8) ?DecodedOp {
    if (blob.len < 3) return null;
    const op = std.enums.fromInt(Op, blob[0]) orelse return null;
    const klen = std.mem.readInt(u16, blob[1..3], .little);
    if (blob.len < 3 + @as(usize, klen)) return null;
    return .{ .op = op, .key = blob[3..][0..klen], .value = blob[3 + @as(usize, klen) ..] };
}

// ── frame I/O ───────────────────────────────────────────────────────────────

pub fn writeFrame(w: *std.Io.Writer, payload: []const u8) !void {
    try framing.writeFrame(w, payload, limits);
    try w.flush();
}

pub fn readFrame(r: *std.Io.Reader, buf: []u8) ![]u8 {
    return framing.readFrame(r, buf, limits);
}

// ── client command bodies ───────────────────────────────────────────────────

/// kind(1) | klen(u16) | key | value(rest) — value empty for get/del/dump.
pub fn encodeClient(gpa: std.mem.Allocator, kind: Kind, key: []const u8, value: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, 3 + key.len + value.len);
    out[0] = @intFromEnum(kind);
    std.mem.writeInt(u16, out[1..3], @intCast(key.len), .little);
    @memcpy(out[3..][0..key.len], key);
    @memcpy(out[3 + key.len ..], value);
    return out;
}

pub const ClientCmd = struct { kind: Kind, key: []const u8, value: []const u8 };

pub fn decodeClient(frame: []const u8) ?ClientCmd {
    if (frame.len < 3) return null;
    const kind = std.enums.fromInt(Kind, frame[0]) orelse return null;
    const klen = std.mem.readInt(u16, frame[1..3], .little);
    if (klen > max_key or frame.len < 3 + @as(usize, klen)) return null;
    const value = frame[3 + @as(usize, klen) ..];
    if (value.len > max_value) return null;
    return .{ .kind = kind, .key = frame[3..][0..klen], .value = value };
}
