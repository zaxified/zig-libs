// SPDX-License-Identifier: MIT

//! Frames on the wire. One TCP connection carries exactly one request frame
//! and one response frame — request/response, then close. That keeps every
//! thread's world small: the listener only ever sees REQUESTS (peer RPCs and
//! client commands), and each sender reads its own response on the connection
//! it opened.
//!
//! Length-prefixed frames come from the `framing` module; what this file adds
//! is the payload layout inside a frame:
//!
//!   frame := kind(1) ++ body
//!
//! Peer RPC bodies are the `raft` module's OWN wire encoding (`types.zig`'s
//! `encode`/`decode`, the same bytes the model-check exchanges in `netsim`) —
//! this app invents no consensus message format. The one thing the module's
//! fixed-width `Command = u64` cannot carry is an arbitrary KV operation, so
//! an AppendEntries body is followed by a PAYLOAD SECTION: one length-prefixed
//! blob per entry, and each entry's `command` is the truncated SHA-256 of its
//! blob (see `commandHash`). The consensus kernel agrees on (term, index,
//! command); the hash binds the blob to that agreement, and `apply` refuses a
//! blob whose hash does not match the committed command.

const std = @import("std");
const framing = @import("framing");
const raft = @import("raft");

pub const limits: framing.Limits = .{ .max_frame = 1 << 20 };

pub const max_key = 1024;
pub const max_value = 64 * 1024;

/// frame[0] — request kinds.
pub const Kind = enum(u8) {
    /// Peer RPC: body is the raft module's wire bytes (+ payload section for
    /// an AppendEntries request).
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

// ── state-machine operations (the blob a log entry's command binds) ─────────

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

/// The `Command` a log entry carries for this blob: the first 8 bytes of
/// SHA-256(blob). The kernel replicates and commits (term, index, command);
/// the blob rides alongside and is refused at `apply` if it does not hash to
/// the committed command — so what the state machines execute is bound to
/// what consensus agreed on, up to a hash collision.
pub fn commandHash(blob: []const u8) u64 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(blob, &digest, .{});
    return std.mem.readInt(u64, digest[0..8], .little);
}

// ── frame I/O ───────────────────────────────────────────────────────────────

pub fn writeFrame(w: *std.Io.Writer, payload: []const u8) !void {
    try framing.writeFrame(w, payload, limits);
    try w.flush();
}

pub fn readFrame(r: *std.Io.Reader, buf: []u8) ![]u8 {
    return framing.readFrame(r, buf, limits);
}

// ── AppendEntries request + payload section ─────────────────────────────────

/// raft wire bytes ++ { u32 len | blob }*entries.len, all in one frame body
/// after the `.rpc` kind byte.
pub fn encodeAppendWithPayloads(
    gpa: std.mem.Allocator,
    req: raft.AppendEntriesReq,
    blobs: []const []const u8,
) ![]u8 {
    std.debug.assert(req.entries.len == blobs.len);
    var rpc_buf: [raft.AppendEntriesReq.max_wire]u8 = undefined;
    const rpc_len = req.encode(&rpc_buf);
    var total: usize = 1 + rpc_len;
    for (blobs) |b| total += 4 + b.len;
    const out = try gpa.alloc(u8, total);
    out[0] = @intFromEnum(Kind.rpc);
    @memcpy(out[1..][0..rpc_len], rpc_buf[0..rpc_len]);
    var off: usize = 1 + rpc_len;
    for (blobs) |b| {
        std.mem.writeInt(u32, out[off..][0..4], @intCast(b.len), .little);
        off += 4;
        @memcpy(out[off..][0..b.len], b);
        off += b.len;
    }
    return out;
}

pub const DecodedAppend = struct {
    req: raft.AppendEntriesReq,
    /// Borrows the frame buffer, one blob per entry.
    blobs: [raft.max_entries_per_msg][]const u8,
};

/// `body` is the frame payload MINUS the kind byte. `entries_out` backs the
/// decoded request's entries slice.
pub fn decodeAppendWithPayloads(
    body: []const u8,
    entries_out: *[raft.max_entries_per_msg]raft.LogEntry,
) !DecodedAppend {
    const req = try raft.AppendEntriesReq.decode(body, entries_out);
    const rpc_len = raft.AppendEntriesReq.header_len + req.entries.len * raft.LogEntry.wire_len;
    var out: DecodedAppend = .{ .req = req, .blobs = undefined };
    var off: usize = rpc_len;
    for (0..req.entries.len) |i| {
        if (body.len < off + 4) return error.Truncated;
        const blen = std.mem.readInt(u32, body[off..][0..4], .little);
        off += 4;
        if (blen > max_value + max_key + 3) return error.InvalidEncoding;
        if (body.len < off + blen) return error.Truncated;
        out.blobs[i] = body[off..][0..blen];
        off += blen;
    }
    if (off != body.len) return error.InvalidEncoding;
    return out;
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
