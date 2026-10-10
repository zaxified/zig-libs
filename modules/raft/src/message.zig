// SPDX-License-Identifier: MIT

//! message — what `Node` (node.zig) exchanges with its peers: log entries that
//! carry the caller's bytes, the four Raft RPCs built on them, and their wire
//! codec. MECHANICAL — no consensus decision lives here.
//!
//! Why not `types.zig`'s codecs. Those carry a `u64` command per entry, which
//! is what the model-check needs and what a real state machine cannot use; a
//! deployment replicates arbitrary bytes. They also name the sender inside the
//! frame (`candidate_id`, `leader_id`), and that is a field a peer can lie in:
//! here the sender is whatever the TRANSPORT says it is (`decode`'s `from`),
//! because the transport is the only thing that can authenticate it. The tag
//! bytes are disjoint from `types.RpcTag` (0x10.. vs 0..3), so a frame of one
//! format can never decode as the other.
//!
//! ## Decoding fails closed
//!
//! Same rules as `types.zig`: every count and length is checked against the
//! REMAINING bytes before it is looped on, terms above `types.max_term` are
//! refused, and so is a frame with bytes left over. On top of that an
//! AppendEntries batch must be one an honest leader could have sent — entry
//! terms non-decreasing, none below `prev_log_term`, none above the message's
//! own term, and `prev_log_index + count` must not overflow — because
//! `leaderCommitIndex` walks a log whose terms it assumes are non-decreasing.

const std = @import("std");
const types = @import("types.zig");
const Allocator = std.mem.Allocator;

const Term = types.Term;
const LogIndex = types.LogIndex;
const NodeId = types.NodeId;
const EntryKind = types.EntryKind;
pub const DecodeError = types.DecodeError;

/// One log entry as the caller sees it: its position, the term of the leader
/// that created it, its kind and the caller's bytes. `data` is borrowed —
/// see the lifetime notes on `Node.Ready` and `decode`.
pub const Entry = struct {
    index: LogIndex,
    term: Term,
    kind: EntryKind = .command,
    data: []const u8 = "",
};

/// RequestVote (Figure 2). The candidate is the message's `from`.
pub const VoteReq = struct {
    term: Term,
    last_log_index: LogIndex,
    last_log_term: Term,
};

pub const VoteResp = struct {
    term: Term,
    granted: bool,
};

/// AppendEntries (Figure 2). The leader is the message's `from`; `entries`
/// are indices `prev_log_index + 1 ..`, contiguous.
pub const AppendReq = struct {
    term: Term,
    prev_log_index: LogIndex,
    prev_log_term: Term,
    leader_commit: LogIndex,
    entries: []const Entry,
};

pub const AppendResp = struct {
    term: Term,
    success: bool,
    /// On success: the highest index the follower VERIFIED against this
    /// request (`prev_log_index + entries.len`, the kernel's
    /// `AppendOutcome.match_index`), never its raw last index — see
    /// `types.AppendEntriesResp.match_index` for why. On failure: the
    /// follower's last log index, a HINT that lets the leader skip straight
    /// past a gap instead of walking `nextIndex` back one entry per round
    /// trip. A hint only ever lowers `nextIndex`, and every index the leader
    /// then sends is re-checked by the follower, so a wrong one costs round
    /// trips, never safety.
    index: LogIndex,
};

pub const Tag = enum(u8) {
    vote_req = 0x10,
    vote_resp = 0x11,
    append_req = 0x12,
    append_resp = 0x13,
};

pub const Body = union(Tag) {
    vote_req: VoteReq,
    vote_resp: VoteResp,
    append_req: AppendReq,
    append_resp: AppendResp,
};

pub const Message = struct {
    from: NodeId,
    to: NodeId,
    body: Body,

    pub const vote_req_len = 1 + 8 + 8 + 8;
    pub const vote_resp_len = 1 + 8 + 1;
    pub const append_resp_len = 1 + 8 + 1 + 8;
    pub const append_header_len = 1 + 8 + 8 + 8 + 8 + 4;
    /// Per entry: term(8) kind(1) data length(4), then the data.
    pub const entry_header_len = 8 + 1 + 4;

    /// Exact size of `encode`'s output.
    pub fn encodedLen(self: Message) usize {
        return switch (self.body) {
            .vote_req => vote_req_len,
            .vote_resp => vote_resp_len,
            .append_resp => append_resp_len,
            .append_req => |a| blk: {
                var n: usize = append_header_len;
                for (a.entries) |e| n += entry_header_len + e.data.len;
                break :blk n;
            },
        };
    }

    /// Write the frame into `buf` (at least `encodedLen()` bytes); returns the
    /// bytes written. `from`/`to` are not on the wire — they are the
    /// transport's business.
    pub fn encode(self: Message, buf: []u8) usize {
        std.debug.assert(buf.len >= self.encodedLen());
        buf[0] = @intFromEnum(std.meta.activeTag(self.body));
        switch (self.body) {
            .vote_req => |v| {
                std.mem.writeInt(u64, buf[1..9], v.term, .little);
                std.mem.writeInt(u64, buf[9..17], v.last_log_index, .little);
                std.mem.writeInt(u64, buf[17..25], v.last_log_term, .little);
                return vote_req_len;
            },
            .vote_resp => |v| {
                std.mem.writeInt(u64, buf[1..9], v.term, .little);
                buf[9] = @intFromBool(v.granted);
                return vote_resp_len;
            },
            .append_resp => |a| {
                std.mem.writeInt(u64, buf[1..9], a.term, .little);
                buf[9] = @intFromBool(a.success);
                std.mem.writeInt(u64, buf[10..18], a.index, .little);
                return append_resp_len;
            },
            .append_req => |a| {
                std.mem.writeInt(u64, buf[1..9], a.term, .little);
                std.mem.writeInt(u64, buf[9..17], a.prev_log_index, .little);
                std.mem.writeInt(u64, buf[17..25], a.prev_log_term, .little);
                std.mem.writeInt(u64, buf[25..33], a.leader_commit, .little);
                std.mem.writeInt(u32, buf[33..37], @intCast(a.entries.len), .little);
                var off: usize = append_header_len;
                for (a.entries) |e| {
                    std.mem.writeInt(u64, buf[off..][0..8], e.term, .little);
                    buf[off + 8] = @intFromEnum(e.kind);
                    std.mem.writeInt(u32, buf[off + 9 ..][0..4], @intCast(e.data.len), .little);
                    off += entry_header_len;
                    @memcpy(buf[off..][0..e.data.len], e.data);
                    off += e.data.len;
                }
                return off;
            },
        }
    }

    /// `encode` into a fresh gpa-owned slice.
    pub fn encodeAlloc(self: Message, gpa: Allocator) Allocator.Error![]u8 {
        const buf = try gpa.alloc(u8, self.encodedLen());
        _ = self.encode(buf);
        return buf;
    }

    /// Decode a frame that the transport says came from `from` and is meant
    /// for `to`. An AppendEntries' entries are written to `entries_out` and
    /// their `data` slices BORROW `bytes`: the message is valid only while
    /// both are. More entries than `entries_out` holds is `InvalidEncoding`.
    pub fn decode(bytes: []const u8, from: NodeId, to: NodeId, entries_out: []Entry) DecodeError!Message {
        if (bytes.len < 1) return error.Truncated;
        const tag = std.enums.fromInt(Tag, bytes[0]) orelse return error.InvalidEncoding;
        const body: Body = switch (tag) {
            .vote_req => blk: {
                try exactLen(bytes, vote_req_len);
                break :blk .{ .vote_req = .{
                    .term = try requestTermAt(bytes, 1),
                    .last_log_index = std.mem.readInt(u64, bytes[9..17], .little),
                    .last_log_term = try termAt(bytes, 17),
                } };
            },
            .vote_resp => blk: {
                try exactLen(bytes, vote_resp_len);
                break :blk .{ .vote_resp = .{
                    .term = try termAt(bytes, 1),
                    .granted = try boolAt(bytes, 9),
                } };
            },
            .append_resp => blk: {
                try exactLen(bytes, append_resp_len);
                break :blk .{ .append_resp = .{
                    .term = try termAt(bytes, 1),
                    .success = try boolAt(bytes, 9),
                    .index = std.mem.readInt(u64, bytes[10..18], .little),
                } };
            },
            .append_req => .{ .append_req = try decodeAppend(bytes, entries_out) },
        };
        return .{ .from = from, .to = to, .body = body };
    }

    fn decodeAppend(bytes: []const u8, entries_out: []Entry) DecodeError!AppendReq {
        if (bytes.len < append_header_len) return error.Truncated;
        const term = try requestTermAt(bytes, 1);
        const prev_index = std.mem.readInt(u64, bytes[9..17], .little);
        const prev_term = try termAt(bytes, 17);
        const commit = std.mem.readInt(u64, bytes[25..33], .little);
        const count = std.mem.readInt(u32, bytes[33..37], .little);
        if (count > entries_out.len) return error.InvalidEncoding;
        // Before the loop: the smallest entry is its header, so the bytes
        // present bound the count independently of `entries_out`.
        if ((bytes.len - append_header_len) / entry_header_len < count) return error.Truncated;
        if (prev_index > std.math.maxInt(LogIndex) - @as(LogIndex, count)) return error.InvalidEncoding;
        if (prev_term > term) return error.InvalidEncoding;
        // Index 0 is the only position with term 0; every real entry has a
        // term >= 1 (terms start at 1, and only a leader creates entries).
        if ((prev_index == 0) != (prev_term == 0)) return error.InvalidEncoding;

        var off: usize = append_header_len;
        var last_term = prev_term;
        for (entries_out[0..count], 0..) |*e, i| {
            if (bytes.len - off < entry_header_len) return error.Truncated;
            const et = std.mem.readInt(u64, bytes[off..][0..8], .little);
            // An honest leader's batch: non-decreasing terms, none older than
            // the entry it is appended after, none newer than its own term.
            if (et == 0 or et < last_term or et > term) return error.InvalidEncoding;
            last_term = et;
            const kind = std.enums.fromInt(EntryKind, bytes[off + 8]) orelse return error.InvalidEncoding;
            const len = std.mem.readInt(u32, bytes[off + 9 ..][0..4], .little);
            off += entry_header_len;
            if (bytes.len - off < len) return error.Truncated;
            e.* = .{ .index = prev_index + 1 + i, .term = et, .kind = kind, .data = bytes[off..][0..len] };
            off += len;
        }
        if (off != bytes.len) return error.InvalidEncoding;
        return .{
            .term = term,
            .prev_log_index = prev_index,
            .prev_log_term = prev_term,
            .leader_commit = commit,
            .entries = entries_out[0..count],
        };
    }
};

fn exactLen(bytes: []const u8, n: usize) DecodeError!void {
    if (bytes.len < n) return error.Truncated;
    if (bytes.len > n) return error.InvalidEncoding;
}

fn termAt(bytes: []const u8, off: usize) DecodeError!Term {
    const t = std.mem.readInt(u64, bytes[off..][0..8], .little);
    if (t > types.max_term) return error.InvalidEncoding;
    return t;
}

/// A request's term: a candidate or leader has always started a term, so 0
/// (the pre-election bootstrap term) is impossible on a request.
fn requestTermAt(bytes: []const u8, off: usize) DecodeError!Term {
    const t = try termAt(bytes, off);
    if (t == 0) return error.InvalidEncoding;
    return t;
}

fn boolAt(bytes: []const u8, off: usize) DecodeError!bool {
    return switch (bytes[off]) {
        0 => false,
        1 => true,
        else => error.InvalidEncoding,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn roundTrip(m: Message) !void {
    var buf: [512]u8 = undefined;
    const n = m.encode(&buf);
    try testing.expectEqual(m.encodedLen(), n);
    var scratch: [8]Entry = undefined;
    const d = try Message.decode(buf[0..n], m.from, m.to, &scratch);
    try testing.expectEqual(std.meta.activeTag(m.body), std.meta.activeTag(d.body));
    switch (m.body) {
        .vote_req => |v| try testing.expectEqual(v, d.body.vote_req),
        .vote_resp => |v| try testing.expectEqual(v, d.body.vote_resp),
        .append_resp => |v| try testing.expectEqual(v, d.body.append_resp),
        .append_req => |a| {
            const b = d.body.append_req;
            try testing.expectEqual(a.term, b.term);
            try testing.expectEqual(a.prev_log_index, b.prev_log_index);
            try testing.expectEqual(a.prev_log_term, b.prev_log_term);
            try testing.expectEqual(a.leader_commit, b.leader_commit);
            try testing.expectEqual(a.entries.len, b.entries.len);
            for (a.entries, b.entries) |x, y| {
                try testing.expectEqual(x.index, y.index);
                try testing.expectEqual(x.term, y.term);
                try testing.expectEqual(x.kind, y.kind);
                try testing.expectEqualSlices(u8, x.data, y.data);
            }
        },
    }
}

test "every message kind round-trips, entries with their bytes" {
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .vote_req = .{ .term = 4, .last_log_index = 9, .last_log_term = 3 } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .vote_resp = .{ .term = 4, .granted = true } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .append_resp = .{ .term = 4, .success = false, .index = 17 } } });
    const es = [_]Entry{
        .{ .index = 6, .term = 2, .kind = .noop },
        .{ .index = 7, .term = 3, .data = "set k v" },
        .{ .index = 8, .term = 3, .data = "" },
    };
    try roundTrip(.{ .from = 0, .to = 1, .body = .{ .append_req = .{
        .term = 3,
        .prev_log_index = 5,
        .prev_log_term = 2,
        .leader_commit = 5,
        .entries = &es,
    } } });
    // A heartbeat.
    try roundTrip(.{ .from = 0, .to = 1, .body = .{ .append_req = .{
        .term = 3,
        .prev_log_index = 8,
        .prev_log_term = 3,
        .leader_commit = 8,
        .entries = &.{},
    } } });
}

fn appendFrame(buf: []u8, term: Term, prev_index: LogIndex, prev_term: Term, entries: []const Entry) []u8 {
    const m: Message = .{ .from = 0, .to = 1, .body = .{ .append_req = .{
        .term = term,
        .prev_log_index = prev_index,
        .prev_log_term = prev_term,
        .leader_commit = 0,
        .entries = entries,
    } } };
    return buf[0..m.encode(buf)];
}

test "decode refuses a batch no honest leader sends" {
    var buf: [256]u8 = undefined;
    var scratch: [4]Entry = undefined;
    // Terms going backwards inside the batch.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 0, 0, &.{
        .{ .index = 1, .term = 3 }, .{ .index = 2, .term = 2 },
    }), 0, 1, &scratch));
    // An entry newer than the leader's own term.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 0, 0, &.{
        .{ .index = 1, .term = 6 },
    }), 0, 1, &scratch));
    // An entry older than the one it is appended after.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 3, 4, &.{
        .{ .index = 4, .term = 3 },
    }), 0, 1, &scratch));
    // Term 0 requests, a term-0 entry, a term-0 prev entry past index 0.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 0, 0, 0, &.{}), 0, 1, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 0, 0, &.{.{ .index = 1, .term = 0 }}), 0, 1, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 3, 0, &.{}), 0, 1, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 0, 2, &.{}), 0, 1, &scratch));
    // prev_log_term above the message term.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 3, 6, &.{}), 0, 1, &scratch));
    // An index range that would overflow.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, std.math.maxInt(u64), 1, &.{
        .{ .index = 0, .term = 5 },
    }), 0, 1, &scratch));
    // More entries than the caller's buffer.
    try testing.expectError(error.InvalidEncoding, Message.decode(appendFrame(&buf, 5, 0, 0, &.{
        .{ .index = 1, .term = 5 }, .{ .index = 2, .term = 5 },
    }), 0, 1, scratch[0..1]));
}

test "decode refuses lying lengths, trailing bytes, bad tags, bools and terms" {
    var buf: [256]u8 = undefined;
    var scratch: [4]Entry = undefined;
    const ok = appendFrame(&buf, 5, 0, 0, &.{.{ .index = 1, .term = 5, .data = "abc" }});
    _ = try Message.decode(ok, 0, 1, &scratch);

    // Data length one past the bytes present.
    var lying = buf;
    std.mem.writeInt(u32, lying[Message.append_header_len + 9 ..][0..4], 4, .little);
    try testing.expectError(error.Truncated, Message.decode(lying[0..ok.len], 0, 1, &scratch));
    // Entry count the bytes cannot back (checked before the loop).
    lying = buf;
    std.mem.writeInt(u32, lying[33..37], 0xFFFF_FFFF, .little);
    try testing.expectError(error.InvalidEncoding, Message.decode(lying[0..ok.len], 0, 1, &scratch));
    var big_scratch: [64]Entry = undefined;
    std.mem.writeInt(u32, lying[33..37], 64, .little);
    try testing.expectError(error.Truncated, Message.decode(lying[0..ok.len], 0, 1, &big_scratch));
    // One byte left over.
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0 .. ok.len + 1], 0, 1, &scratch));
    // Undefined tag; the old format's tags; an empty frame.
    try testing.expectError(error.InvalidEncoding, Message.decode(&.{0x14}, 0, 1, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(&.{0x02}, 0, 1, &scratch));
    try testing.expectError(error.Truncated, Message.decode(&.{}, 0, 1, &scratch));

    var vr: [Message.vote_resp_len]u8 = undefined;
    _ = (Message{ .from = 0, .to = 1, .body = .{ .vote_resp = .{ .term = 1, .granted = true } } }).encode(&vr);
    // A fixed-size message with a byte left over.
    var vr_long: [Message.vote_resp_len + 1]u8 = @splat(0);
    @memcpy(vr_long[0..Message.vote_resp_len], &vr);
    try testing.expectError(error.InvalidEncoding, Message.decode(&vr_long, 0, 1, &scratch));
    vr[9] = 2; // neither 0 nor 1
    try testing.expectError(error.InvalidEncoding, Message.decode(&vr, 0, 1, &scratch));
    vr[9] = 1;
    std.mem.writeInt(u64, vr[1..9], std.math.maxInt(u64), .little); // above max_term
    try testing.expectError(error.InvalidEncoding, Message.decode(&vr, 0, 1, &scratch));
}

// ── fuzz: the decoder is total over arbitrary bytes ─────────────────────────
//
// One `smith.slice` draw, so the corpus entry's own length header hands the
// frame over intact (see types.zig's fuzz section for what a split draw did).

const testkit = @import("testkit");
const seed = testkit.fuzz.seedHex;

const message_seeds = [_][]const u8{
    seed("10" ++ "0400000000000000" ++ "0900000000000000" ++ "0300000000000000"), // vote_req
    seed("11" ++ "0400000000000000" ++ "01"), // vote_resp
    seed("13" ++ "0400000000000000" ++ "00" ++ "1100000000000000"), // append_resp (reject + hint)
    seed("12" ++ "0300000000000000" ++ "0500000000000000" ++ "0200000000000000" ++ "0500000000000000" ++ "00000000"), // heartbeat
    seed("12" ++ "0300000000000000" ++ "0500000000000000" ++ "0200000000000000" ++ "0500000000000000" ++ "02000000" ++
        "0200000000000000" ++ "00" ++ "00000000" ++
        "0300000000000000" ++ "01" ++ "03000000" ++ "616263"), // two entries, one with data
    seed("12" ++ "0300000000000000" ++ "0500000000000000" ++ "0200000000000000" ++ "0500000000000000" ++ "ffffffff"), // ⭐ lying count
    seed("12" ++ "0300000000000000" ++ "0500000000000000" ++ "0200000000000000" ++ "0500000000000000" ++ "01000000" ++
        "0300000000000000" ++ "01" ++ "ffffffff" ++ "61"), // ⭐ lying data length
    seed("12" ++ "0300000000000000" ++ "0500000000000000" ++ "0200000000000000" ++ "0500000000000000" ++ "01000000" ++
        "0400000000000000" ++ "01" ++ "00000000"), // ⭐ entry newer than the message term
    seed("11" ++ "ffffffffffffffff" ++ "01"), // ⭐ term above max_term
    seed("02"), // an old-format tag
    seed(""),
};

const fz = @import("fuzz_test.zig");
const MessageMark = fz.Marker(enum { vote_req, vote_resp, append_resp, append_req, refused });

test "fuzz: Message.decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodeSmith, .{ .corpus = &message_seeds });
}

test "fuzz driver: RAFT_FUZZ (message)" {
    try fz.fuzz_driver.run(fuzzDecode, .{ .prefix = "RAFT_FUZZ", .name = "raft-message" });
}

test "fuzz harness: message, 500 seeds, reaches every outcome" {
    try MessageMark.reach(fuzzDecode, "raft-message", 500);
}

fn fuzzDecodeSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzDecode(std.testing.Smith, smith, testing.allocator);
}

fn fuzzDecode(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    const entries: []const []const u8 = &message_seeds;
    var buf: [160]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, entries);
    var scratch: [4]Entry = undefined;
    const m = Message.decode(buf[0..len], 0, 1, &scratch) catch {
        MessageMark.mark(.refused);
        return;
    };
    switch (m.body) {
        .vote_req => MessageMark.mark(.vote_req),
        .vote_resp => MessageMark.mark(.vote_resp),
        .append_resp => MessageMark.mark(.append_resp),
        .append_req => MessageMark.mark(.append_req),
    }
    // Accepted ⇒ re-encodes to the same bytes (the codec has one encoding).
    var out: [160]u8 = undefined;
    std.debug.assert(m.encodedLen() == len);
    const n = m.encode(&out);
    std.debug.assert(std.mem.eql(u8, out[0..n], buf[0..len]));
}

test "corpus: every message seed reaches the decoder, and what it accepted is pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var entries: usize = 0;
    for (message_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [160]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var scratch: [4]Entry = undefined;
        const m = Message.decode(buf[0..len], 0, 1, &scratch) catch continue;
        accepted += 1;
        if (m.body == .append_req) entries += m.body.append_req.entries.len;
    }
    try testing.expectEqual(message_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 5), accepted);
    // The number a heartbeat-only corpus cannot produce.
    try testing.expectEqual(@as(usize, 2), entries);
}
