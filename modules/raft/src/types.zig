// SPDX-License-Identifier: MIT

//! types — the mechanical wire layer: scalar aliases, the log-entry record, the
//! four Raft RPCs (RequestVote req/resp, AppendEntries req/resp) with their
//! byte codecs, and the persistent-state (de)serialization the durability model
//! rests on. Pure data + mechanical (de)serialization ONLY — no consensus-safety
//! logic lives here (that is `safety.zig`, the Fable core). Modeled on the RPC
//! message set of Ongaro & Ousterhout, "In Search of an Understandable Consensus
//! Algorithm" (extended version), Figure 2.

const std = @import("std");
const netsim = @import("netsim");
const Allocator = std.mem.Allocator;

/// A monotonically-increasing election term (Raft's logical clock). 0 is the
/// pre-election bootstrap term; real terms start at 1.
pub const Term = u64;

/// A 1-based position in the replicated log. 0 is the sentinel "before the first
/// entry" (an empty log has `lastIndex() == 0`, `lastTerm() == 0`).
pub const LogIndex = u64;

/// A Raft server's identity — its `netsim` node id.
pub const NodeId = netsim.NodeId;

/// The opaque state-machine command a log entry carries. Real Raft replicates
/// arbitrary bytes; the sim uses a `u64` so that "two nodes applied DIFFERENT
/// commands at the same index" (a State Machine Safety violation) is detectable
/// by value equality with zero allocation.
pub const Command = u64;

/// A candidate's `voted_for` slot uses this sentinel on the wire / in the
/// persistent image to mean "did not vote this term" (there is no `?NodeId` on
/// the wire).
pub const no_vote: NodeId = 0xFFFF_FFFF;

/// The three log-entry kinds. `noop` is the empty entry a fresh leader appends
/// to commit prior-term entries indirectly (the Figure-8 mechanism); `config`
/// carries a membership change (design-only in Phase 1 — see SPEC.md §Membership).
pub const EntryKind = enum(u8) { noop = 0, command = 1, config = 2 };

/// One replicated log entry: the term in which the leader that created it was in
/// power, its kind, and its command payload.
pub const LogEntry = struct {
    term: Term,
    kind: EntryKind = .command,
    command: Command = 0,

    pub const wire_len = 17; // term(8) + kind(1) + command(8)

    pub fn encode(self: LogEntry, buf: *[wire_len]u8) void {
        std.mem.writeInt(u64, buf[0..8], self.term, .little);
        buf[8] = @intFromEnum(self.kind);
        std.mem.writeInt(u64, buf[9..17], self.command, .little);
    }

    pub fn decode(b: []const u8) LogEntry {
        return .{
            .term = std.mem.readInt(u64, b[0..8], .little),
            .kind = @enumFromInt(b[8]),
            .command = std.mem.readInt(u64, b[9..17], .little),
        };
    }
};

/// Upper bound on entries carried in a single AppendEntries in the sim — keeps
/// the wire buffer a fixed stack size. A real deployment streams unbounded
/// batches; the harness's small `until` never needs more.
pub const max_entries_per_msg = 8;

/// The message kinds this module puts on a `netsim` link, tagged by payload[0].
pub const RpcTag = enum(u8) {
    request_vote_req = 0,
    request_vote_resp = 1,
    append_entries_req = 2,
    append_entries_resp = 3,
};

pub fn tagOf(payload: []const u8) RpcTag {
    return @enumFromInt(payload[0]);
}

// ── RequestVote (Figure 2) ──────────────────────────────────────────────────

pub const RequestVoteReq = struct {
    term: Term,
    candidate_id: NodeId,
    last_log_index: LogIndex,
    last_log_term: Term,

    pub const wire_len = 1 + 8 + 4 + 8 + 8; // = 29

    pub fn encode(self: RequestVoteReq, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(RpcTag.request_vote_req);
        std.mem.writeInt(u64, buf[1..9], self.term, .little);
        std.mem.writeInt(u32, buf[9..13], self.candidate_id, .little);
        std.mem.writeInt(u64, buf[13..21], self.last_log_index, .little);
        std.mem.writeInt(u64, buf[21..29], self.last_log_term, .little);
    }

    pub fn decode(p: []const u8) RequestVoteReq {
        return .{
            .term = std.mem.readInt(u64, p[1..9], .little),
            .candidate_id = std.mem.readInt(u32, p[9..13], .little),
            .last_log_index = std.mem.readInt(u64, p[13..21], .little),
            .last_log_term = std.mem.readInt(u64, p[21..29], .little),
        };
    }
};

pub const RequestVoteResp = struct {
    term: Term,
    vote_granted: bool,

    pub const wire_len = 1 + 8 + 1; // = 10

    pub fn encode(self: RequestVoteResp, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(RpcTag.request_vote_resp);
        std.mem.writeInt(u64, buf[1..9], self.term, .little);
        buf[9] = @intFromBool(self.vote_granted);
    }

    pub fn decode(p: []const u8) RequestVoteResp {
        return .{
            .term = std.mem.readInt(u64, p[1..9], .little),
            .vote_granted = p[9] != 0,
        };
    }
};

// ── AppendEntries (Figure 2) ────────────────────────────────────────────────

pub const AppendEntriesReq = struct {
    term: Term,
    leader_id: NodeId,
    prev_log_index: LogIndex,
    prev_log_term: Term,
    entries: []const LogEntry,
    leader_commit: LogIndex,

    pub const header_len = 1 + 8 + 4 + 8 + 8 + 8 + 2; // = 39 (…count is a u16)
    pub const max_wire = header_len + max_entries_per_msg * LogEntry.wire_len;

    /// Encode into `buf`; returns the number of bytes written.
    pub fn encode(self: AppendEntriesReq, buf: *[max_wire]u8) usize {
        std.debug.assert(self.entries.len <= max_entries_per_msg);
        buf[0] = @intFromEnum(RpcTag.append_entries_req);
        std.mem.writeInt(u64, buf[1..9], self.term, .little);
        std.mem.writeInt(u32, buf[9..13], self.leader_id, .little);
        std.mem.writeInt(u64, buf[13..21], self.prev_log_index, .little);
        std.mem.writeInt(u64, buf[21..29], self.prev_log_term, .little);
        std.mem.writeInt(u64, buf[29..37], self.leader_commit, .little);
        std.mem.writeInt(u16, buf[37..39], @intCast(self.entries.len), .little);
        var off: usize = header_len;
        for (self.entries) |e| {
            e.encode(buf[off..][0..LogEntry.wire_len]);
            off += LogEntry.wire_len;
        }
        return off;
    }

    /// Decode, materializing the entries into caller-owned `out`. The returned
    /// value's `entries` slice borrows `out[0..count]`.
    pub fn decode(p: []const u8, out: *[max_entries_per_msg]LogEntry) AppendEntriesReq {
        const count = std.mem.readInt(u16, p[37..39], .little);
        std.debug.assert(count <= max_entries_per_msg);
        var off: usize = header_len;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            out[i] = LogEntry.decode(p[off..][0..LogEntry.wire_len]);
            off += LogEntry.wire_len;
        }
        return .{
            .term = std.mem.readInt(u64, p[1..9], .little),
            .leader_id = std.mem.readInt(u32, p[9..13], .little),
            .prev_log_index = std.mem.readInt(u64, p[13..21], .little),
            .prev_log_term = std.mem.readInt(u64, p[21..29], .little),
            .entries = out[0..count],
            .leader_commit = std.mem.readInt(u64, p[29..37], .little),
        };
    }
};

pub const AppendEntriesResp = struct {
    term: Term,
    success: bool,
    /// On success, the highest index the follower VERIFIED against the leader —
    /// `prevLogIndex + entries.len` of the request it is acking (the core's
    /// `AppendOutcome.match_index` verdict), NOT its raw last log index. The
    /// follower's log may extend past the verified region with a stale tail an
    /// RPC neither checked nor truncated; advertising that tail would let the
    /// leader count unverified entries toward a commit majority. The leader uses
    /// this to advance `matchIndex`/`nextIndex` without pairing replies to
    /// requests. 0 (meaningless) on failure.
    match_index: LogIndex,

    pub const wire_len = 1 + 8 + 1 + 8; // = 18

    pub fn encode(self: AppendEntriesResp, buf: *[wire_len]u8) void {
        buf[0] = @intFromEnum(RpcTag.append_entries_resp);
        std.mem.writeInt(u64, buf[1..9], self.term, .little);
        buf[9] = @intFromBool(self.success);
        std.mem.writeInt(u64, buf[10..18], self.match_index, .little);
    }

    pub fn decode(p: []const u8) AppendEntriesResp {
        return .{
            .term = std.mem.readInt(u64, p[1..9], .little),
            .success = p[9] != 0,
            .match_index = std.mem.readInt(u64, p[10..18], .little),
        };
    }
};

// ── persistent-state serialization (the durability model) ───────────────────
//
// Raft's crash-durability contract (Figure 2 "Persistent state"): `currentTerm`,
// `votedFor`, and `log[]` MUST survive a crash (be on stable storage before an
// RPC is answered); everything else (commitIndex, lastApplied, role,
// nextIndex[], matchIndex[]) is volatile and rebuilt on restart. `PersistentState`
// is exactly that durable triple, with a byte codec standing in for the disk
// write. In the sim, a node crash clears only volatile state; on restart the
// server reloads this image (see server.zig) — so the codec is what makes
// "restart re-enters with its term/vote/log intact" a real, tested property.

pub const PersistentState = struct {
    current_term: Term = 0,
    voted_for: NodeId = no_vote,
    /// Owned by the deserializer's arena on decode; borrowed on encode.
    log: []const LogEntry = &.{},

    /// Serialize to a fresh gpa-owned byte image. Caller frees the slice.
    pub fn serialize(self: PersistentState, gpa: Allocator) Allocator.Error![]u8 {
        const total = 8 + 4 + 4 + self.log.len * LogEntry.wire_len;
        const buf = try gpa.alloc(u8, total);
        std.mem.writeInt(u64, buf[0..8], self.current_term, .little);
        std.mem.writeInt(u32, buf[8..12], self.voted_for, .little);
        std.mem.writeInt(u32, buf[12..16], @intCast(self.log.len), .little);
        var off: usize = 16;
        for (self.log) |e| {
            e.encode(buf[off..][0..LogEntry.wire_len]);
            off += LogEntry.wire_len;
        }
        return buf;
    }

    /// Deserialize; the returned `log` slice is gpa-owned (free with
    /// `gpa.free(state.log)`).
    pub fn deserialize(gpa: Allocator, bytes: []const u8) Allocator.Error!PersistentState {
        const term = std.mem.readInt(u64, bytes[0..8], .little);
        const voted = std.mem.readInt(u32, bytes[8..12], .little);
        const n = std.mem.readInt(u32, bytes[12..16], .little);
        const log = try gpa.alloc(LogEntry, n);
        var off: usize = 16;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            log[i] = LogEntry.decode(bytes[off..][0..LogEntry.wire_len]);
            off += LogEntry.wire_len;
        }
        return .{ .current_term = term, .voted_for = voted, .log = log };
    }
};

// ── tests (all mechanical — no consensus logic touched) ─────────────────────

const testing = std.testing;

test "LogEntry round-trips through its wire encoding" {
    var buf: [LogEntry.wire_len]u8 = undefined;
    const e = LogEntry{ .term = 7, .kind = .config, .command = 0xDEAD_BEEF };
    e.encode(&buf);
    const d = LogEntry.decode(&buf);
    try testing.expectEqual(e.term, d.term);
    try testing.expectEqual(e.kind, d.kind);
    try testing.expectEqual(e.command, d.command);
}

test "RequestVote req/resp round-trip + tag" {
    var rq: [RequestVoteReq.wire_len]u8 = undefined;
    const req = RequestVoteReq{ .term = 3, .candidate_id = 2, .last_log_index = 9, .last_log_term = 2 };
    req.encode(&rq);
    try testing.expectEqual(RpcTag.request_vote_req, tagOf(&rq));
    const rd = RequestVoteReq.decode(&rq);
    try testing.expectEqual(req.term, rd.term);
    try testing.expectEqual(req.candidate_id, rd.candidate_id);
    try testing.expectEqual(req.last_log_index, rd.last_log_index);
    try testing.expectEqual(req.last_log_term, rd.last_log_term);

    var rs: [RequestVoteResp.wire_len]u8 = undefined;
    const resp = RequestVoteResp{ .term = 3, .vote_granted = true };
    resp.encode(&rs);
    try testing.expectEqual(RpcTag.request_vote_resp, tagOf(&rs));
    const sd = RequestVoteResp.decode(&rs);
    try testing.expectEqual(resp.term, sd.term);
    try testing.expectEqual(resp.vote_granted, sd.vote_granted);
}

test "AppendEntries req round-trips including a multi-entry batch" {
    const entries = [_]LogEntry{
        .{ .term = 2, .command = 100 },
        .{ .term = 2, .command = 101 },
        .{ .term = 3, .kind = .noop, .command = 0 },
    };
    const req = AppendEntriesReq{
        .term = 3,
        .leader_id = 1,
        .prev_log_index = 5,
        .prev_log_term = 2,
        .entries = &entries,
        .leader_commit = 4,
    };
    var buf: [AppendEntriesReq.max_wire]u8 = undefined;
    const n = req.encode(&buf);
    try testing.expectEqual(RpcTag.append_entries_req, tagOf(buf[0..n]));

    var scratch: [max_entries_per_msg]LogEntry = undefined;
    const d = AppendEntriesReq.decode(buf[0..n], &scratch);
    try testing.expectEqual(req.term, d.term);
    try testing.expectEqual(req.leader_id, d.leader_id);
    try testing.expectEqual(req.prev_log_index, d.prev_log_index);
    try testing.expectEqual(req.prev_log_term, d.prev_log_term);
    try testing.expectEqual(req.leader_commit, d.leader_commit);
    try testing.expectEqual(@as(usize, 3), d.entries.len);
    for (entries, d.entries) |a, b| {
        try testing.expectEqual(a.term, b.term);
        try testing.expectEqual(a.kind, b.kind);
        try testing.expectEqual(a.command, b.command);
    }
}

test "AppendEntries req round-trips an empty (heartbeat) batch" {
    const req = AppendEntriesReq{
        .term = 4,
        .leader_id = 0,
        .prev_log_index = 0,
        .prev_log_term = 0,
        .entries = &.{},
        .leader_commit = 0,
    };
    var buf: [AppendEntriesReq.max_wire]u8 = undefined;
    const n = req.encode(&buf);
    try testing.expectEqual(@as(usize, AppendEntriesReq.header_len), n);
    var scratch: [max_entries_per_msg]LogEntry = undefined;
    const d = AppendEntriesReq.decode(buf[0..n], &scratch);
    try testing.expectEqual(@as(usize, 0), d.entries.len);
}

test "AppendEntries resp round-trips" {
    var buf: [AppendEntriesResp.wire_len]u8 = undefined;
    const resp = AppendEntriesResp{ .term = 5, .success = true, .match_index = 12 };
    resp.encode(&buf);
    const d = AppendEntriesResp.decode(&buf);
    try testing.expectEqual(resp.term, d.term);
    try testing.expectEqual(resp.success, d.success);
    try testing.expectEqual(resp.match_index, d.match_index);
}

test "PersistentState survives a serialize/deserialize round-trip (the durability contract)" {
    const gpa = testing.allocator;
    const entries = [_]LogEntry{
        .{ .term = 1, .command = 42 },
        .{ .term = 2, .command = 43 },
    };
    const ps = PersistentState{ .current_term = 2, .voted_for = 3, .log = &entries };
    const bytes = try ps.serialize(gpa);
    defer gpa.free(bytes);

    const back = try PersistentState.deserialize(gpa, bytes);
    defer gpa.free(back.log);
    try testing.expectEqual(ps.current_term, back.current_term);
    try testing.expectEqual(ps.voted_for, back.voted_for);
    try testing.expectEqual(ps.log.len, back.log.len);
    for (entries, back.log) |a, b| {
        try testing.expectEqual(a.term, b.term);
        try testing.expectEqual(a.command, b.command);
    }
}

test "PersistentState with an empty log and no vote round-trips" {
    const gpa = testing.allocator;
    const ps = PersistentState{};
    const bytes = try ps.serialize(gpa);
    defer gpa.free(bytes);
    const back = try PersistentState.deserialize(gpa, bytes);
    defer gpa.free(back.log);
    try testing.expectEqual(@as(Term, 0), back.current_term);
    try testing.expectEqual(no_vote, back.voted_for);
    try testing.expectEqual(@as(usize, 0), back.log.len);
}
