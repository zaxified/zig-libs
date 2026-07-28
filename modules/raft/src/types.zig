// SPDX-License-Identifier: MIT

//! types — the mechanical wire layer: scalar aliases, the log-entry record, the
//! four Raft RPCs (RequestVote req/resp, AppendEntries req/resp) with their
//! byte codecs, and the persistent-state (de)serialization the durability model
//! rests on. Pure data + mechanical (de)serialization ONLY — no consensus-safety
//! logic lives here (that is `safety.zig`, the Fable core). Modeled on the RPC
//! message set of Ongaro & Ousterhout, "In Search of an Understandable Consensus
//! Algorithm" (extended version), Figure 2.
//!
//! ## Decoding fails closed
//!
//! Every `decode` / `deserialize` here returns `DecodeError!T` and validates
//! each field against the buffer BEFORE indexing it. A peer's RPC bytes are
//! untrusted input: in the sim they only ever come from this module's own
//! `encode`, but the codec is the module's outer boundary and a consensus
//! implementation that can be crashed by one malformed datagram has no
//! availability story at all. Concretely, before this was enforced:
//!
//!  - any short payload panicked on an out-of-bounds index (`decode(&[_]u8{0})`
//!    → "index out of bounds: index 9, len 1");
//!  - an undefined RPC tag or entry-kind byte panicked on `@enumFromInt`
//!    ("invalid enum value") — a validity fault, not a length fault;
//!  - `AppendEntriesReq.decode` took its entry count off the wire and guarded
//!    it with `std.debug.assert`, which is compiled out when safety is off:
//!    a 39-byte message declaring 65535 entries wrote past the caller's
//!    8-element stack array (measured: SIGSEGV in `ReleaseFast`). An
//!    out-of-bounds WRITE from two attacker-chosen bytes.
//!  - `PersistentState.deserialize` allocated its entry count off the wire
//!    with no check that the buffer could back it — the same unbounded-count
//!    class fixed in `threshold_ecdsa.PublicKeys.fromBytesAlloc`.
//!
//! A count or length field is therefore always checked against the REMAINING
//! buffer before it is looped on or allocated from, never after.

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

/// Why a buffer could not be decoded. Same vocabulary as the other wire
/// decoders in this library (`pbb.DecodeError`, `isis`'s TLV iterator): a
/// length problem is `Truncated`, a well-sized but impossible field is
/// `InvalidEncoding`.
pub const DecodeError = error{
    /// Fewer bytes than the fixed fields being read require, or a declared
    /// entry count the remaining bytes cannot back.
    Truncated,
    /// The bytes are long enough but a field is semantically impossible: an
    /// undefined RPC tag or entry-kind byte, or an entry count above
    /// `max_entries_per_msg`.
    InvalidEncoding,
};

/// Validate an entry-kind byte instead of `@enumFromInt`-ing it, which panics
/// with "invalid enum value" for anything outside the three defined kinds.
fn entryKindFrom(b: u8) DecodeError!EntryKind {
    return switch (b) {
        @intFromEnum(EntryKind.noop) => .noop,
        @intFromEnum(EntryKind.command) => .command,
        @intFromEnum(EntryKind.config) => .config,
        else => error.InvalidEncoding,
    };
}

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

    pub fn decode(b: []const u8) DecodeError!LogEntry {
        if (b.len < wire_len) return error.Truncated;
        return .{
            .term = std.mem.readInt(u64, b[0..8], .little),
            .kind = try entryKindFrom(b[8]),
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

/// Read the RPC tag off an untrusted payload. Rejects an empty buffer and any
/// byte outside the four defined tags — `@enumFromInt` on a raw wire byte
/// panics, and this is the FIRST thing done with every inbound datagram, so a
/// fail-closed decoder behind a panicking tag read would never be reached.
pub fn tagOf(payload: []const u8) DecodeError!RpcTag {
    if (payload.len < 1) return error.Truncated;
    return switch (payload[0]) {
        @intFromEnum(RpcTag.request_vote_req) => .request_vote_req,
        @intFromEnum(RpcTag.request_vote_resp) => .request_vote_resp,
        @intFromEnum(RpcTag.append_entries_req) => .append_entries_req,
        @intFromEnum(RpcTag.append_entries_resp) => .append_entries_resp,
        else => error.InvalidEncoding,
    };
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

    pub fn decode(p: []const u8) DecodeError!RequestVoteReq {
        if (p.len < wire_len) return error.Truncated;
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

    pub fn decode(p: []const u8) DecodeError!RequestVoteResp {
        if (p.len < wire_len) return error.Truncated;
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
    ///
    /// `count` is read off the wire and therefore bounded TWICE before the loop
    /// runs: once against `out`'s fixed capacity and once against the bytes
    /// actually present. This used to be a `std.debug.assert`, which is
    /// compiled out whenever safety is off — a 39-byte message declaring 65535
    /// entries then wrote ~1.5 MB past an 8-element stack array (measured:
    /// SIGSEGV under `ReleaseFast`). An assert is a statement about our own
    /// bugs; a wire field is someone else's input and needs a real check.
    pub fn decode(p: []const u8, out: *[max_entries_per_msg]LogEntry) DecodeError!AppendEntriesReq {
        if (p.len < header_len) return error.Truncated;
        const count = std.mem.readInt(u16, p[37..39], .little);
        if (count > max_entries_per_msg) return error.InvalidEncoding;
        // Only now is `count` known to fit `out`; check the payload can back it
        // before reading a single entry.
        if ((p.len - header_len) / LogEntry.wire_len < count) return error.Truncated;
        var off: usize = header_len;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            out[i] = try LogEntry.decode(p[off..][0..LogEntry.wire_len]);
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

    pub fn decode(p: []const u8) DecodeError!AppendEntriesResp {
        if (p.len < wire_len) return error.Truncated;
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
        const total = header_len + self.log.len * LogEntry.wire_len;
        const buf = try gpa.alloc(u8, total);
        std.mem.writeInt(u64, buf[0..8], self.current_term, .little);
        std.mem.writeInt(u32, buf[8..12], self.voted_for, .little);
        std.mem.writeInt(u32, buf[12..16], @intCast(self.log.len), .little);
        var off: usize = header_len;
        for (self.log) |e| {
            e.encode(buf[off..][0..LogEntry.wire_len]);
            off += LogEntry.wire_len;
        }
        return buf;
    }

    pub const header_len = 8 + 4 + 4; // term(8) + voted_for(4) + log count(4)

    /// Deserialize; the returned `log` slice is gpa-owned (free with
    /// `gpa.free(state.log)`).
    ///
    /// The stored image is the crash-recovery path, so it is not "our own
    /// bytes" in any meaningful sense — it is whatever survived the crash, or
    /// whatever is on the disk now. The entry count is validated against the
    /// remaining bytes BEFORE `alloc`, the same guard
    /// `threshold_ecdsa.PublicKeys.fromBytesAlloc` uses: without it a 16-byte
    /// image declaring 1_000_000 entries allocated 24 MB and then read far past
    /// the buffer (measured: "index out of bounds: index 33, len 16"), and
    /// `0xFFFFFFFF` demanded ~103 GB. With safety off that read would silently
    /// pull adjacent heap into the replicated log.
    pub fn deserialize(gpa: Allocator, bytes: []const u8) (Allocator.Error || DecodeError)!PersistentState {
        if (bytes.len < header_len) return error.Truncated;
        const term = std.mem.readInt(u64, bytes[0..8], .little);
        const voted = std.mem.readInt(u32, bytes[8..12], .little);
        const n = std.mem.readInt(u32, bytes[12..16], .little);
        if ((bytes.len - header_len) / LogEntry.wire_len < n) return error.Truncated;
        const log = try gpa.alloc(LogEntry, n);
        errdefer gpa.free(log);
        var off: usize = header_len;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            log[i] = try LogEntry.decode(bytes[off..][0..LogEntry.wire_len]);
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
    const d = try LogEntry.decode(&buf);
    try testing.expectEqual(e.term, d.term);
    try testing.expectEqual(e.kind, d.kind);
    try testing.expectEqual(e.command, d.command);
}

test "RequestVote req/resp round-trip + tag" {
    var rq: [RequestVoteReq.wire_len]u8 = undefined;
    const req = RequestVoteReq{ .term = 3, .candidate_id = 2, .last_log_index = 9, .last_log_term = 2 };
    req.encode(&rq);
    try testing.expectEqual(RpcTag.request_vote_req, try tagOf(&rq));
    const rd = try RequestVoteReq.decode(&rq);
    try testing.expectEqual(req.term, rd.term);
    try testing.expectEqual(req.candidate_id, rd.candidate_id);
    try testing.expectEqual(req.last_log_index, rd.last_log_index);
    try testing.expectEqual(req.last_log_term, rd.last_log_term);

    var rs: [RequestVoteResp.wire_len]u8 = undefined;
    const resp = RequestVoteResp{ .term = 3, .vote_granted = true };
    resp.encode(&rs);
    try testing.expectEqual(RpcTag.request_vote_resp, try tagOf(&rs));
    const sd = try RequestVoteResp.decode(&rs);
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
    try testing.expectEqual(RpcTag.append_entries_req, try tagOf(buf[0..n]));

    var scratch: [max_entries_per_msg]LogEntry = undefined;
    const d = try AppendEntriesReq.decode(buf[0..n], &scratch);
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
    const d = try AppendEntriesReq.decode(buf[0..n], &scratch);
    try testing.expectEqual(@as(usize, 0), d.entries.len);
}

test "AppendEntries resp round-trips" {
    var buf: [AppendEntriesResp.wire_len]u8 = undefined;
    const resp = AppendEntriesResp{ .term = 5, .success = true, .match_index = 12 };
    resp.encode(&buf);
    const d = try AppendEntriesResp.decode(&buf);
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

// ── rejection tests: every decoder fails closed ─────────────────────────────
//
// Each of these inputs previously PANICKED (out-of-bounds index, "invalid enum
// value", or — for `AppendEntriesReq` with safety off — an out-of-bounds write
// past the caller's 8-element array).

test "decoders reject every input too short for their fixed fields" {
    try testing.expectError(error.Truncated, tagOf(&[_]u8{}));
    try testing.expectError(error.Truncated, LogEntry.decode(&[_]u8{0} ** (LogEntry.wire_len - 1)));
    // The exact reproducer from the bug report.
    try testing.expectError(error.Truncated, RequestVoteReq.decode(&[_]u8{0}));
    try testing.expectError(error.Truncated, RequestVoteResp.decode(&[_]u8{0}));
    try testing.expectError(error.Truncated, AppendEntriesResp.decode(&[_]u8{0}));

    var scratch: [max_entries_per_msg]LogEntry = undefined;
    try testing.expectError(error.Truncated, AppendEntriesReq.decode(&[_]u8{0}, &scratch));

    // Every prefix of a valid encoding is rejected, none panics.
    var rq: [RequestVoteReq.wire_len]u8 = undefined;
    (RequestVoteReq{ .term = 1, .candidate_id = 0, .last_log_index = 0, .last_log_term = 0 }).encode(&rq);
    for (0..rq.len) |n| try testing.expectError(error.Truncated, RequestVoteReq.decode(rq[0..n]));
    _ = try RequestVoteReq.decode(&rq); // the full buffer still decodes
}

test "decoders reject undefined tag and entry-kind bytes" {
    for (4..256) |b| try testing.expectError(error.InvalidEncoding, tagOf(&[_]u8{@intCast(b)}));
    var e = [_]u8{0} ** LogEntry.wire_len;
    for (3..256) |b| {
        e[8] = @intCast(b);
        try testing.expectError(error.InvalidEncoding, LogEntry.decode(&e));
    }
    for (0..3) |b| {
        e[8] = @intCast(b);
        _ = try LogEntry.decode(&e); // the three defined kinds still decode
    }
}

test "AppendEntriesReq rejects a wire entry count the buffer cannot back" {
    var scratch: [max_entries_per_msg]LogEntry = undefined;

    // A bare header claiming 65535 entries. This is the out-of-bounds WRITE:
    // with safety off the old `std.debug.assert` vanished and the loop wrote
    // ~1.5 MB past `scratch` (measured: SIGSEGV under ReleaseFast).
    var p = [_]u8{0} ** AppendEntriesReq.header_len;
    std.mem.writeInt(u16, p[37..39], 0xFFFF, .little);
    try testing.expectError(error.InvalidEncoding, AppendEntriesReq.decode(&p, &scratch));

    // A count that fits `scratch` but that the payload does not carry: caught
    // as Truncated, before the loop reads anything.
    std.mem.writeInt(u16, p[37..39], max_entries_per_msg, .little);
    try testing.expectError(error.Truncated, AppendEntriesReq.decode(&p, &scratch));

    // One entry short of the declared count is still rejected.
    var q = [_]u8{0} ** (AppendEntriesReq.header_len + 2 * LogEntry.wire_len);
    std.mem.writeInt(u16, q[37..39], 3, .little);
    try testing.expectError(error.Truncated, AppendEntriesReq.decode(&q, &scratch));
    std.mem.writeInt(u16, q[37..39], 2, .little);
    try testing.expectEqual(@as(usize, 2), (try AppendEntriesReq.decode(&q, &scratch)).entries.len);
}

test "PersistentState.deserialize rejects a log count the image cannot back" {
    const gpa = testing.allocator;
    try testing.expectError(error.Truncated, PersistentState.deserialize(gpa, &[_]u8{0} ** 15));

    // 16 bytes claiming 1_000_000 entries: previously allocated 24 MB and then
    // read far past the buffer ("index out of bounds: index 33, len 16").
    var b = [_]u8{0} ** PersistentState.header_len;
    std.mem.writeInt(u32, b[12..16], 1_000_000, .little);
    try testing.expectError(error.Truncated, PersistentState.deserialize(gpa, &b));

    // 0xFFFFFFFF demanded ~103 GB; rejected before `alloc` is reached.
    std.mem.writeInt(u32, b[12..16], 0xFFFF_FFFF, .little);
    try testing.expectError(error.Truncated, PersistentState.deserialize(gpa, &b));

    // A truthful count still round-trips (the guard is not over-tight).
    std.mem.writeInt(u32, b[12..16], 0, .little);
    const st = try PersistentState.deserialize(gpa, &b);
    defer gpa.free(st.log);
    try testing.expectEqual(@as(usize, 0), st.log.len);
}

// ── fuzz: every decoder is total over arbitrary bytes ───────────────────────
//
// These could not have been landed before the fix: each one fails on its first
// input against the old decoders (verified by reverting the guards — see
// SPEC.md §"Malformed messages"). `smith.bytes` + a length draw covers both the
// short-input and the hostile-field-value cases, and the buffers are sized past
// `max_wire` so a well-formed header with a lying count is reachable.

test "fuzz: tagOf never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzTagOf, .{});
}

fn fuzzTagOf(_: void, smith: *std.testing.Smith) !void {
    var buf: [8]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = tagOf(buf[0..len]) catch return;
}

test "fuzz: LogEntry.decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzLogEntry, .{});
}

fn fuzzLogEntry(_: void, smith: *std.testing.Smith) !void {
    var buf: [LogEntry.wire_len * 2]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = LogEntry.decode(buf[0..len]) catch return;
}

test "fuzz: RequestVote req/resp decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzRequestVote, .{});
}

fn fuzzRequestVote(_: void, smith: *std.testing.Smith) !void {
    var buf: [RequestVoteReq.wire_len * 2]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    _ = RequestVoteReq.decode(buf[0..len]) catch {};
    _ = RequestVoteResp.decode(buf[0..len]) catch {};
}

test "fuzz: AppendEntries req/resp decode never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzAppendEntries, .{});
}

fn fuzzAppendEntries(_: void, smith: *std.testing.Smith) !void {
    // Wider than `max_wire` so a full header plus a lying entry count — the
    // out-of-bounds-write case — is inside the drawn range.
    var buf: [AppendEntriesReq.max_wire + 16]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);

    var scratch: [max_entries_per_msg]LogEntry = undefined;
    if (AppendEntriesReq.decode(buf[0..len], &scratch)) |req| {
        // A successful decode must have produced a slice that really is backed
        // by `scratch` — the property the old assert was standing in for.
        std.debug.assert(req.entries.len <= max_entries_per_msg);
        for (req.entries) |e| std.mem.doNotOptimizeAway(e.term);
    } else |_| {}
    _ = AppendEntriesResp.decode(buf[0..len]) catch {};
}

test "fuzz: PersistentState.deserialize never panics or over-allocates" {
    try testing.fuzz({}, fuzzPersistentState, .{});
}

fn fuzzPersistentState(_: void, smith: *std.testing.Smith) !void {
    var buf: [PersistentState.header_len + 4 * LogEntry.wire_len]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);

    // The testing allocator is the guard against the unbounded-count bug: a
    // count the buffer cannot back must be rejected BEFORE `alloc`, so this
    // never asks for more than `buf` could possibly describe.
    const st = PersistentState.deserialize(testing.allocator, buf[0..len]) catch return;
    defer testing.allocator.free(st.log);
    std.debug.assert(st.log.len * LogEntry.wire_len <= buf.len);
}
