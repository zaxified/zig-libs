// SPDX-License-Identifier: MIT

//! message — what `Node` (node.zig) exchanges with its peers: log entries that
//! carry the caller's bytes, the Raft RPCs built on them (Figure 2's two,
//! PreVote, TimeoutNow), and their wire codec. MECHANICAL — no consensus
//! decision lives here.
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
    /// The election was asked for by the leader (leadership transfer,
    /// `timeout_now`): receivers honour it inside a CheckQuorum lease
    /// (etcd/raft's `campaignTransfer` context, hashicorp/raft's
    /// `RequestVoteRequest.LeadershipTransfer`). Wire: an optional 26th byte
    /// (= 1), present only when set, so a frame without it is the plain 25-byte
    /// RequestVote; an older decoder refuses the longer
    /// frame. Never sent, and refused, on `pre_vote_req` (a transfer never
    /// pre-votes).
    transfer: bool = false,
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
    /// OPTIONAL conflict-term hint (§5.3's optimization; Raft thesis §5.3,
    /// etcd-style), only on a failure caused by a log mismatch, and only when
    /// `conflict_index != 0` (zero means "no hint": a legacy peer, a stale
    /// term, or a success). `conflict_term` is the term of the follower's
    /// entry at `prev_log_index` (0 when `prev_log_index` is past the
    /// follower's end); `conflict_index` is the first index of that term in
    /// the follower's log, or, past the end, one beyond its last index (so
    /// `>= 1`). The leader resumes after its own last entry of
    /// `conflict_term` if it has one, else at `conflict_index`: O(terms)
    /// round trips for a divergent tail. Wire: the 18-byte frame is extended
    /// to 34 bytes (`conflict_term`, `conflict_index`) only when a hint is
    /// present; the tag has no version byte, so the decoder accepts both
    /// lengths and an old peer's frames decode with no hint. An old decoder
    /// refuses the 34-byte frame (a mixed-version cluster must upgrade
    /// leaders first; a follower only sends it in reply to AppendEntries).
    conflict_term: Term = 0,
    conflict_index: LogIndex = 0,
};

pub const Tag = enum(u8) {
    vote_req = 0x10,
    vote_resp = 0x11,
    append_req = 0x12,
    append_resp = 0x13,
    /// PreVote (Raft thesis §9.6; etcd/raft `MsgPreVote` / `MsgPreVoteResp`).
    /// Added as new tags, the way this codec versions additions
    /// (no version byte): an older decoder refuses them as an undefined tag
    /// (dropped and counted), so `Config.pre_vote` must only be switched on
    /// once every server runs a decoder that knows them.
    pre_vote_req = 0x14,
    pre_vote_resp = 0x15,
    /// Leadership transfer (Raft thesis §3.10; etcd/raft `MsgTimeoutNow`,
    /// hashicorp/raft `TimeoutNow`). Added as a new tag, same
    /// caveat as PreVote: an older decoder drops it, so a transfer to a
    /// server that predates it is abandoned after one election timeout.
    timeout_now = 0x16,
    /// ReadIndex (Raft thesis §6.4; etcd/raft `MsgHeartbeat` with a context,
    /// `ReadOnlySafe`): the leader asks a peer to confirm it still follows it.
    /// New tags, same caveat as PreVote: an older decoder drops them, so a
    /// read against such a peer never reaches a quorum.
    read_req = 0x17,
    read_resp = 0x18,
    /// InstallSnapshot (Raft §7; etcd/raft `MsgSnap`, hashicorp/raft
    /// `InstallSnapshot`): the leader sends a follower whose next entry it has
    /// compacted away its latest snapshot, whole. The follower answers with
    /// an `append_resp`. New tag, same caveat as PreVote: an older decoder
    /// drops it, so a lagging server that predates it is never caught up
    /// once the leader has compacted past its log.
    snapshot = 0x19,
};

/// InstallSnapshot. The leader is the message's `from`.
pub const SnapshotMsg = struct {
    /// The leader's term.
    term: Term,
    /// The last index the snapshot covers, and that entry's term.
    index: LogIndex,
    snap_term: Term,
    /// The membership in force at `index` (`Membership.encode`).
    conf: []const u8,
    /// The caller's state-machine image at `index`.
    data: []const u8,
};

/// A cluster membership (Raft thesis §4; etcd/raft `ConfState`): who votes,
/// and who only replicates. Carried as the data of every `config` log entry
/// (the whole membership, not a delta, as hashicorp/raft's configuration
/// entries) and in every snapshot.
pub const Membership = struct {
    /// The voters (C_new during joint consensus). Never empty.
    voters: []const NodeId,
    /// Non-empty only during joint consensus (§6, thesis §4.3): C_old, whose
    /// majority is required as well as `voters`' one.
    voters_outgoing: []const NodeId = &.{},
    /// Non-voting members (etcd/raft learners, hashicorp/raft nonvoters):
    /// the leader replicates to them; they never vote or campaign, and never
    /// count toward a quorum. Disjoint from both voter lists.
    learners: []const NodeId = &.{},

    pub fn isJoint(self: Membership) bool {
        return self.voters_outgoing.len > 0;
    }

    pub fn encodedLen(self: Membership) usize {
        return 12 + 4 * (self.voters.len + self.voters_outgoing.len + self.learners.len);
    }

    /// Three `u32`-counted lists of `u32` ids (voters, outgoing voters,
    /// learners), each strictly ascending. `buf` holds at least
    /// `encodedLen()` bytes; returns the bytes written.
    pub fn encode(self: Membership, buf: []u8) usize {
        std.debug.assert(buf.len >= self.encodedLen());
        var off: usize = 0;
        for ([_][]const NodeId{ self.voters, self.voters_outgoing, self.learners }) |list| {
            std.mem.writeInt(u32, buf[off..][0..4], @intCast(list.len), .little);
            off += 4;
            for (list) |id| {
                std.mem.writeInt(u32, buf[off..][0..4], id, .little);
                off += 4;
            }
        }
        return off;
    }

    pub fn encodeAlloc(self: Membership, gpa: Allocator) Allocator.Error![]u8 {
        const buf = try gpa.alloc(u8, self.encodedLen());
        _ = self.encode(buf);
        return buf;
    }

    /// Decode into slices of `ids_out` (more ids than it holds is
    /// `InvalidEncoding`). Refused: a list not strictly ascending (so no
    /// duplicates and one encoding), no voters, the id `types.no_vote`, a
    /// learner that is also a voter, bytes left over.
    pub fn decode(bytes: []const u8, ids_out: []NodeId) DecodeError!Membership {
        var off: usize = 0;
        var used: usize = 0;
        var lists: [3][]const NodeId = undefined;
        for (&lists) |*list| {
            if (bytes.len - off < 4) return error.Truncated;
            const count = std.mem.readInt(u32, bytes[off..][0..4], .little);
            off += 4;
            if ((bytes.len - off) / 4 < count) return error.Truncated;
            if (count > ids_out.len - used) return error.InvalidEncoding;
            const out = ids_out[used..][0..count];
            for (out, 0..) |*id, i| {
                id.* = std.mem.readInt(u32, bytes[off..][0..4], .little);
                off += 4;
                if (id.* == types.no_vote) return error.InvalidEncoding;
                if (i > 0 and id.* <= out[i - 1]) return error.InvalidEncoding;
            }
            used += count;
            list.* = out;
        }
        if (off != bytes.len) return error.InvalidEncoding;
        const m: Membership = .{ .voters = lists[0], .voters_outgoing = lists[1], .learners = lists[2] };
        if (m.voters.len == 0) return error.InvalidEncoding;
        for (m.learners) |l| {
            if (std.mem.findScalar(NodeId, m.voters, l) != null) return error.InvalidEncoding;
            if (std.mem.findScalar(NodeId, m.voters_outgoing, l) != null) return error.InvalidEncoding;
        }
        return m;
    }
};

/// ReadIndex probe and its echo (same layout). `term` is the sender's term;
/// `seq` is the leader's probe number (1 and up), echoed unchanged.
pub const ReadProbe = struct {
    term: Term,
    seq: u64,
};

/// The leader tells a caught-up follower to start an election now.
pub const TimeoutNow = struct {
    /// The leader's term.
    term: Term,
};

pub const Body = union(Tag) {
    vote_req: VoteReq,
    vote_resp: VoteResp,
    append_req: AppendReq,
    append_resp: AppendResp,
    /// Same layout as `vote_req`. `term` is the term the sender WOULD
    /// campaign in (its own + 1); nobody adopts it.
    pre_vote_req: VoteReq,
    /// Same layout as `vote_resp`. A grant carries the request's term, a
    /// refusal the responder's own (etcd/raft does the same).
    pre_vote_resp: VoteResp,
    timeout_now: TimeoutNow,
    read_req: ReadProbe,
    read_resp: ReadProbe,
    snapshot: SnapshotMsg,
};

pub const Message = struct {
    from: NodeId,
    to: NodeId,
    body: Body,

    pub const vote_req_len = 1 + 8 + 8 + 8;
    /// `vote_req_len` plus the transfer flag byte.
    pub const vote_req_transfer_len = vote_req_len + 1;
    pub const timeout_now_len = 1 + 8;
    pub const read_probe_len = 1 + 8 + 8;
    /// InstallSnapshot without its two variable parts: tag, term, index,
    /// snapshot term, and the two `u32` lengths.
    pub const snapshot_header_len = 1 + 8 + 8 + 8 + 4 + 4;
    pub const vote_resp_len = 1 + 8 + 1;
    pub const append_resp_len = 1 + 8 + 1 + 8;
    /// `append_resp_len` plus `conflict_term` and `conflict_index`.
    pub const append_resp_hint_len = append_resp_len + 8 + 8;
    pub const append_header_len = 1 + 8 + 8 + 8 + 8 + 4;
    /// Per entry: term(8) kind(1) data length(4), then the data.
    pub const entry_header_len = 8 + 1 + 4;

    /// Exact size of `encode`'s output.
    pub fn encodedLen(self: Message) usize {
        return switch (self.body) {
            .vote_req => |v| if (v.transfer) vote_req_transfer_len else vote_req_len,
            .pre_vote_req => vote_req_len,
            .vote_resp, .pre_vote_resp => vote_resp_len,
            .timeout_now => timeout_now_len,
            .read_req, .read_resp => read_probe_len,
            .snapshot => |sn| snapshot_header_len + sn.conf.len + sn.data.len,
            .append_resp => |a| if (a.conflict_index != 0) append_resp_hint_len else append_resp_len,
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
        buf[0] = @backingInt(std.meta.activeTag(self.body));
        switch (self.body) {
            .vote_req, .pre_vote_req => |v| {
                std.mem.writeInt(u64, buf[1..9], v.term, .little);
                std.mem.writeInt(u64, buf[9..17], v.last_log_index, .little);
                std.mem.writeInt(u64, buf[17..25], v.last_log_term, .little);
                if (self.body == .pre_vote_req or !v.transfer) return vote_req_len;
                buf[vote_req_len] = 1;
                return vote_req_transfer_len;
            },
            .timeout_now => |t| {
                std.mem.writeInt(u64, buf[1..9], t.term, .little);
                return timeout_now_len;
            },
            .read_req, .read_resp => |r| {
                std.mem.writeInt(u64, buf[1..9], r.term, .little);
                std.mem.writeInt(u64, buf[9..17], r.seq, .little);
                return read_probe_len;
            },
            .vote_resp, .pre_vote_resp => |v| {
                std.mem.writeInt(u64, buf[1..9], v.term, .little);
                buf[9] = @intFromBool(v.granted);
                return vote_resp_len;
            },
            .snapshot => |sn| {
                std.mem.writeInt(u64, buf[1..9], sn.term, .little);
                std.mem.writeInt(u64, buf[9..17], sn.index, .little);
                std.mem.writeInt(u64, buf[17..25], sn.snap_term, .little);
                std.mem.writeInt(u32, buf[25..29], @intCast(sn.conf.len), .little);
                @memcpy(buf[29..][0..sn.conf.len], sn.conf);
                var off: usize = 29 + sn.conf.len;
                std.mem.writeInt(u32, buf[off..][0..4], @intCast(sn.data.len), .little);
                off += 4;
                @memcpy(buf[off..][0..sn.data.len], sn.data);
                return off + sn.data.len;
            },
            .append_resp => |a| {
                std.mem.writeInt(u64, buf[1..9], a.term, .little);
                buf[9] = @intFromBool(a.success);
                std.mem.writeInt(u64, buf[10..18], a.index, .little);
                if (a.conflict_index == 0) return append_resp_len;
                std.mem.writeInt(u64, buf[18..26], a.conflict_term, .little);
                std.mem.writeInt(u64, buf[26..34], a.conflict_index, .little);
                return append_resp_hint_len;
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
                    buf[off + 8] = @backingInt(e.kind);
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
            .vote_req, .pre_vote_req => blk: {
                // The transfer flag: a 26th byte, only on vote_req, only 1
                // (one encoding per message — a 0 byte would be a second
                // spelling of the 25-byte frame).
                const transfer = tag == .vote_req and bytes.len == vote_req_transfer_len;
                if (transfer) {
                    if (bytes[vote_req_len] != 1) return error.InvalidEncoding;
                } else try exactLen(bytes, vote_req_len);
                const v: VoteReq = .{
                    .term = try requestTermAt(bytes, 1),
                    .last_log_index = std.mem.readInt(u64, bytes[9..17], .little),
                    .last_log_term = try termAt(bytes, 17),
                    .transfer = transfer,
                };
                break :blk if (tag == .vote_req) .{ .vote_req = v } else .{ .pre_vote_req = v };
            },
            .vote_resp, .pre_vote_resp => blk: {
                try exactLen(bytes, vote_resp_len);
                const v: VoteResp = .{
                    .term = try termAt(bytes, 1),
                    .granted = try boolAt(bytes, 9),
                };
                break :blk if (tag == .vote_resp) .{ .vote_resp = v } else .{ .pre_vote_resp = v };
            },
            .append_resp => blk: {
                if (bytes.len < append_resp_len) return error.Truncated;
                var r: AppendResp = .{
                    .term = try termAt(bytes, 1),
                    .success = try boolAt(bytes, 9),
                    .index = std.mem.readInt(u64, bytes[10..18], .little),
                };
                if (bytes.len != append_resp_len) {
                    // The hinted form: only a rejection carries one, and its
                    // index is >= 1 (the first index of a term / one past the end).
                    if (bytes.len < append_resp_hint_len) return error.Truncated;
                    try exactLen(bytes, append_resp_hint_len);
                    r.conflict_term = try termAt(bytes, 18);
                    r.conflict_index = std.mem.readInt(u64, bytes[26..34], .little);
                    if (r.success or r.conflict_index == 0) return error.InvalidEncoding;
                }
                break :blk .{ .append_resp = r };
            },
            .append_req => .{ .append_req = try decodeAppend(bytes, entries_out) },
            .snapshot => .{ .snapshot = try decodeSnapshot(bytes) },
            .timeout_now => blk: {
                try exactLen(bytes, timeout_now_len);
                break :blk .{ .timeout_now = .{ .term = try requestTermAt(bytes, 1) } };
            },
            .read_req, .read_resp => blk: {
                try exactLen(bytes, read_probe_len);
                // Probes are numbered from 1; the leader's term is >= 1, and a
                // reply may carry a lower one (a stale leader is told its own is old).
                const r: ReadProbe = .{
                    .term = if (tag == .read_req) try requestTermAt(bytes, 1) else try termAt(bytes, 1),
                    .seq = std.mem.readInt(u64, bytes[9..17], .little),
                };
                if (r.seq == 0) return error.InvalidEncoding;
                break :blk if (tag == .read_req) .{ .read_req = r } else .{ .read_resp = r };
            },
        };
        return .{ .from = from, .to = to, .body = body };
    }

    /// `conf` and `data` BORROW `bytes`. `conf` must be a well-formed
    /// `Membership` (checked here; the receiver checks its ids against its
    /// own id bound).
    fn decodeSnapshot(bytes: []const u8) DecodeError!SnapshotMsg {
        if (bytes.len < snapshot_header_len) return error.Truncated;
        const term = try requestTermAt(bytes, 1);
        const index = std.mem.readInt(u64, bytes[9..17], .little);
        const snap_term = try termAt(bytes, 17);
        // A snapshot covers at least one entry, of a real term no newer
        // than the leader's.
        if (index == 0 or snap_term == 0 or snap_term > term) return error.InvalidEncoding;
        const conf_len = std.mem.readInt(u32, bytes[25..29], .little);
        if (bytes.len - snapshot_header_len < conf_len) return error.Truncated;
        const conf = bytes[29..][0..conf_len];
        var off: usize = 29 + conf_len;
        const data_len = std.mem.readInt(u32, bytes[off..][0..4], .little);
        off += 4;
        if (bytes.len - off < data_len) return error.Truncated;
        if (bytes.len - off != data_len) return error.InvalidEncoding;
        var ids: [max_conf_ids]NodeId = undefined;
        _ = try Membership.decode(conf, &ids);
        return .{ .term = term, .index = index, .snap_term = snap_term, .conf = conf, .data = bytes[off..] };
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

/// The most ids one encoded `Membership` may name (all three lists):
/// what `decodeSnapshot` validates against without an allocator.
pub const max_conf_ids = 2048;

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
        .pre_vote_req => |v| try testing.expectEqual(v, d.body.pre_vote_req),
        .pre_vote_resp => |v| try testing.expectEqual(v, d.body.pre_vote_resp),
        .timeout_now => |v| try testing.expectEqual(v, d.body.timeout_now),
        .read_req => |v| try testing.expectEqual(v, d.body.read_req),
        .read_resp => |v| try testing.expectEqual(v, d.body.read_resp),
        .snapshot => |v| {
            const b = d.body.snapshot;
            try testing.expectEqual(v.term, b.term);
            try testing.expectEqual(v.index, b.index);
            try testing.expectEqual(v.snap_term, b.snap_term);
            try testing.expectEqualSlices(u8, v.conf, b.conf);
            try testing.expectEqualSlices(u8, v.data, b.data);
        },
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
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .pre_vote_req = .{ .term = 5, .last_log_index = 9, .last_log_term = 3 } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .pre_vote_resp = .{ .term = 5, .granted = false } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .vote_req = .{ .term = 4, .last_log_index = 9, .last_log_term = 3, .transfer = true } } });
    try roundTrip(.{ .from = 0, .to = 2, .body = .{ .timeout_now = .{ .term = 7 } } });
    try roundTrip(.{ .from = 0, .to = 2, .body = .{ .read_req = .{ .term = 7, .seq = 12 } } });
    try roundTrip(.{ .from = 2, .to = 0, .body = .{ .read_resp = .{ .term = 7, .seq = 12 } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .append_resp = .{ .term = 4, .success = false, .index = 17 } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .append_resp = .{ .term = 4, .success = false, .index = 17, .conflict_term = 3, .conflict_index = 9 } } });
    try roundTrip(.{ .from = 1, .to = 2, .body = .{ .append_resp = .{ .term = 4, .success = false, .index = 17, .conflict_term = 0, .conflict_index = 18 } } });
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
    try testing.expectError(error.InvalidEncoding, Message.decode(&.{0x1a}, 0, 1, &scratch));
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
    seed("14" ++ "0500000000000000" ++ "0900000000000000" ++ "0300000000000000"), // pre_vote_req
    seed("15" ++ "0500000000000000" ++ "00"), // pre_vote_resp
    seed("10" ++ "0500000000000000" ++ "0900000000000000" ++ "0300000000000000" ++ "01"), // vote_req, transfer
    seed("16" ++ "0700000000000000"), // timeout_now
    seed("17" ++ "0700000000000000" ++ "0c00000000000000"), // read_req
    seed("18" ++ "0700000000000000" ++ "0c00000000000000"), // read_resp
    seed("19" ++ "0700000000000000" ++ "0900000000000000" ++ "0600000000000000" ++ "14000000" ++
        "02000000" ++ "00000000" ++ "01000000" ++ "00000000" ++ "00000000" ++ "03000000" ++ "616263"), // snapshot, voters {0,1}
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
const MessageMark = fz.Marker(enum { vote_req, vote_resp, append_resp, append_req, pre_vote_req, pre_vote_resp, timeout_now, read_req, read_resp, snapshot, refused });

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
        .pre_vote_req => MessageMark.mark(.pre_vote_req),
        .pre_vote_resp => MessageMark.mark(.pre_vote_resp),
        .timeout_now => MessageMark.mark(.timeout_now),
        .read_req => MessageMark.mark(.read_req),
        .read_resp => MessageMark.mark(.read_resp),
        .snapshot => MessageMark.mark(.snapshot),
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
    try testing.expectEqual(@as(usize, 12), accepted);
    // The number a heartbeat-only corpus cannot produce.
    try testing.expectEqual(@as(usize, 2), entries);
}

test "append_resp conflict hint: optional on the wire, legacy frames still decode, bad ones refused" {
    var scratch: [1]Entry = undefined;
    var buf: [40]u8 = undefined;
    // No hint: the 18-byte legacy frame, decoding to a zero hint.
    const plain: Message = .{ .from = 1, .to = 2, .body = .{ .append_resp = .{ .term = 4, .success = false, .index = 17 } } };
    try testing.expectEqual(Message.append_resp_len, plain.encode(&buf));
    const d = try Message.decode(buf[0..Message.append_resp_len], 1, 2, &scratch);
    try testing.expectEqual(@as(LogIndex, 0), d.body.append_resp.conflict_index);
    // Hinted: 34 bytes.
    const hinted: Message = .{ .from = 1, .to = 2, .body = .{ .append_resp = .{ .term = 4, .success = false, .index = 17, .conflict_term = 2, .conflict_index = 5 } } };
    try testing.expectEqual(Message.append_resp_hint_len, hinted.encode(&buf));
    // In-between, too long, a success with a hint, a zero conflict index, a term above max.
    try testing.expectError(error.Truncated, Message.decode(buf[0..30], 1, 2, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0..35], 1, 2, &scratch));
    var bad = buf;
    bad[9] = 1;
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..34], 1, 2, &scratch));
    bad = buf;
    @memset(bad[26..34], 0);
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..34], 1, 2, &scratch));
    bad = buf;
    std.mem.writeInt(u64, bad[18..26], types.max_term + 1, .little);
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..34], 1, 2, &scratch));
}

test "ReadIndex probes on the wire: new tags, 17 bytes, numbered from 1, fail closed" {
    var scratch: [1]Entry = undefined;
    var buf: [24]u8 = undefined;
    const req: Message = .{ .from = 0, .to = 1, .body = .{ .read_req = .{ .term = 3, .seq = 9 } } };
    try testing.expectEqual(Message.read_probe_len, req.encode(&buf));
    try testing.expectEqual(@as(u8, 0x17), buf[0]);
    const d = try Message.decode(buf[0..Message.read_probe_len], 0, 1, &scratch);
    try testing.expectEqual(@as(u64, 9), d.body.read_req.seq);
    try testing.expectError(error.Truncated, Message.decode(buf[0 .. Message.read_probe_len - 1], 0, 1, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0 .. Message.read_probe_len + 1], 0, 1, &scratch));
    var bad = buf;
    @memset(bad[9..17], 0); // seq 0
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.read_probe_len], 0, 1, &scratch));
    bad = buf;
    @memset(bad[1..9], 0); // a request's term is never 0 ...
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.read_probe_len], 0, 1, &scratch));
    bad[0] = 0x18; // ... a reply's may be (it echoes a stale leader's own term back)
    try testing.expectEqual(@as(Term, 0), (try Message.decode(bad[0..Message.read_probe_len], 1, 0, &scratch)).body.read_resp.term);
    std.mem.writeInt(u64, bad[1..9], types.max_term + 1, .little);
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.read_probe_len], 1, 0, &scratch));
}

test "leadership transfer on the wire: the vote flag is an optional byte, timeout_now a new tag, both fail closed" {
    var scratch: [1]Entry = undefined;
    var buf: [32]u8 = undefined;
    // Without the flag: the 25-byte RequestVote of before, decoding unflagged.
    const plain: Message = .{ .from = 1, .to = 2, .body = .{ .vote_req = .{ .term = 4, .last_log_index = 9, .last_log_term = 3 } } };
    try testing.expectEqual(Message.vote_req_len, plain.encode(&buf));
    try testing.expect(!(try Message.decode(buf[0..Message.vote_req_len], 1, 2, &scratch)).body.vote_req.transfer);
    // Flagged: 26 bytes, the last one 1.
    const flagged: Message = .{ .from = 1, .to = 2, .body = .{ .vote_req = .{ .term = 4, .last_log_index = 9, .last_log_term = 3, .transfer = true } } };
    try testing.expectEqual(Message.vote_req_transfer_len, flagged.encode(&buf));
    try testing.expectEqual(@as(u8, 1), buf[Message.vote_req_len]);
    try testing.expect((try Message.decode(buf[0..Message.vote_req_transfer_len], 1, 2, &scratch)).body.vote_req.transfer);
    // A flag byte other than 1, a 27-byte frame, the flag on a pre-vote: refused.
    var bad = buf;
    bad[Message.vote_req_len] = 0;
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.vote_req_transfer_len], 1, 2, &scratch));
    bad[Message.vote_req_len] = 2;
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.vote_req_transfer_len], 1, 2, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0 .. Message.vote_req_transfer_len + 1], 1, 2, &scratch));
    bad = buf;
    bad[0] = @backingInt(Tag.pre_vote_req);
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.vote_req_transfer_len], 1, 2, &scratch));
    // A pre-vote never carries it, even if the struct says so.
    const pv: Message = .{ .from = 1, .to = 2, .body = .{ .pre_vote_req = .{ .term = 4, .last_log_index = 9, .last_log_term = 3, .transfer = true } } };
    try testing.expectEqual(Message.vote_req_len, pv.encodedLen());
    try testing.expectEqual(Message.vote_req_len, pv.encode(&buf));

    // timeout_now: tag 0x16 and the leader's term, nothing else; term 0 and
    // above max_term refused, as on every request.
    const tn: Message = .{ .from = 0, .to = 1, .body = .{ .timeout_now = .{ .term = 3 } } };
    try testing.expectEqual(Message.timeout_now_len, tn.encode(&buf));
    try testing.expectEqual(@as(u8, 0x16), buf[0]);
    try testing.expectEqual(@as(Term, 3), (try Message.decode(buf[0..Message.timeout_now_len], 0, 1, &scratch)).body.timeout_now.term);
    try testing.expectError(error.Truncated, Message.decode(buf[0 .. Message.timeout_now_len - 1], 0, 1, &scratch));
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0 .. Message.timeout_now_len + 1], 0, 1, &scratch));
    bad = buf;
    @memset(bad[1..9], 0);
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.timeout_now_len], 0, 1, &scratch));
    std.mem.writeInt(u64, bad[1..9], types.max_term + 1, .little);
    try testing.expectError(error.InvalidEncoding, Message.decode(bad[0..Message.timeout_now_len], 0, 1, &scratch));
}

test "InstallSnapshot round-trips and refuses what an honest leader never sends" {
    var conf_buf: [64]u8 = undefined;
    const voters = [_]NodeId{ 0, 2, 5 };
    const learners = [_]NodeId{7};
    const conf_len = (Membership{ .voters = &voters, .learners = &learners }).encode(&conf_buf);
    const conf = conf_buf[0..conf_len];
    try roundTrip(.{ .from = 0, .to = 1, .body = .{ .snapshot = .{ .term = 7, .index = 40, .snap_term = 6, .conf = conf, .data = "state" } } });
    try roundTrip(.{ .from = 0, .to = 1, .body = .{ .snapshot = .{ .term = 7, .index = 40, .snap_term = 7, .conf = conf, .data = "" } } });

    var buf: [128]u8 = undefined;
    var scratch: [1]Entry = undefined;
    const good: Message = .{ .from = 0, .to = 1, .body = .{ .snapshot = .{ .term = 7, .index = 40, .snap_term = 6, .conf = conf, .data = "state" } } };
    const n = good.encode(&buf);
    // Truncated anywhere, or a byte too many.
    for (0..n) |cut| try testing.expect(std.meta.isError(Message.decode(buf[0..cut], 0, 1, &scratch)));
    buf[n] = 0;
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0 .. n + 1], 0, 1, &scratch));
    // Index 0, snapshot term 0, a snapshot term above the leader's, term 0.
    inline for (.{
        .{ .term = 7, .index = 0, .snap_term = 6 },
        .{ .term = 7, .index = 40, .snap_term = 0 },
        .{ .term = 7, .index = 40, .snap_term = 8 },
    }) |bad| {
        const m: Message = .{ .from = 0, .to = 1, .body = .{ .snapshot = .{ .term = bad.term, .index = bad.index, .snap_term = bad.snap_term, .conf = conf, .data = "" } } };
        const k = m.encode(&buf);
        try testing.expectError(error.InvalidEncoding, Message.decode(buf[0..k], 0, 1, &scratch));
    }
    // A malformed membership inside.
    const dup = [_]NodeId{ 2, 2 };
    var bad_conf: [64]u8 = undefined;
    const bl = (Membership{ .voters = &dup }).encode(&bad_conf);
    const m: Message = .{ .from = 0, .to = 1, .body = .{ .snapshot = .{ .term = 7, .index = 4, .snap_term = 6, .conf = bad_conf[0..bl], .data = "" } } };
    const k = m.encode(&buf);
    try testing.expectError(error.InvalidEncoding, Message.decode(buf[0..k], 0, 1, &scratch));
}

test "Membership: round-trips, and refuses every second spelling and every impossible set" {
    var ids: [16]NodeId = undefined;
    var buf: [128]u8 = undefined;
    const ok: Membership = .{ .voters = &.{ 1, 2, 3 }, .voters_outgoing = &.{ 0, 1, 2 }, .learners = &.{9} };
    const n = ok.encode(&buf);
    try testing.expectEqual(ok.encodedLen(), n);
    const d = try Membership.decode(buf[0..n], &ids);
    try testing.expectEqualSlices(NodeId, ok.voters, d.voters);
    try testing.expectEqualSlices(NodeId, ok.voters_outgoing, d.voters_outgoing);
    try testing.expectEqualSlices(NodeId, ok.learners, d.learners);
    try testing.expect(d.isJoint());
    for (0..n) |cut| try testing.expect(std.meta.isError(Membership.decode(buf[0..cut], &ids)));
    // More ids than the caller's buffer.
    try testing.expectError(error.InvalidEncoding, Membership.decode(buf[0..n], ids[0..6]));
    const bad = [_]Membership{
        .{ .voters = &.{} }, // no voters
        .{ .voters = &.{ 2, 1 } }, // not ascending
        .{ .voters = &.{ 1, 1 } }, // duplicate
        .{ .voters = &.{ 1, types.no_vote } }, // the "nobody" id
        .{ .voters = &.{1}, .learners = &.{1} }, // a learner that votes
        .{ .voters = &.{1}, .voters_outgoing = &.{2}, .learners = &.{2} }, // ... in C_old
    };
    for (bad) |b| {
        const k = b.encode(&buf);
        try testing.expectError(error.InvalidEncoding, Membership.decode(buf[0..k], &ids));
    }
}
