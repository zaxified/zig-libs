// SPDX-License-Identifier: MIT

//! What a consumer builds `raft` INTO: a follower's RPC receive path running
//! over its OWN transport, not `netsim`. The module ships two kinds of public
//! surface — a simulation harness (`RaftServer`, `scenario`, the `netsim`
//! wiring) for model-checking, and the underlying decision kernel (`types`'
//! wire codecs + `safety`'s pure `handleRequestVote` / `handleAppendEntries`)
//! that a real server calls directly against RPCs that arrived over TCP,
//! QUIC, whatever transport the consumer already has. This example is the
//! second kind: decode two RPCs off the wire, run them through the safety
//! kernel, and apply the mechanical log mutation the kernel's verdict
//! prescribes — exactly what `server.zig` does internally, but from OUTSIDE
//! the module, which is what proves the kernel is usable standalone.
//!
//! Built against the PUBLISHED module (`@import("raft")`) only.

const std = @import("std");
const raft = @import("raft");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // This follower is at term 3, has not voted this term, and holds two
    // entries from term 1 and term 2.
    var log: raft.Log = .{};
    defer log.deinit(gpa);
    try log.append(gpa, .{ .term = 1, .command = 10 });
    try log.append(gpa, .{ .term = 2, .command = 11 });

    var current_term: raft.Term = 3;
    var voted_for: raft.NodeId = raft.no_vote;
    var commit_index: raft.LogIndex = 1;

    // ── a RequestVote arrives as wire bytes (a peer over our own transport) ──
    var rv_buf: [raft.RequestVoteReq.wire_len]u8 = undefined;
    (raft.RequestVoteReq{
        .term = 4,
        .candidate_id = 7,
        .last_log_index = 2,
        .last_log_term = 2,
    }).encode(&rv_buf);

    const rv_req = raft.RequestVoteReq.decode(&rv_buf) catch |err| switch (err) {
        // A decode failure here is a malformed peer datagram, not our bug —
        // handled by name, not swallowed into `catch unreachable`.
        error.Truncated, error.InvalidEncoding => {
            std.debug.print("malformed RequestVote, ignoring\n", .{});
            return;
        },
    };

    const vote = raft.handleRequestVote(current_term, voted_for, log.info(), rv_req);
    if (vote.term_advanced) current_term = vote.new_term;
    if (vote.grant) voted_for = vote.voted_for;
    std.debug.print("RequestVote from node {d}: grant={}, term now {d}\n", .{
        rv_req.candidate_id, vote.grant, current_term,
    });

    // ── AppendEntries from the leader we just voted for ─────────────────────
    //
    // `AppendEntriesReq.decode` writes into a caller-owned `*[N]LogEntry`
    // scratch array sized to the wire format's own entry cap. `raft` does not
    // re-export the constant that cap is defined from (`types.max_entries_
    // per_msg`, private to the module) — the size has to be rederived from
    // the two wire-length constants it DOES export. See the note at the
    // bottom of this file.
    const max_entries_per_msg = (raft.AppendEntriesReq.max_wire - raft.AppendEntriesReq.header_len) / raft.LogEntry.wire_len;

    const new_entries = [_]raft.LogEntry{.{ .term = 4, .command = 99 }};
    var ae_buf: [raft.AppendEntriesReq.max_wire]u8 = undefined;
    const ae_len = (raft.AppendEntriesReq{
        .term = 4,
        .leader_id = 7,
        .prev_log_index = 2,
        .prev_log_term = 2,
        .entries = &new_entries,
        .leader_commit = 2,
    }).encode(&ae_buf);

    var entry_scratch: [max_entries_per_msg]raft.LogEntry = undefined;
    const ae_req = raft.AppendEntriesReq.decode(ae_buf[0..ae_len], &entry_scratch) catch |err| switch (err) {
        error.Truncated, error.InvalidEncoding => {
            std.debug.print("malformed AppendEntries, ignoring\n", .{});
            return;
        },
    };

    const outcome = raft.handleAppendEntries(current_term, &log, commit_index, ae_req);
    if (outcome.term_advanced) current_term = outcome.new_term;
    if (!outcome.success) {
        std.debug.print("AppendEntries rejected (consistency check failed)\n", .{});
        return;
    }

    // The kernel decided WHAT to do (conflict-only truncation, which entries
    // to append, where commitIndex may advance); applying that verdict to the
    // log is mechanical and is ours to do, exactly as `server.zig` does.
    log.truncateAfter(outcome.truncate_to);
    try log.appendSlice(gpa, ae_req.entries[outcome.append_from..]);
    commit_index = outcome.new_commit_index;

    std.debug.print(
        "AppendEntries accepted: log now has {d} entries, commitIndex={d}, matchIndex={d}\n",
        .{ log.lastIndex(), commit_index, outcome.match_index },
    );

    // Reply the leader needs to advance matchIndex/nextIndex for this node —
    // encoded the same way this follower would put it back on the wire.
    var resp_buf: [raft.AppendEntriesResp.wire_len]u8 = undefined;
    (raft.AppendEntriesResp{
        .term = current_term,
        .success = true,
        .match_index = outcome.match_index,
    }).encode(&resp_buf);
    std.debug.print("reply: {d} bytes ready to send back to the leader\n", .{resp_buf.len});
}
