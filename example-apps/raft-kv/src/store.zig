// SPDX-License-Identifier: MIT

//! Durable state, over the `kv` module. Raft's correctness contract is that
//! (currentTerm, votedFor) and the log survive a crash — a node that answers
//! an RPC and then forgets what it answered can elect two leaders. `kv.Db`
//! fsyncs on every `put`, so "this function returned" IS the durability
//! point, and the calling order in `node.zig` is: persist, THEN send the
//! message that promises it (`raft.Node`'s `ready` contract).
//!
//! Layout, one record per fact:
//!   "m"            term(8) | vote(4)               — persistent state (§5.1)
//!   "l" ++ idx(8)  term(8) | kind(1) | data — log entry (raft.Entry)
//!
//! Log indices are dense from 1, so "iterate" is `get(1), get(2), …` until
//! the first miss — no ordered scan needed. commitIndex is deliberately NOT
//! persisted (volatile in Figure 2): it is re-learned from the next leader,
//! and the applied state machine is rebuilt by re-applying from index 1.

const std = @import("std");
const kv = @import("kv");
const raft = @import("raft");

pub const Store = struct {
    fs: kv.FsStorage,
    db: kv.Db,

    /// In-place: `db` captures a pointer to `fs`, so `self` must already sit
    /// at its final address — returning a `Store` by value would hand `db` a
    /// dangling interface (measured: GP fault on the first cross-thread put).
    pub fn open(self: *Store, gpa: std.mem.Allocator, io: std.Io, data_dir: []const u8) !void {
        std.Io.Dir.cwd().createDirPath(io, data_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        const dir = try std.Io.Dir.cwd().openDir(io, data_dir, .{});
        self.fs = kv.FsStorage.init(io, dir);
        self.db = try kv.Db.open(gpa, self.fs.storage(), "raft.kv", .{});
    }

    pub fn close(self: *Store) void {
        self.db.close();
    }

    // ── persistent state ────────────────────────────────────────────────────

    pub fn saveMeta(self: *Store, term: raft.Term, vote: raft.NodeId) !void {
        var buf: [12]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], term, .little);
        std.mem.writeInt(u32, buf[8..12], vote, .little);
        try self.db.put("m", &buf);
    }

    pub fn loadMeta(self: *Store) struct { term: raft.Term, vote: raft.NodeId } {
        var buf: [12]u8 = undefined;
        const v = self.db.getBuf(&buf, "m") catch return .{ .term = 0, .vote = raft.no_vote };
        if (v == null or v.?.len != 12) return .{ .term = 0, .vote = raft.no_vote };
        return .{
            .term = std.mem.readInt(u64, buf[0..8], .little),
            .vote = std.mem.readInt(u32, buf[8..12], .little),
        };
    }

    // ── log entries ─────────────────────────────────────────────────────────

    fn entryKey(idx: raft.LogIndex, buf: *[9]u8) []const u8 {
        buf[0] = 'l';
        std.mem.writeInt(u64, buf[1..9], idx, .little);
        return buf;
    }

    /// Record: term(8) | kind(1) | data(rest).
    pub fn putEntry(self: *Store, gpa: std.mem.Allocator, entry: raft.Entry) !void {
        var kbuf: [9]u8 = undefined;
        const rec = try gpa.alloc(u8, 9 + entry.data.len);
        defer gpa.free(rec);
        std.mem.writeInt(u64, rec[0..8], entry.term, .little);
        rec[8] = @intFromEnum(entry.kind);
        @memcpy(rec[9..], entry.data);
        try self.db.put(entryKey(entry.index, &kbuf), rec);
    }

    pub fn delEntry(self: *Store, idx: raft.LogIndex) !void {
        var kbuf: [9]u8 = undefined;
        try self.db.delete(entryKey(idx, &kbuf));
    }

    /// Caller frees `data`.
    pub fn getEntry(self: *Store, gpa: std.mem.Allocator, idx: raft.LogIndex) !?raft.Entry {
        var kbuf: [9]u8 = undefined;
        const rec = (try self.db.get(gpa, entryKey(idx, &kbuf))) orelse return null;
        defer gpa.free(rec);
        if (rec.len < 9) return error.Corrupt;
        const kind = std.enums.fromInt(raft.EntryKind, rec[8]) orelse return error.Corrupt;
        return .{
            .index = idx,
            .term = std.mem.readInt(u64, rec[0..8], .little),
            .kind = kind,
            .data = try gpa.dupe(u8, rec[9..]),
        };
    }
};
