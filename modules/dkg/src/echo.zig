// SPDX-License-Identifier: MIT

//! echo — an echo-broadcast helper: lets a plain point-to-point transport
//! carry the "reliable broadcast" the per-participant API assumes
//! (broadcast with abort, Goldwasser-Lindell style, as used by FROST and
//! CGGMP deployments).
//!
//! After a round whose messages must be broadcast, every party feeds the
//! bytes it RECEIVED from each sender (its own included) into an
//! `EchoBroadcast`, takes `digest()`, sends that 32-octet digest to every
//! other party over the point-to-point channel, and proceeds only if every
//! digest it receives passes `check` (or `firstMismatch` returns null).
//! A mismatch means some sender gave different parties different bytes. A
//! party cannot always tell WHICH sender equivocated (only that its view and
//! `peer`'s differ), so the error names the first disagreeing PEER, not the
//! equivocator; the parties then abort the session.
//!
//! Sans-I/O and allocation-free: the caller provides the slot storage
//! (`n` slots), so there is no participant cap. The helper wraps the
//! existing round functions; it changes none of them. The digest is
//! domain-separated SHA-256 over the round label, the participant set and,
//! in ascending id order, each sender id with SHA-256 of its received message.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    /// `participants` is empty, has a duplicate id, or `slots` is too short.
    BadParticipants,
    /// The sender (or peer) is not in the participant set.
    UnknownSender,
    /// A message from this sender was already added.
    DuplicateSender,
    /// `digest()` called before every sender's message arrived.
    Incomplete,
    /// A peer's digest differs from ours: equivocation detected.
    Equivocation,
};

/// One participant's record. Caller-provided storage; contents are internal.
pub const Slot = struct {
    id: u32 = 0,
    seen: bool = false,
    msg_hash: [32]u8 = @splat(0),
};

/// A peer's echoed digest, for `firstMismatch`.
pub const PeerDigest = struct { peer: u32, digest: [32]u8 };

pub const EchoBroadcast = struct {
    label: []const u8,
    /// Sorted ascending by id.
    slots: []Slot,

    /// `participants`: distinct ids, any order (every party of the round,
    /// self included). `slots.len >= participants.len`; the first
    /// `participants.len` slots are used. `round_label` is borrowed.
    pub fn init(round_label: []const u8, participants: []const u32, slots: []Slot) Error!EchoBroadcast {
        if (participants.len == 0 or slots.len < participants.len) return error.BadParticipants;
        if (participants.len > std.math.maxInt(u32) or round_label.len > std.math.maxInt(u32)) return error.BadParticipants;
        const s = slots[0..participants.len];
        for (participants, s) |id, *slot| slot.* = .{ .id = id };
        std.mem.sort(Slot, s, {}, lessThan);
        for (s[1..], 0..) |slot, i| if (slot.id == s[i].id) return error.BadParticipants;
        return .{ .label = round_label, .slots = s };
    }

    fn lessThan(_: void, a: Slot, b: Slot) bool {
        return a.id < b.id;
    }

    fn find(self: *const EchoBroadcast, id: u32) ?*Slot {
        var lo: usize = 0;
        var hi: usize = self.slots.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.slots[mid].id == id) return &self.slots[mid];
            if (self.slots[mid].id < id) lo = mid + 1 else hi = mid;
        }
        return null;
    }

    /// Record the bytes received from `sender`.
    pub fn addReceived(self: *EchoBroadcast, sender: u32, msg: []const u8) Error!void {
        const slot = self.find(sender) orelse return error.UnknownSender;
        if (slot.seen) return error.DuplicateSender;
        Sha256.hash(msg, &slot.msg_hash, .{});
        slot.seen = true;
    }

    /// Participants whose message has not arrived yet, written into `out`
    /// (ascending); returns how many are missing in total (may exceed `out.len`).
    pub fn missing(self: *const EchoBroadcast, out: []u32) usize {
        var n: usize = 0;
        for (self.slots) |s| if (!s.seen) {
            if (n < out.len) out[n] = s.id;
            n += 1;
        };
        return n;
    }

    pub fn isComplete(self: *const EchoBroadcast) bool {
        return self.missing(&.{}) == 0;
    }

    /// The transcript digest to send to every other party.
    /// `error.Incomplete` until every sender's message was added.
    pub fn digest(self: *const EchoBroadcast) Error![32]u8 {
        if (!self.isComplete()) return error.Incomplete;
        var h = Sha256.init(.{});
        h.update("zig-libs dkg echo-broadcast v1");
        updateU32(&h, @intCast(self.label.len));
        h.update(self.label);
        updateU32(&h, @intCast(self.slots.len));
        for (self.slots) |s| updateU32(&h, s.id);
        for (self.slots) |s| {
            updateU32(&h, s.id);
            h.update(&s.msg_hash);
        }
        return h.finalResult();
    }

    /// Compare `peer`'s echoed digest with ours. `error.Equivocation` on a
    /// mismatch; the caller aborts the session.
    pub fn check(self: *const EchoBroadcast, peer: u32, peer_digest: [32]u8) Error!void {
        if (self.find(peer) == null) return error.UnknownSender;
        const mine = try self.digest();
        if (!std.crypto.timing_safe.eql([32]u8, mine, peer_digest)) return error.Equivocation;
    }

    /// Check every echo; returns the first peer (in the order given) whose
    /// digest differs, or null if all agree. Errors as `check`.
    pub fn firstMismatch(self: *const EchoBroadcast, echoes: []const PeerDigest) Error!?u32 {
        for (echoes) |e| self.check(e.peer, e.digest) catch |err| switch (err) {
            error.Equivocation => return e.peer,
            else => return err,
        };
        return null;
    }
};

fn updateU32(h: *Sha256, v: u32) void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    h.update(&b);
}

const testing = std.testing;

test "echo: honest run, all digests equal, any participant order" {
    const ids = [_]u32{ 3, 1, 2 };
    var sa: [3]Slot = undefined;
    var sb: [4]Slot = undefined; // extra slots are fine
    var a = try EchoBroadcast.init("round1", &ids, &sa);
    var b = try EchoBroadcast.init("round1", &.{ 1, 2, 3 }, &sb);
    for (ids) |id| {
        var m: [2]u8 = .{ 0xAB, @intCast(id) };
        try a.addReceived(id, &m);
        try b.addReceived(id, &m);
    }
    try testing.expect(a.isComplete());
    const da = try a.digest();
    try testing.expectEqual(da, try b.digest());
    try a.check(2, da);
    try testing.expectEqual(@as(?u32, null), try a.firstMismatch(&.{ .{ .peer = 2, .digest = da }, .{ .peer = 3, .digest = da } }));
}

test "echo: equivocating sender is detected by an honest party" {
    // Sender 3 sends "x" to party 1 and "y" to party 2.
    var s1: [3]Slot = undefined;
    var s2: [3]Slot = undefined;
    var p1 = try EchoBroadcast.init("r", &.{ 1, 2, 3 }, &s1);
    var p2 = try EchoBroadcast.init("r", &.{ 1, 2, 3 }, &s2);
    for ([_]*EchoBroadcast{ &p1, &p2 }) |p| {
        try p.addReceived(1, "m1");
        try p.addReceived(2, "m2");
    }
    try p1.addReceived(3, "x");
    try p2.addReceived(3, "y");
    const d1 = try p1.digest();
    const d2 = try p2.digest();
    try testing.expect(!std.mem.eql(u8, &d1, &d2));
    try testing.expectError(error.Equivocation, p1.check(2, d2));
    try testing.expectError(error.Equivocation, p2.check(1, d1));
    try testing.expectEqual(@as(?u32, 2), try p1.firstMismatch(&.{ .{ .peer = 3, .digest = d1 }, .{ .peer = 2, .digest = d2 } }));
}

test "echo: label, set and message boundaries are bound into the digest" {
    var s: [2]Slot = undefined;
    var a = try EchoBroadcast.init("A", &.{ 1, 2 }, &s);
    try a.addReceived(1, "ab");
    try a.addReceived(2, "c");
    const da = try a.digest();
    var t: [2]Slot = undefined;
    var b = try EchoBroadcast.init("B", &.{ 1, 2 }, &t);
    try b.addReceived(1, "ab");
    try b.addReceived(2, "c");
    try testing.expect(!std.mem.eql(u8, &da, &(try b.digest())));
    var u: [2]Slot = undefined;
    var c = try EchoBroadcast.init("A", &.{ 1, 2 }, &u);
    try c.addReceived(1, "a");
    try c.addReceived(2, "bc");
    try testing.expect(!std.mem.eql(u8, &da, &(try c.digest())));
    var v: [2]Slot = undefined;
    var d = try EchoBroadcast.init("A", &.{ 1, 3 }, &v);
    try d.addReceived(1, "ab");
    try d.addReceived(3, "c");
    try testing.expect(!std.mem.eql(u8, &da, &(try d.digest())));
}

test "echo: duplicate, unknown sender, incomplete and bad setup refused" {
    var s: [3]Slot = undefined;
    var e = try EchoBroadcast.init("r", &.{ 1, 2, 3 }, &s);
    try e.addReceived(1, "a");
    try testing.expectError(error.DuplicateSender, e.addReceived(1, "b"));
    try testing.expectError(error.UnknownSender, e.addReceived(9, "b"));
    try testing.expectError(error.Incomplete, e.digest());
    try testing.expectError(error.Incomplete, e.check(2, @splat(0)));
    var miss: [1]u32 = undefined;
    try testing.expectEqual(@as(usize, 2), e.missing(&miss));
    try testing.expectEqual(@as(u32, 2), miss[0]);
    try e.addReceived(2, "b");
    try e.addReceived(3, "c");
    try testing.expectEqual(@as(usize, 0), e.missing(&miss));
    _ = try e.digest();
    try testing.expectError(error.UnknownSender, e.check(9, @splat(0)));
    try testing.expectError(error.BadParticipants, EchoBroadcast.init("r", &.{}, &s));
    try testing.expectError(error.BadParticipants, EchoBroadcast.init("r", &.{ 1, 1 }, &s));
    try testing.expectError(error.BadParticipants, EchoBroadcast.init("r", &.{ 1, 2, 3, 4 }, &s));
}

test "echo: wraps the real DKG flow — round-1 frames agree at every party" {
    const wire = @import("wire.zig");
    const Participant = @import("participant.zig").Participant;
    var prng = std.Random.DefaultPrng.init(0xEC40);
    const cfg: @import("types.zig").Config = .{ .t = 2, .n = 3 };
    var parties: [3]Participant = undefined;
    for (&parties, 0..) |*p, i| p.* = try Participant.init(testing.allocator, cfg, @intCast(i + 1), prng.random());
    defer for (&parties) |*p| p.deinit();
    for (&parties) |*p| try p.start();
    // Each receiver's view of every sender's broadcast frame (its own included).
    var slots: [3][3]Slot = undefined;
    var echo: [3]EchoBroadcast = undefined;
    for (&echo, 0..) |*e, r| e.* = try EchoBroadcast.init("dkg/round1/pedersen", &.{ 1, 2, 3 }, &slots[r]);
    for (&parties) |*p| {
        const out = try p.takeOutgoing();
        defer wire.freeOutgoing(testing.allocator, out);
        for (out) |m| switch (m.to) {
            .broadcast => for (&echo) |*e| try e.addReceived(p.me, m.bytes),
            .party => {},
        };
    }
    const d0 = try echo[0].digest();
    for (&echo) |*e| try testing.expectEqual(d0, try e.digest());
    try echo[1].check(1, d0);
    try echo[2].check(1, d0);
}

test "echo: more than 2^32-1 participants is refused before any slot is touched" {
    // Never dereferenced: init must refuse on the lengths alone.
    const huge: usize = @as(usize, std.math.maxInt(u32)) + 1;
    const ids: [*]const u32 = @ptrFromInt(0x1000);
    const slots: [*]Slot = @ptrFromInt(0x1000);
    try testing.expectError(error.BadParticipants, EchoBroadcast.init("r", ids[0..huge], slots[0..huge]));
}

test "echo: a round label longer than 2^32-1 is refused; exactly 2^32-1 is not" {
    const label: [*]const u8 = @ptrFromInt(0x1000);
    var slots: [1]Slot = undefined;
    try testing.expectError(error.BadParticipants, EchoBroadcast.init(label[0 .. @as(usize, std.math.maxInt(u32)) + 1], &.{7}, &slots));
    _ = try EchoBroadcast.init(label[0..std.math.maxInt(u32)], &.{7}, &slots);
}
