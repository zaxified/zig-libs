// SPDX-License-Identifier: MIT

//! Redundancy groups of a controlled station (IEC 60870-5-104 Ed. 2 clause 10,
//! "redundant connections"): which connections of which controlling stations
//! may carry data, and which one does now. A pure arbitration state machine, no
//! I/O and no clock: the caller owns one `outstation.Server` per accepted
//! connection, tells the `Arbiter` about connects, `STARTDT`/`STOPDT` and
//! disconnects, and does what it answers.
//!
//! The rules follow lib60870's documented model (the user guide of the C
//! library; documentation only, no source read):
//!
//! - **A group allows one active connection**, the one that most recently sent
//!   `STARTDT act`. Its other connections stay up in standby: they answer
//!   `TESTFR` and acknowledge, they carry no data.
//! - **A standby that sends `STARTDT act` takes activation over.** The previously
//!   active connection is deactivated without a frame (`Arbiter.activate` names
//!   it; `Server.deactivate` does it); it stays connected and can take the
//!   activation back with its own `STARTDT`.
//! - **A peer's group follows its address.** In `multiple_groups` mode each group
//!   lists the client addresses it takes in; a group with no addresses is the
//!   catch-all for everybody else, and a connection that matches no group is
//!   refused. `single_group` is one catch-all group; `connection_is_group` makes
//!   every connection its own group, so all of them may be active at once.
//!
//! What stays with the caller: routing the process data to the active
//! connection's `Server` (`reportSpontaneous`), and replaying what a deactivated
//! connection had queued, if the application needs that.

const std = @import("std");
const outstation = @import("outstation.zig");

/// A client address as 16 octets: IPv6 as is, IPv4 as `::ffff:a.b.c.d`.
pub const PeerAddr = [16]u8;

/// The IPv4-mapped form of an IPv4 address.
pub fn peerFromIp4(octets: [4]u8) PeerAddr {
    var a: PeerAddr = @splat(0);
    a[10] = 0xff;
    a[11] = 0xff;
    @memcpy(a[12..], &octets);
    return a;
}

pub const Mode = enum {
    /// One catch-all group: at most one active connection, whoever it is.
    single_group,
    /// Every connection is its own group: all may be active.
    connection_is_group,
    /// Groups by client address; a group without addresses is the catch-all.
    multiple_groups,
};

pub const GroupSpec = struct {
    /// Client addresses this group takes in; empty: the catch-all group.
    allowed: []const PeerAddr = &.{},
};

pub const ConnId = u16;

pub const Error = error{
    /// `multiple_groups`: no group lists this address and none is the catch-all.
    NoGroup,
    /// Every connection slot is taken.
    TooManyConnections,
    /// The id names no connection that is up.
    UnknownConnection,
};

pub const Activation = struct {
    /// The connection of the same group that was active and now is not, if any.
    /// The caller deactivates its `Server` (`Server.deactivate`).
    deactivated: ?ConnId = null,
};

pub const Arbiter = struct {
    mode: Mode,
    groups: []const GroupSpec,
    conns: []Conn,
    clock: u64 = 0,

    pub const Conn = struct {
        used: bool = false,
        group: u16 = 0,
        peer: PeerAddr = @splat(0),
        active: bool = false,
        /// When it was last activated (a counter, not a time).
        activated_at: u64 = 0,
    };

    /// `slots` is the caller's connection table (all `.{}`); its length is the
    /// most connections open at once. `groups` is only read in `multiple_groups`
    /// mode.
    pub fn init(mode: Mode, groups: []const GroupSpec, slots: []Conn) Arbiter {
        for (slots) |*s| s.* = .{};
        return .{ .mode = mode, .groups = groups, .conns = slots };
    }

    /// A connection from `peer` came up. Returns its id.
    pub fn connect(self: *Arbiter, peer: PeerAddr) Error!ConnId {
        const group = try self.groupFor(peer);
        for (self.conns, 0..) |*c, i| {
            if (c.used) continue;
            c.* = .{ .used = true, .group = group, .peer = peer };
            // `connection_is_group`: the group is the slot itself.
            if (self.mode == .connection_is_group) c.group = @intCast(i);
            return @intCast(i);
        }
        return error.TooManyConnections;
    }

    /// The connection went away. Returns whether it was the active one of its
    /// group: the group has no active connection until a `STARTDT` arrives.
    pub fn disconnect(self: *Arbiter, id: ConnId) Error!bool {
        const c = try self.get(id);
        const was = c.active;
        c.* = .{};
        return was;
    }

    /// `STARTDT act` arrived on `id`: it becomes the active connection of its
    /// group and the one that was active, if another, is named for deactivation.
    pub fn activate(self: *Arbiter, id: ConnId) Error!Activation {
        const c = try self.get(id);
        var out: Activation = .{};
        if (c.active) return out;
        for (self.conns, 0..) |*o, i| {
            if (!o.used or !o.active or o.group != c.group or i == id) continue;
            o.active = false;
            out.deactivated = @intCast(i);
        }
        c.active = true;
        self.clock += 1;
        c.activated_at = self.clock;
        return out;
    }

    /// `STOPDT act` arrived on `id`: it is standby now and its group has no
    /// active connection until one sends `STARTDT`.
    pub fn deactivate(self: *Arbiter, id: ConnId) Error!void {
        (try self.get(id)).active = false;
    }

    pub fn isActive(self: *const Arbiter, id: ConnId) bool {
        if (id >= self.conns.len or !self.conns[id].used) return false;
        return self.conns[id].active;
    }

    /// The group index of a connection.
    pub fn groupOf(self: *const Arbiter, id: ConnId) ?u16 {
        if (id >= self.conns.len or !self.conns[id].used) return null;
        return self.conns[id].group;
    }

    /// The active connection of `group`, if any: where its process data goes.
    pub fn activeIn(self: *const Arbiter, group: u16) ?ConnId {
        for (self.conns, 0..) |c, i| {
            if (c.used and c.active and c.group == group) return @intCast(i);
        }
        return null;
    }

    fn get(self: *Arbiter, id: ConnId) Error!*Conn {
        if (id >= self.conns.len or !self.conns[id].used) return error.UnknownConnection;
        return &self.conns[id];
    }

    fn groupFor(self: *const Arbiter, peer: PeerAddr) Error!u16 {
        switch (self.mode) {
            .single_group, .connection_is_group => return 0,
            .multiple_groups => {
                var catch_all: ?u16 = null;
                for (self.groups, 0..) |g, i| {
                    if (g.allowed.len == 0) {
                        if (catch_all == null) catch_all = @intCast(i);
                        continue;
                    }
                    for (g.allowed) |a| if (std.mem.eql(u8, &a, &peer)) return @intCast(i);
                }
                return catch_all orelse error.NoGroup;
            },
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

const master_a = peerFromIp4(.{ 10, 0, 0, 1 });
const master_b = peerFromIp4(.{ 10, 0, 0, 2 });
const engineer = peerFromIp4(.{ 192, 168, 1, 9 });

test "single group: the most recent STARTDT is the one active connection" {
    var slots: [4]Arbiter.Conn = undefined;
    var arb = Arbiter.init(.single_group, &.{}, &slots);
    const a = try arb.connect(master_a);
    const b = try arb.connect(master_b);
    try testing.expect(!arb.isActive(a) and !arb.isActive(b));

    try testing.expectEqual(@as(?ConnId, null), (try arb.activate(a)).deactivated);
    try testing.expect(arb.isActive(a));
    // The standby takes over; the previous active one is named, not closed.
    try testing.expectEqual(@as(?ConnId, a), (try arb.activate(b)).deactivated);
    try testing.expect(!arb.isActive(a) and arb.isActive(b));
    // And back.
    try testing.expectEqual(@as(?ConnId, b), (try arb.activate(a)).deactivated);
    // A repeated STARTDT on the active one changes nothing.
    try testing.expectEqual(@as(?ConnId, null), (try arb.activate(a)).deactivated);
    try testing.expectEqual(@as(?ConnId, a), arb.activeIn(0));
}

test "STOPDT and a disconnect leave the group without an active connection" {
    var slots: [4]Arbiter.Conn = undefined;
    var arb = Arbiter.init(.single_group, &.{}, &slots);
    const a = try arb.connect(master_a);
    const b = try arb.connect(master_b);
    _ = try arb.activate(a);
    try arb.deactivate(a);
    try testing.expectEqual(@as(?ConnId, null), arb.activeIn(0));
    _ = try arb.activate(b);
    try testing.expect(try arb.disconnect(b));
    try testing.expectEqual(@as(?ConnId, null), arb.activeIn(0));
    // A standby that goes away was not the active one.
    try testing.expect(!(try arb.disconnect(a)));
    try testing.expectError(error.UnknownConnection, arb.disconnect(a));
}

test "connection is group: every connection may be active at once" {
    var slots: [3]Arbiter.Conn = undefined;
    var arb = Arbiter.init(.connection_is_group, &.{}, &slots);
    const a = try arb.connect(master_a);
    const b = try arb.connect(master_b);
    try testing.expectEqual(@as(?ConnId, null), (try arb.activate(a)).deactivated);
    try testing.expectEqual(@as(?ConnId, null), (try arb.activate(b)).deactivated);
    try testing.expect(arb.isActive(a) and arb.isActive(b));
    try testing.expect(arb.groupOf(a).? != arb.groupOf(b).?);
}

test "multiple groups: the address picks the group, the catch-all takes the rest, no catch-all refuses" {
    const groups = [_]GroupSpec{
        .{ .allowed = &.{ master_a, master_b } },
        .{ .allowed = &.{engineer} },
    };
    var slots: [6]Arbiter.Conn = undefined;
    var arb = Arbiter.init(.multiple_groups, &groups, &slots);
    const a = try arb.connect(master_a);
    const b = try arb.connect(master_b);
    const e = try arb.connect(engineer);
    try testing.expectEqual(@as(?u16, 0), arb.groupOf(a));
    try testing.expectEqual(@as(?u16, 0), arb.groupOf(b));
    try testing.expectEqual(@as(?u16, 1), arb.groupOf(e));
    // One active per group, independently.
    _ = try arb.activate(a);
    _ = try arb.activate(e);
    try testing.expect(arb.isActive(a) and arb.isActive(e));
    try testing.expectEqual(@as(?ConnId, a), (try arb.activate(b)).deactivated);
    try testing.expect(arb.isActive(e));
    // An address no group lists, and no catch-all.
    try testing.expectError(error.NoGroup, arb.connect(peerFromIp4(.{ 8, 8, 8, 8 })));

    const with_catch_all = [_]GroupSpec{ groups[0], .{} };
    var slots2: [4]Arbiter.Conn = undefined;
    var arb2 = Arbiter.init(.multiple_groups, &with_catch_all, &slots2);
    const stranger = try arb2.connect(peerFromIp4(.{ 8, 8, 8, 8 }));
    try testing.expectEqual(@as(?u16, 1), arb2.groupOf(stranger));
}

test "connection slots run out" {
    var slots: [2]Arbiter.Conn = undefined;
    var arb = Arbiter.init(.single_group, &.{}, &slots);
    _ = try arb.connect(master_a);
    const b = try arb.connect(master_b);
    try testing.expectError(error.TooManyConnections, arb.connect(engineer));
    _ = try arb.disconnect(b);
    _ = try arb.connect(engineer); // the slot is free again
}

test "two servers behind one arbiter: the standby takes over and the old active sends no more data" {
    var points = [_]outstation.Point{.{
        .ioa = 1,
        .type_id = .m_sp_na_1,
        .element = .{ .siq = .{ .on = true } },
    }};
    const apci = @import("apci.zig");
    const transport = @import("transport.zig");
    var loops: [2]transport.LoopTransport = .{ .{}, .{} };
    var frames: [2][apci.max_apdu_len * 2]u8 = undefined;
    var queues: [2][1024]u8 = undefined;
    var servers: [2]outstation.Server = undefined;
    for (&servers, 0..) |*s, i| {
        s.* = try outstation.Server.init(.{ .common_address = 7 }, &points, loops[i].transport(), &frames[i], &queues[i], .{});
        s.onConnected(0);
    }
    var slots: [2]Arbiter.Conn = undefined;
    var arb = Arbiter.init(.single_group, &.{}, &slots);
    const ids = [2]ConnId{ try arb.connect(master_a), try arb.connect(master_b) };

    const startdt_act = [_]u8{ 0x68, 0x04, 0x07, 0x00, 0x00, 0x00 };
    // Master A starts data transfer on connection 0.
    loops[0].deliver(&startdt_act);
    try testing.expectEqual(outstation.Server.Event.started, try servers[0].poll(0));
    try testing.expectEqual(@as(?ConnId, null), (try arb.activate(ids[0])).deactivated);
    _ = try servers[0].poll(0); // sends STARTDT con
    try servers[0].reportSpontaneous(1, 1);
    _ = try servers[0].poll(1);
    const before = loops[0].sent().len;
    try testing.expect(before > 6); // the STARTDT con and a data frame

    // Master B starts on connection 1: A is deactivated, B gets the data.
    loops[1].deliver(&startdt_act);
    try testing.expectEqual(outstation.Server.Event.started, try servers[1].poll(2));
    const act = try arb.activate(ids[1]);
    try testing.expectEqual(@as(?ConnId, ids[0]), act.deactivated);
    servers[act.deactivated.?].deactivate();
    try testing.expect(!servers[0].isStarted() and servers[1].isStarted());
    try servers[0].reportSpontaneous(1, 3);
    _ = try servers[0].poll(3);
    try testing.expectEqual(before, loops[0].sent().len); // nothing more to the standby
    // A STARTDT of its own takes the activation back.
    loops[0].deliver(&startdt_act);
    try testing.expectEqual(outstation.Server.Event.started, try servers[0].poll(4));
}
