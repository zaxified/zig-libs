// SPDX-License-Identifier: MIT
//! **Traffic-control notifications** (`tc monitor`): a socket joined to the
//! `RTNLGRP_TC` multicast group, and an iterator that decodes each message of
//! a received datagram into a qdisc, class, filter, action or chain event.
//!
//! The kernel sends one message per change, in the same shape as a dump
//! record (`struct tcmsg` plus attributes; actions use `struct tcamsg`), so the
//! module's own decoders do the work. Joining the group needs no privilege.
//!
//! ```zig
//! var mon = try tc.monitor.Monitor.open(gpa);
//! defer mon.close();
//! var events = try mon.recv();
//! while (try events.next()) |ev| switch (ev.body) {
//!     .qdisc => |q| std.log.info("{s} qdisc {s}", .{ if (ev.added) "new" else "del", q.kind() }),
//!     else => {},
//! };
//! ```

const std = @import("std");
const builtin = @import("builtin");

const netlink = @import("netlink");
const codec = netlink.codec;

const qdisc = @import("qdisc.zig");
const filter = @import("filter.zig");
const action = @import("action.zig");
const message = @import("message.zig");

/// `RTNLGRP_TC` (linux/rtnetlink.h): the group every tc notification goes to.
pub const RTNLGRP_TC: u32 = 4;

/// One notification.
pub const Event = struct {
    /// `RTM_NEW*` (a creation or a change) versus `RTM_DEL*`.
    added: bool,
    body: Body,

    pub const Body = union(enum) {
        qdisc: qdisc.Qdisc,
        class: qdisc.Class,
        filter: filter.Filter,
        /// A chain; `Filter.chain` is its index and `kind()` its template's.
        chain: filter.Filter,
        /// The shared-table actions the message carries; borrows the receive
        /// buffer until the next `Monitor.recv`.
        actions: ?action.ActionIterator,
    };
};

/// Iterates the messages of one received datagram. Messages of other types
/// are skipped; a message that does not decode is an error (`codec.Error`).
pub const EventIterator = struct {
    it: codec.MessageIterator,

    pub fn init(datagram: []const u8) EventIterator {
        return .{ .it = .{ .buf = datagram } };
    }

    pub fn next(self: *EventIterator) codec.Error!?Event {
        while (try self.it.next()) |m| {
            const body: Event.Body = switch (m.type) {
                message.RTM_NEWQDISC, message.RTM_DELQDISC => .{ .qdisc = try qdisc.parseQdisc(m.payload) },
                message.RTM_NEWTCLASS, message.RTM_DELTCLASS => .{ .class = try qdisc.parseClass(m.payload) },
                message.RTM_NEWTFILTER, message.RTM_DELTFILTER => .{ .filter = try filter.parseFilter(m.payload) },
                message.RTM_NEWCHAIN, message.RTM_DELCHAIN => .{ .chain = try filter.parseFilter(m.payload) },
                message.RTM_NEWACTION, message.RTM_DELACTION => .{ .actions = try action.actionsOf(m.payload) },
                else => continue,
            };
            return .{ .added = isNew(m.type), .body = body };
        }
        return null;
    }

    fn isNew(t: u16) bool {
        return switch (t) {
            message.RTM_NEWQDISC,
            message.RTM_NEWTCLASS,
            message.RTM_NEWTFILTER,
            message.RTM_NEWCHAIN,
            message.RTM_NEWACTION,
            => true,
            else => false,
        };
    }
};

/// A socket subscribed to `RTNLGRP_TC`.
pub const Monitor = struct {
    nl: netlink.Socket,

    pub fn open(gpa: std.mem.Allocator) netlink.OpenError!Monitor {
        if (comptime builtin.os.tag != .linux)
            @compileError("tc.monitor is Linux-only (AF_NETLINK raw syscalls)");
        const mask = netlink.rtnlGroupMask(&.{RTNLGRP_TC}) catch unreachable; // group 4 is in range
        return .{ .nl = try netlink.Socket.openMonitor(gpa, mask) };
    }

    pub fn close(m: *Monitor) void {
        m.nl.close();
    }

    /// Block for the next datagram (bounded by the socket's receive timeout,
    /// if one is set on `nl`) and iterate its events. `error.Overrun` means
    /// the kernel dropped notifications: rebuild the view with dumps.
    pub fn recv(m: *Monitor) netlink.StrictRecvError!EventIterator {
        return EventIterator.init(try m.nl.recvDatagramStrict());
    }
};
