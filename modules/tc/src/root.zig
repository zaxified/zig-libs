// SPDX-License-Identifier: MIT
//! tc — pure-Zig Linux traffic control over rtnetlink: **qdiscs, classes,
//! filters and actions**, with no `tc` shell-out and no libc.
//!
//! * **qdiscs** — `netem` (delay/jitter/loss/duplicate/reorder/corrupt/rate),
//!   `htb`, `tbf`, `fq_codel`, plus a `raw` escape hatch for any other kind.
//! * **classes** — `RTM_NEWTCLASS`/`DELTCLASS`/`GETTCLASS` with the htb
//!   rate/ceil token buckets, including the psched rate tables and the 64-bit
//!   `TCA_HTB_RATE64`/`CEIL64` attributes for rates above 4.29 GB/s.
//! * **filters** — `RTM_NEWTFILTER`/`DELTFILTER`/`GETTFILTER` with `u32`
//!   (masked 32-bit matches at fixed offsets) and `flower` (structured
//!   L2–L4 keys).
//! * **actions** — the `TCA_*_ACT` list a filter runs on a match (`gact`,
//!   `mirred`, `police`, `skbedit`, `vlan`, `raw`), chained by `TC_ACT_PIPE`,
//!   plus the standalone shared table (`RTM_NEWACTION`/`DELACTION`/
//!   `GETACTION`).
//!
//! ```zig
//! var sock = try tc.Socket.open(gpa);
//! defer sock.close();
//! const root: tc.Handle = .root;
//! const one: tc.Handle = .init(1, 0);
//!
//! try sock.qdiscAdd(.{ .ifindex = ifi, .handle = one, .parent = root },
//!                   .{ .htb = .{ .defcls = 0x10 } });
//! try sock.classAdd(.{ .ifindex = ifi, .handle = .init(1, 0x10), .parent = one },
//!                   .{ .htb = .{ .rate = 125_000, .ceil = 250_000 } });
//! try sock.filterAdd(.{ .ifindex = ifi, .parent = one, .prio = 1,
//!                       .eth_type = tc.ETH_P.IP },
//!                    .{ .u32 = .{ .classid = .init(1, 0x10),
//!                                 .keys = &.{ .ipv4Dst(.{ 10, 0, 0, 1 }, 32) } } });
//! // A filter that runs an action list instead of just picking a class:
//! // mark the packet, then rate-limit it.
//! try sock.filterAdd(.{ .ifindex = ifi, .parent = one, .prio = 2,
//!                       .eth_type = tc.ETH_P.IP },
//!                    .{ .u32 = .{ .keys = &.{ .ipv4Src(.{ 10, 0, 0, 2 }, 32) },
//!                                 .actions = &.{
//!                                     .{ .skbedit = .{ .mark = 7 } }, // ⇒ PIPE
//!                                     .{ .police = .{ .rate = 125_000,
//!                                                     .burst = 10 * 1024,
//!                                                     .exceed = .shot } },
//!                                 } } });
//! const classes = try sock.classes(ifi, one);
//! defer gpa.free(classes);
//! try sock.qdiscDel(.{ .ifindex = ifi, .parent = root });
//! ```
//!
//! The v1 netem shortcuts (`add`/`change`/`del`/`show`) are unchanged and
//! still attach netem as the interface's root qdisc.
//!
//! Every write op needs **CAP_NET_ADMIN**; the `RTM_GET*` dumps do not.
//!
//! **Transport is shared with the sibling `netlink` module.** This module no
//! longer runs its own `NETLINK_ROUTE` socket, sequence counter, errno table
//! or extended-ACK handling: it drives `netlink.Socket` through the public
//! `nextSeq`/`requestAck`/`lastErrorMessage` seam and builds its own tc
//! messages on top of `netlink.codec`. Only the multi-part **dump** receive
//! loop is still local — see the `DRY candidate` note on `Socket.dump`.
//!
//! Verification: `goldens.zig` asserts the encoders reproduce, byte for byte,
//! requests captured from a real `iproute2` `tc` under `strace`; the tests at
//! the bottom of this file exercise the whole stack against a live kernel in
//! a network namespace (and skip cleanly without privileges).

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
pub const codec = netlink.codec;

pub const meta = .{
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .reentrant, // no globals; one Socket per thread/loop
    .model_after = "iproute2 `tc` (attribute-shape/behavior + rate-table arithmetic; wire layout is clean-room from the kernel UAPI linux/pkt_sched.h + linux/pkt_cls.h + linux/rtnetlink.h — see NOTICE)",
    .deps = .{"netlink"},
};

// ── submodules + re-exports ─────────────────────────────────────────────────

pub const handle = @import("handle.zig");
pub const ratespec = @import("ratespec.zig");
pub const qdisc = @import("qdisc.zig");
pub const filter = @import("filter.zig");
pub const action = @import("action.zig");
pub const message = @import("message.zig");

/// `major:minor` handle arithmetic (hexadecimal, like `tc`).
pub const Handle = handle.Handle;
pub const TC_H_UNSPEC = handle.TC_H_UNSPEC;
pub const TC_H_ROOT = handle.TC_H_ROOT;
pub const TC_H_INGRESS = handle.TC_H_INGRESS;
pub const TC_H_CLSACT = handle.TC_H_CLSACT;

/// psched clock calibration + rate tables.
pub const Psched = ratespec.Psched;
pub const RateSpec = ratespec.RateSpec;
pub const LinkLayer = ratespec.LinkLayer;

/// Qdisc/class specs and their wire readbacks.
pub const QdiscSpec = qdisc.QdiscSpec;
pub const ClassSpec = qdisc.ClassSpec;
pub const Netem = qdisc.Netem;
pub const NetemWire = qdisc.NetemWire;
pub const Htb = qdisc.Htb;
pub const HtbWire = qdisc.HtbWire;
pub const HtbClass = qdisc.HtbClass;
pub const HtbClassWire = qdisc.HtbClassWire;
pub const Tbf = qdisc.Tbf;
pub const TbfWire = qdisc.TbfWire;
pub const FqCodel = qdisc.FqCodel;
pub const FqCodelWire = qdisc.FqCodelWire;
pub const Qdisc = qdisc.Qdisc;
pub const Class = qdisc.Class;
pub const TCA = qdisc.TCA;
pub const TCA_NETEM = qdisc.TCA_NETEM;
pub const TCA_HTB = qdisc.TCA_HTB;
pub const TCA_TBF = qdisc.TCA_TBF;
pub const TCA_FQ_CODEL = qdisc.TCA_FQ_CODEL;
pub const percentToU32 = qdisc.percentToU32;
pub const parseQdisc = qdisc.parseQdisc;
pub const parseClass = qdisc.parseClass;
pub const tcmsg_len = qdisc.tcmsg_len;
pub const tc_netem_qopt_len = qdisc.tc_netem_qopt_len;
pub const kind_netem = qdisc.kind_netem;

/// Filter specs and their wire readbacks.
pub const FilterSpec = filter.FilterSpec;
pub const U32 = filter.U32;
pub const U32Key = filter.U32Key;
pub const U32Wire = filter.U32Wire;
pub const Flower = filter.Flower;
pub const FlowerWire = filter.FlowerWire;
pub const Prefix4 = filter.Prefix4;
pub const Prefix6 = filter.Prefix6;
pub const Filter = filter.Filter;
pub const ETH_P = filter.ETH_P;
pub const IPPROTO = filter.IPPROTO;
pub const TCA_U32 = filter.TCA_U32;
pub const TCA_FLOWER = filter.TCA_FLOWER;
pub const parseFilter = filter.parseFilter;

/// Action specs, their wire readbacks and the `TC_ACT_*` verdicts.
pub const ActionSpec = action.ActionSpec;
pub const ActionRef = action.ActionRef;
pub const Action = action.Action;
pub const ActionList = action.ActionList;
pub const ActionIterator = action.ActionIterator;
pub const Verdict = action.Verdict;
pub const Gen = action.Gen;
pub const Gact = action.Gact;
pub const GactProb = action.GactProb;
pub const GactWire = action.GactWire;
pub const ProbType = action.ProbType;
pub const Mirred = action.Mirred;
pub const MirredAction = action.MirredAction;
pub const MirredWire = action.MirredWire;
pub const Police = action.Police;
pub const PoliceWire = action.PoliceWire;
pub const Skbedit = action.Skbedit;
pub const SkbeditWire = action.SkbeditWire;
pub const Vlan = action.Vlan;
pub const VlanAction = action.VlanAction;
pub const VlanWire = action.VlanWire;
pub const PACKET = action.PACKET;
pub const TCA_ACT = action.TCA_ACT;
pub const TCA_ACT_TAB = action.TCA_ACT_TAB;
pub const TCA_ROOT = action.TCA_ROOT;
pub const TCA_GACT = action.TCA_GACT;
pub const TCA_MIRRED = action.TCA_MIRRED;
pub const TCA_POLICE = action.TCA_POLICE;
pub const TCA_SKBEDIT = action.TCA_SKBEDIT;
pub const TCA_VLAN = action.TCA_VLAN;
pub const TCA_STATS = action.TCA_STATS;
pub const parseAction = action.parseAction;
pub const parseActionList = action.parseActionList;

/// Request construction (message types, targets, builders).
pub const Create = message.Create;
pub const QdiscTarget = message.QdiscTarget;
pub const ClassTarget = message.ClassTarget;
pub const FilterTarget = message.FilterTarget;
pub const RTM_NEWQDISC = message.RTM_NEWQDISC;
pub const RTM_DELQDISC = message.RTM_DELQDISC;
pub const RTM_GETQDISC = message.RTM_GETQDISC;
pub const RTM_NEWTCLASS = message.RTM_NEWTCLASS;
pub const RTM_DELTCLASS = message.RTM_DELTCLASS;
pub const RTM_GETTCLASS = message.RTM_GETTCLASS;
pub const RTM_NEWTFILTER = message.RTM_NEWTFILTER;
pub const RTM_DELTFILTER = message.RTM_DELTFILTER;
pub const RTM_GETTFILTER = message.RTM_GETTFILTER;
pub const RTM_NEWACTION = message.RTM_NEWACTION;
pub const RTM_DELACTION = message.RTM_DELACTION;
pub const RTM_GETACTION = message.RTM_GETACTION;

/// The handle the v1 netem shortcuts assign a root qdisc: `1:0`.
pub const netem_handle: u32 = 0x00010000;

// ── errors ──────────────────────────────────────────────────────────────────

/// Transport + kernel-errno failures, shared with `netlink` (this module maps
/// no errnos of its own any more — `netlink.writeErrorFromCode` does it).
pub const RequestError = netlink.RequestError;
/// Everything a write op can fail with: message construction + transport.
pub const WriteError = RequestError || message.BuildError;
/// A dump can additionally give up on a table that keeps changing under it.
pub const DumpError = RequestError || error{InconsistentDump};
/// The action dumps additionally build a request *body* (a kind string, an
/// index), so message construction can fail too — every other `RTM_GET*`
/// request is fixed-shape.
pub const ActionDumpError = DumpError || message.BuildError;

pub const OpenError = netlink.OpenError;
pub const BuildError = message.BuildError;
pub const SetError = WriteError; // v1 alias
pub const DelError = WriteError; // v1 alias
pub const GetError = DumpError; // v1 alias

// ── socket ──────────────────────────────────────────────────────────────────

const initial_recv_buf_len = 8192;
const max_recv_buf_len = 1 << 24;
const max_dump_attempts = 4; // NLM_F_DUMP_INTR restarts before giving up

/// A blocking tc client over one `NETLINK_ROUTE` socket. One instance per
/// thread/loop; no shared state.
pub const Socket = struct {
    gpa: std.mem.Allocator,
    /// The shared rtnetlink transport: sequence numbers, the write+ACK
    /// engine, typed errno mapping and the kernel's extended-ACK strings all
    /// come from here.
    nl: netlink.Socket,
    /// psched calibration used for every rate/burst computation. Read from
    /// `/proc/net/psched` at open time; override with `openWithPsched` to
    /// build requests for a host other than this one.
    psched: Psched,
    /// Receive buffer for dumps; grown on demand.
    buf: []u8,

    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        return openWithPsched(gpa, Psched.read());
    }

    /// Open with an explicit psched calibration (testing, or building
    /// requests destined for a different kernel).
    pub fn openWithPsched(gpa: std.mem.Allocator, ps: Psched) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("tc.Socket is Linux-only (AF_NETLINK raw syscalls)");
        var nl = try netlink.Socket.open(gpa);
        errdefer nl.close();
        const buf = try gpa.alloc(u8, initial_recv_buf_len);
        return .{ .gpa = gpa, .nl = nl, .psched = ps, .buf = buf };
    }

    pub fn close(self: *Socket) void {
        self.gpa.free(self.buf);
        self.nl.close();
        self.* = undefined;
    }

    /// The kernel's reason for the last failed write, from the extended ACK
    /// (`NLMSGERR_ATTR_MSG`) — e.g. "Specified qdisc kind is unknown". Empty
    /// when the kernel attached none. Valid until the next request.
    pub fn lastErrorMessage(self: *const Socket) []const u8 {
        return self.nl.lastErrorMessage();
    }

    // ── qdisc ops ──────────────────────────────────────────────────────────

    /// Attach a qdisc (`NLM_F_CREATE|NLM_F_EXCL` — `error.Exists` if one is
    /// already at that attach point).
    pub fn qdiscAdd(self: *Socket, target: QdiscTarget, spec: QdiscSpec) WriteError!void {
        return self.qdiscSet(.add, target, spec);
    }

    /// Create-or-replace a qdisc (`NLM_F_CREATE|NLM_F_REPLACE` — idempotent).
    pub fn qdiscReplace(self: *Socket, target: QdiscTarget, spec: QdiscSpec) WriteError!void {
        return self.qdiscSet(.replace, target, spec);
    }

    /// Modify an existing qdisc in place (no create bits).
    pub fn qdiscChange(self: *Socket, target: QdiscTarget, spec: QdiscSpec) WriteError!void {
        return self.qdiscSet(.change, target, spec);
    }

    fn qdiscSet(self: *Socket, op: Create, target: QdiscTarget, spec: QdiscSpec) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildQdiscSet(self.gpa, seq, op, target, spec, self.psched);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Remove a qdisc, reverting the attach point to its default.
    pub fn qdiscDel(self: *Socket, target: QdiscTarget) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildQdiscDel(self.gpa, seq, target);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Dump every qdisc on an interface (root plus any leaves). Caller owns
    /// the slice (`gpa.free`).
    pub fn qdiscs(self: *Socket, ifindex: u32) DumpError![]Qdisc {
        return self.dump(Qdisc, qdisc.parseQdisc, RTM_GETQDISC, RTM_NEWQDISC, ifindex, null, .exact);
    }

    // ── class ops ──────────────────────────────────────────────────────────

    pub fn classAdd(self: *Socket, target: ClassTarget, spec: ClassSpec) WriteError!void {
        return self.classSet(.add, target, spec);
    }

    pub fn classReplace(self: *Socket, target: ClassTarget, spec: ClassSpec) WriteError!void {
        return self.classSet(.replace, target, spec);
    }

    pub fn classChange(self: *Socket, target: ClassTarget, spec: ClassSpec) WriteError!void {
        return self.classSet(.change, target, spec);
    }

    fn classSet(self: *Socket, op: Create, target: ClassTarget, spec: ClassSpec) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildClassSet(self.gpa, seq, op, target, spec, self.psched);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Delete a class. `target.parent` may stay `unspec` — the kernel finds
    /// the parent from the class id, which is what `tc class del` sends.
    pub fn classDel(self: *Socket, target: ClassTarget) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildClassDel(self.gpa, seq, target);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Dump classes on an interface. The kernel dumps **every** class of the
    /// ifindex regardless of what the request asked for, so `parent` filters
    /// client-side:
    ///
    /// * a **qdisc** handle (`1:`) keeps every class of that qdisc, matched
    ///   on the class id's major — which is how `tc class show … parent 1:`
    ///   does it, and the only workable rule: a classful qdisc reports
    ///   `tcm_parent = TC_H_ROOT` for its top-level classes, not the qdisc
    ///   handle;
    /// * a **class** handle (`1:10`) keeps that class's direct children,
    ///   matched on `tcm_parent`;
    /// * null keeps everything.
    pub fn classes(self: *Socket, ifindex: u32, parent: ?Handle) DumpError![]Class {
        return self.dump(Class, qdisc.parseClass, RTM_GETTCLASS, RTM_NEWTCLASS, ifindex, parent, .class_scope);
    }

    // ── filter ops ─────────────────────────────────────────────────────────

    pub fn filterAdd(self: *Socket, target: FilterTarget, spec: FilterSpec) WriteError!void {
        return self.filterSet(.add, target, spec);
    }

    pub fn filterReplace(self: *Socket, target: FilterTarget, spec: FilterSpec) WriteError!void {
        return self.filterSet(.replace, target, spec);
    }

    pub fn filterChange(self: *Socket, target: FilterTarget, spec: FilterSpec) WriteError!void {
        return self.filterSet(.change, target, spec);
    }

    fn filterSet(self: *Socket, op: Create, target: FilterTarget, spec: FilterSpec) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildFilterSetWith(self.gpa, seq, op, target, spec, self.psched);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Delete a filter, matched on (parent, prio, protocol, handle).
    /// `kind` is optional and usually null — `tc filter del` omits it too.
    pub fn filterDel(self: *Socket, target: FilterTarget, kind: ?[]const u8) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildFilterDel(self.gpa, seq, target, kind);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Dump filters on an interface, optionally scoped to one attach point.
    /// Filters *do* report the attach point they were installed on, so
    /// `parent` is matched exactly (same rule `tc filter show … parent 1:`
    /// applies).
    pub fn filters(self: *Socket, ifindex: u32, parent: ?Handle) DumpError![]Filter {
        return self.dump(Filter, filter.parseFilter, RTM_GETTFILTER, RTM_NEWTFILTER, ifindex, parent, .exact);
    }

    // ── standalone action ops (the shared action table) ────────────────────

    /// Install one or more actions in the shared table
    /// (`tc actions add action …`, `NLM_F_CREATE|NLM_F_EXCL`). Each spec's
    /// `index` picks its slot; 0 lets the kernel allocate one.
    pub fn actionAdd(self: *Socket, specs: []const ActionSpec) WriteError!void {
        return self.actionSet(.add, specs);
    }

    /// Create-or-replace (`tc actions replace`).
    pub fn actionReplace(self: *Socket, specs: []const ActionSpec) WriteError!void {
        return self.actionSet(.replace, specs);
    }

    /// Modify existing table entries only (`tc actions change`).
    pub fn actionChange(self: *Socket, specs: []const ActionSpec) WriteError!void {
        return self.actionSet(.change, specs);
    }

    fn actionSet(self: *Socket, op: Create, specs: []const ActionSpec) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildActionSet(self.gpa, seq, op, specs, self.psched);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Delete shared-table actions by `(kind, index)`
    /// (`tc actions del action gact index 1`).
    pub fn actionDel(self: *Socket, refs: []const ActionRef) WriteError!void {
        const seq = self.nl.nextSeq();
        const req = try message.buildActionDel(self.gpa, seq, refs);
        defer self.gpa.free(req);
        return self.nl.requestAck(req, seq);
    }

    /// Dump every shared-table action of one kind (`tc actions ls action
    /// gact`). Caller owns the slice (`gpa.free`). Needs no privilege.
    pub fn actions(self: *Socket, kind: []const u8) ActionDumpError![]Action {
        var attempt: usize = 0;
        retry: while (true) {
            attempt += 1;
            const seq = self.nl.nextSeq();
            const req = try message.buildActionDump(self.gpa, seq, kind);
            defer self.gpa.free(req);
            try self.send(req);

            var out: std.ArrayList(Action) = .empty;
            errdefer out.deinit(self.gpa);
            while (true) {
                const dgram = try self.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    if (m.pid != self.nl.portid or m.seq != seq) continue;
                    if (m.flags & codec.NLM_F_DUMP_INTR != 0) {
                        out.deinit(self.gpa);
                        if (attempt < max_dump_attempts) continue :retry;
                        return error.InconsistentDump;
                    }
                    switch (m.type) {
                        codec.NLMSG_DONE => return out.toOwnedSlice(self.gpa),
                        codec.NLMSG_ERROR => {
                            const code = m.errorCode() catch return error.MalformedReply;
                            if (code == 0) return out.toOwnedSlice(self.gpa); // ACK
                            return netlink.writeErrorFromCode(code);
                        },
                        codec.NLMSG_NOOP => {},
                        codec.NLMSG_OVERRUN => return error.SystemResources,
                        else => {
                            if (m.type != RTM_NEWACTION) continue;
                            // One RTM_NEWACTION carries the whole table slice,
                            // so the messages are flattened into one list.
                            var acts = (action.actionsOf(m.payload) catch
                                return error.MalformedReply) orelse continue;
                            while (acts.next() catch return error.MalformedReply) |a|
                                try out.append(self.gpa, a);
                        },
                    }
                }
            }
        }
    }

    /// Read back one shared-table action (`tc actions get action gact index
    /// 1`). The reply is a single `RTM_NEWACTION`, not a dump; null means the
    /// kernel answered with an empty table.
    pub fn actionGet(self: *Socket, ref: ActionRef) ActionDumpError!?Action {
        const seq = self.nl.nextSeq();
        const req = try message.buildActionGet(self.gpa, seq, &.{ref});
        defer self.gpa.free(req);
        try self.send(req);
        while (true) {
            const dgram = try self.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != self.nl.portid or m.seq != seq) continue;
                switch (m.type) {
                    codec.NLMSG_ERROR => {
                        const code = m.errorCode() catch return error.MalformedReply;
                        if (code != 0) return netlink.writeErrorFromCode(code);
                        return null; // a bare ACK carries no action
                    },
                    codec.NLMSG_DONE => return null,
                    codec.NLMSG_NOOP => {},
                    codec.NLMSG_OVERRUN => return error.SystemResources,
                    RTM_NEWACTION => {
                        var acts = (action.actionsOf(m.payload) catch
                            return error.MalformedReply) orelse return null;
                        return acts.next() catch return error.MalformedReply;
                    },
                    else => {},
                }
            }
        }
    }

    // ── v1 netem shortcuts (source-compatible) ─────────────────────────────

    /// Attach a netem root qdisc with handle `1:0` (`NLM_F_CREATE|NLM_F_EXCL`).
    pub fn add(self: *Socket, ifindex: u32, netem: Netem) WriteError!void {
        return self.qdiscAdd(netemTarget(ifindex), .{ .netem = netem });
    }

    /// Create-or-replace the root qdisc with a new netem config.
    pub fn change(self: *Socket, ifindex: u32, netem: Netem) WriteError!void {
        return self.qdiscReplace(netemTarget(ifindex), .{ .netem = netem });
    }

    /// Remove the root qdisc.
    pub fn del(self: *Socket, ifindex: u32) WriteError!void {
        return self.qdiscDel(netemTarget(ifindex));
    }

    /// The root qdisc of `ifindex` (every interface always has one), or null
    /// when the interface reports nothing.
    pub fn show(self: *Socket, ifindex: u32) DumpError!?Qdisc {
        const list = try self.qdiscs(ifindex);
        defer self.gpa.free(list);
        var found: ?Qdisc = null;
        for (list) |q| {
            if (q.parent.isRoot() or q.handle.raw == netem_handle) return q;
            found = q;
        }
        return found;
    }

    fn netemTarget(ifindex: u32) QdiscTarget {
        return .{
            .ifindex = ifindex,
            .handle = Handle.fromRaw(netem_handle),
            .parent = Handle.root,
        };
    }

    // ── the dump engine ────────────────────────────────────────────────────

    /// DRY candidate: `netlink.Socket` publishes `nextSeq`/`requestAck`/
    /// `lastErrorMessage` for the **write** path, but its multi-part dump
    /// engine is private and generic over its own parse/match callbacks, and
    /// it exposes no raw `send`/`recvDatagram` pair (the sibling
    /// `genetlink.Socket` does). Until it grows one, tc drives the shared
    /// socket's fd directly here. Everything else — sequence numbers, errno
    /// mapping, ext-ACK — stays in `netlink`.
    /// How a dump's `parent` filter is applied client-side (see `classes`).
    const ParentMatch = enum { exact, class_scope };

    fn parentMatches(comptime mode: ParentMatch, want: Handle, item_parent: Handle, item_handle: Handle) bool {
        return switch (mode) {
            .exact => item_parent.raw == want.raw,
            .class_scope => if (want.minor() == 0 and !want.isRoot() and !want.isIngress())
                item_handle.major() == want.major()
            else
                item_parent.raw == want.raw,
        };
    }

    fn dump(
        self: *Socket,
        comptime T: type,
        comptime parseFn: fn ([]const u8) codec.Error!T,
        msg_type: u16,
        reply_type: u16,
        ifindex: u32,
        parent: ?Handle,
        comptime mode: ParentMatch,
    ) DumpError![]T {
        var attempt: usize = 0;
        retry: while (true) {
            attempt += 1;
            const seq = self.nl.nextSeq();
            const req = try message.buildDump(
                self.gpa,
                seq,
                msg_type,
                ifindex,
                parent orelse Handle.unspec,
            );
            defer self.gpa.free(req);
            try self.send(req);

            var out: std.ArrayList(T) = .empty;
            errdefer out.deinit(self.gpa);
            while (true) {
                const dgram = try self.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    if (m.pid != self.nl.portid or m.seq != seq) continue;
                    if (m.flags & codec.NLM_F_DUMP_INTR != 0) {
                        out.deinit(self.gpa);
                        if (attempt < max_dump_attempts) continue :retry;
                        return error.InconsistentDump;
                    }
                    switch (m.type) {
                        codec.NLMSG_DONE => return out.toOwnedSlice(self.gpa),
                        codec.NLMSG_ERROR => {
                            const code = m.errorCode() catch return error.MalformedReply;
                            if (code == 0) return out.toOwnedSlice(self.gpa); // ACK
                            return netlink.writeErrorFromCode(code);
                        },
                        codec.NLMSG_NOOP => {},
                        codec.NLMSG_OVERRUN => return error.SystemResources,
                        else => {
                            if (m.type != reply_type) continue;
                            const item = parseFn(m.payload) catch return error.MalformedReply;
                            if (item.ifindex != ifindex) continue;
                            if (parent) |p| {
                                if (!parentMatches(mode, p, item.parent, item.handle)) continue;
                            }
                            try out.append(self.gpa, item);
                        },
                    }
                }
            }
        }
    }

    fn send(self: *Socket, msg: []const u8) DumpError!void {
        const dst: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
        while (true) {
            const rc = linux.sendto(
                self.nl.fd,
                msg.ptr,
                msg.len,
                0,
                @ptrCast(&dst),
                @sizeOf(linux.sockaddr.nl),
            );
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                .ACCES, .PERM => return error.AccessDenied,
                else => return error.SendFailed,
            }
        }
    }

    fn recvDatagram(self: *Socket) DumpError![]const u8 {
        while (true) {
            // MSG_PEEK|MSG_TRUNC reports the true datagram size without
            // consuming it, so nothing is ever lost to truncation.
            const prc = linux.recvfrom(
                self.nl.fd,
                self.buf.ptr,
                self.buf.len,
                linux.MSG.PEEK | linux.MSG.TRUNC,
                null,
                null,
            );
            switch (linux.errno(prc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            if (prc > self.buf.len) {
                if (prc > max_recv_buf_len) return error.MalformedReply;
                const new_len = std.mem.alignForward(usize, prc, initial_recv_buf_len);
                self.buf = self.gpa.realloc(self.buf, new_len) catch return error.OutOfMemory;
                continue;
            }

            var src: linux.sockaddr.nl = .{ .pid = 0, .groups = 0 };
            var slen: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
            const rc = linux.recvfrom(self.nl.fd, self.buf.ptr, self.buf.len, 0, @ptrCast(&src), &slen);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                .NOBUFS, .NOMEM => return error.SystemResources,
                else => return error.RecvFailed,
            }
            // rtnetlink answers only ever come from the kernel, and any user
            // process may address our port id.
            if (slen >= @sizeOf(linux.sockaddr.nl) and src.pid != 0) continue;
            return self.buf[0..rc];
        }
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "re-exports keep the v1 surface addressable" {
    try testing.expectEqual(@as(u32, 0x00010000), netem_handle);
    try testing.expectEqual(@as(u32, 0xFFFFFFFF), TC_H_ROOT);
    try testing.expectEqual(@as(u16, 36), RTM_NEWQDISC);
    try testing.expectEqual(@as(u16, 37), RTM_DELQDISC);
    try testing.expectEqual(@as(u16, 38), RTM_GETQDISC);
    try testing.expectEqual(@as(usize, 20), tcmsg_len);
    try testing.expectEqual(@as(usize, 24), tc_netem_qopt_len);
    try testing.expectEqualStrings("netem", kind_netem);
    try testing.expectEqual(@as(u32, 42949673), try percentToU32(1.0));
}

test "netem v1 request shape is unchanged (root qdisc, handle 1:0)" {
    const req = try message.buildQdiscSet(
        testing.allocator,
        1,
        .add,
        .{ .ifindex = 5, .handle = Handle.fromRaw(netem_handle), .parent = Handle.root },
        .{ .netem = .{ .delay_ns = 100 * std.time.ns_per_ms, .loss_pct = 1.0 } },
        Psched.fallback,
    );
    defer testing.allocator.free(req);
    var it: codec.MessageIterator = .{ .buf = req };
    const m = (try it.next()).?;
    try testing.expectEqual(RTM_NEWQDISC, m.type);
    const q = try parseQdisc(m.payload);
    try testing.expectEqual(@as(u32, 5), q.ifindex);
    try testing.expectEqual(netem_handle, q.handle.raw);
    try testing.expect(q.parent.isRoot());
    try testing.expectEqualStrings("netem", q.kind());
    try testing.expectEqual(@as(i64, 100 * std.time.ns_per_ms), q.netem.?.delay_ns);
    try testing.expectEqual(try percentToU32(1.0), q.netem.?.loss);
}

test "netem encode/decode round-trip through the full option set" {
    const netem: Netem = .{
        .limit = 500,
        .delay_ns = 50_000_000,
        .jitter_ns = 5_000_000,
        .delay_correlation_pct = 25.0,
        .loss_pct = 2.5,
        .loss_correlation_pct = 10.0,
        .duplicate_pct = 0.5,
        .reorder_pct = 1.0,
        .reorder_correlation_pct = 50.0,
        .reorder_gap = 5,
        .corrupt_pct = 0.1,
        .rate_bytes_per_sec = 125_000,
    };
    const req = try message.buildQdiscSet(
        testing.allocator,
        1,
        .add,
        .{ .ifindex = 42, .handle = Handle.fromRaw(netem_handle) },
        .{ .netem = netem },
        Psched.fallback,
    );
    defer testing.allocator.free(req);

    const q = try parseQdisc(req[codec.header_len..]);
    const nw = q.netem.?;
    try testing.expectEqual(@as(u32, 500), nw.limit);
    try testing.expectEqual(@as(u32, 5), nw.gap);
    try testing.expectEqual(try percentToU32(2.5), nw.loss);
    try testing.expectEqual(try percentToU32(0.5), nw.duplicate);
    try testing.expectEqual(@as(i64, 50_000_000), nw.delay_ns);
    try testing.expectEqual(@as(i64, 5_000_000), nw.jitter_ns);
    try testing.expectEqual(try percentToU32(25.0), nw.delay_correlation);
    try testing.expectEqual(try percentToU32(10.0), nw.loss_correlation);
    try testing.expectEqual(try percentToU32(1.0), nw.reorder_probability);
    try testing.expectEqual(try percentToU32(50.0), nw.reorder_correlation);
    try testing.expectEqual(try percentToU32(0.1), nw.corrupt_probability);
    try testing.expectEqual(@as(u32, 125_000), nw.rate_bytes_per_sec);
}

test "zero-config netem omits every optional attribute" {
    const req = try message.buildQdiscSet(
        testing.allocator,
        1,
        .add,
        .{ .ifindex = 1, .handle = Handle.fromRaw(netem_handle) },
        .{ .netem = .{} },
        Psched.fallback,
    );
    defer testing.allocator.free(req);
    // header(16) + tcmsg(20) + TCA_KIND(12) + TCA_OPTIONS hdr(4) + qopt(24)
    try testing.expectEqual(@as(usize, 16 + 20 + 12 + 4 + 24), req.len);
    const q = try parseQdisc(req[codec.header_len..]);
    try testing.expectEqual(@as(u32, 1000), q.netem.?.limit); // Netem{} default
}

test "netem input validation happens before any allocation" {
    const gpa = testing.allocator;
    const target: QdiscTarget = .{ .ifindex = 1 };
    try testing.expectError(error.InvalidPercent, message.buildQdiscSet(
        gpa,
        1,
        .add,
        target,
        .{ .netem = .{ .loss_pct = 150 } },
        Psched.fallback,
    ));
    const too_big: u64 = @as(u64, std.math.maxInt(i64)) + 1;
    try testing.expectError(error.InvalidDelay, message.buildQdiscSet(
        gpa,
        1,
        .add,
        target,
        .{ .netem = .{ .delay_ns = too_big } },
        Psched.fallback,
    ));
    try testing.expectError(error.InvalidDelay, message.buildQdiscSet(
        gpa,
        1,
        .add,
        target,
        .{ .netem = .{ .jitter_ns = too_big } },
        Psched.fallback,
    ));
    // maxInt(i64) is still legal.
    const ok = try message.buildQdiscSet(
        gpa,
        1,
        .add,
        target,
        .{ .netem = .{ .delay_ns = std.math.maxInt(i64), .jitter_ns = 10_000_000 } },
        Psched.fallback,
    );
    gpa.free(ok);
}

test "errno mapping is netlink's (the tc-local copy is gone)" {
    // The v1 module carried its own errnoToError; the shared one must keep
    // the exact same mappings for every code tc can provoke.
    try testing.expectEqual(error.AccessDenied, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.PERM))));
    try testing.expectEqual(error.Exists, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.EXIST))));
    try testing.expectEqual(error.NotFound, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NOENT))));
    try testing.expectEqual(error.NoSuchDevice, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NODEV))));
    try testing.expectEqual(error.InvalidRequest, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.INVAL))));
    try testing.expectEqual(error.NotSupported, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.OPNOTSUPP))));
    try testing.expectEqual(error.SystemResources, netlink.writeErrorFromCode(-@as(i32, @intFromEnum(linux.E.NOBUFS))));
    try testing.expectEqual(error.Unexpected, netlink.writeErrorFromCode(-9999));
    try testing.expectEqual(error.Unexpected, netlink.writeErrorFromCode(0));
    try testing.expectEqual(error.Unexpected, netlink.writeErrorFromCode(std.math.minInt(i32)));
}

test "fuzz: parseQdisc never crashes on arbitrary payloads" {
    try testing.fuzz({}, fuzzParseQdisc, .{});
}

fn fuzzParseQdisc(_: void, smith: *std.testing.Smith) !void {
    var raw: [256]u8 = undefined;
    smith.bytes(&raw);
    const len = smith.valueRangeAtMost(u16, 0, raw.len);
    if (parseQdisc(raw[0..len])) |_| {} else |_| {}
}

// ── integration tests (real kernel, live netns round-trip) ──────────────────
//
// Every write op needs CAP_NET_ADMIN; the dumps do not. Run unprivileged
// under a network namespace to touch no host state:
//
//     unshare -rn zig build test-tc
//
// Without the capability the write ops return error.AccessDenied and each
// test prints `SKIPPED: …` and passes — the repo's env-gated pattern (see
// `netlink`/`wireguard`/`rawsock`).

fn skip(comptime what: []const u8) error{SkipZigTest} {
    std.debug.print("SKIPPED: {s} (needs CAP_NET_ADMIN in a netns: `unshare -rn zig build test-tc`)\n", .{what});
    return error.SkipZigTest;
}

/// The stronger requirement of the standalone action family: the kernel
/// checks `CAP_NET_ADMIN` against the **initial** user namespace there, so a
/// `unshare -rn` namespace does not grant it.
fn skipInitUserns(comptime what: []const u8) error{SkipZigTest} {
    std.debug.print(
        "SKIPPED: {s} (needs CAP_NET_ADMIN in the *initial* user namespace — " ++
            "`unshare -rn` is not enough for RTM_NEWACTION; try `sudo unshare -n`)\n",
        .{what},
    );
    return error.SkipZigTest;
}

fn openOrSkip() !Socket {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    return Socket.open(testing.allocator) catch return skip("tc.Socket.open");
}

/// The ifindex of `lo`, via the sibling netlink module — brought admin-up on
/// the way, because a fresh `unshare -rn` namespace starts with `lo` DOWN and
/// the kernel reports **no qdisc at all** for a down interface. On a host
/// where `lo` is already up (and we have no privileges) the admin-up fails
/// harmlessly.
fn loIndex(sock: *Socket) !u32 {
    const links = sock.nl.links() catch return skip("RTM_GETLINK dump");
    defer testing.allocator.free(links);
    for (links) |l| {
        if (!std.mem.eql(u8, l.name(), "lo")) continue;
        sock.nl.linkUp(l.index) catch {};
        return l.index;
    }
    return skip("no `lo` interface");
}

test "integration: qdiscs() on lo needs no privilege and reports a root qdisc" {
    var sock = try openOrSkip();
    defer sock.close();
    const lo = try loIndex(&sock);

    const list = sock.qdiscs(lo) catch |e| switch (e) {
        error.AccessDenied => return skip("RTM_GETQDISC dump"),
        else => return e,
    };
    defer testing.allocator.free(list);
    // A down interface has no qdisc at all; `loIndex` brings `lo` up when it
    // can, so an empty list here means we are unprivileged in a fresh netns.
    if (list.len == 0) return skip("lo has no qdisc (interface is down)");
    for (list) |q| {
        try testing.expectEqual(lo, q.ifindex);
        try testing.expect(q.kind().len > 0); // "noqueue" by default on lo
    }
}

test "integration (netns/root): netem v1 add + show + change + del round-trip" {
    var sock = try openOrSkip();
    defer sock.close();
    const lo = try loIndex(&sock);

    // Best-effort cleanup after an aborted earlier run.
    sock.del(lo) catch {};

    const netem1: Netem = .{
        .delay_ns = 100 * std.time.ns_per_ms,
        .jitter_ns = 10 * std.time.ns_per_ms,
        .loss_pct = 1.0,
    };
    sock.add(lo, netem1) catch |e| switch (e) {
        error.AccessDenied => return skip("netem qdisc add"),
        else => return e,
    };
    defer sock.del(lo) catch {};

    {
        const q = (try sock.show(lo)).?;
        try testing.expectEqualStrings("netem", q.kind());
        const nw = q.netem.?;
        try testing.expectEqual(@as(i64, 100 * std.time.ns_per_ms), nw.delay_ns);
        try testing.expectEqual(@as(i64, 10 * std.time.ns_per_ms), nw.jitter_ns);
        try testing.expectEqual(try percentToU32(1.0), nw.loss);
    }

    try sock.change(lo, .{ .delay_ns = 20 * std.time.ns_per_ms, .duplicate_pct = 5.0 });
    {
        const q = (try sock.show(lo)).?;
        try testing.expectEqualStrings("netem", q.kind());
        const nw = q.netem.?;
        try testing.expectEqual(@as(i64, 20 * std.time.ns_per_ms), nw.delay_ns);
        try testing.expectEqual(@as(i64, 0), nw.jitter_ns);
        try testing.expectEqual(try percentToU32(5.0), nw.duplicate);
        try testing.expectEqual(@as(u32, 0), nw.loss);
    }

    try sock.del(lo);
    {
        const q = (try sock.show(lo)).?;
        try testing.expect(!std.mem.eql(u8, q.kind(), "netem"));
    }
}

test "integration (netns/root): htb qdisc + classes + u32/flower filters + dumps" {
    var sock = try openOrSkip();
    defer sock.close();
    const lo = try loIndex(&sock);

    const one: Handle = .init(1, 0);
    const leaf: Handle = .init(1, 0x10);
    const leaf2: Handle = .init(1, 0x20);

    sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};

    sock.qdiscAdd(
        .{ .ifindex = lo, .handle = one, .parent = Handle.root },
        .{ .htb = .{ .defcls = 0x10 } },
    ) catch |e| switch (e) {
        error.AccessDenied => return skip("htb qdisc add"),
        else => return e,
    };
    defer sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};

    // The qdisc came back with the kind and handle we asked for.
    {
        const list = try sock.qdiscs(lo);
        defer testing.allocator.free(list);
        var seen = false;
        for (list) |q| {
            if (q.handle.raw != one.raw) continue;
            seen = true;
            try testing.expectEqualStrings("htb", q.kind());
            const h = q.htb.?;
            // The kernel dumps its full `HTB_VER` (0x30011); only the high
            // half is the protocol version tc sends (3).
            try testing.expectEqual(@as(u32, 3), h.version >> 16);
            try testing.expectEqual(@as(u32, 0x10), h.defcls);
        }
        try testing.expect(seen);
    }

    // Two classes: a 32-bit rate and one that needs TCA_HTB_RATE64.
    try sock.classAdd(
        .{ .ifindex = lo, .handle = leaf, .parent = one },
        .{ .htb = .{ .rate = 125_000, .ceil = 250_000 } },
    );
    try sock.classAdd(
        .{ .ifindex = lo, .handle = leaf2, .parent = one },
        .{ .htb = .{ .rate = 5_000_000_000, .ceil = 10_000_000_000 } },
    );

    {
        const list = try sock.classes(lo, one);
        defer testing.allocator.free(list);
        try testing.expectEqual(@as(usize, 2), list.len);
        for (list) |c| {
            try testing.expectEqualStrings("htb", c.kind());
            // htb (like every classful qdisc) reports TC_H_ROOT as the parent
            // of a top-level class, not the qdisc handle — which is exactly
            // why `classes()` scopes by the class id's major instead.
            try testing.expect(c.parent.isRoot());
            try testing.expectEqual(one.major(), c.handle.major());
            const h = c.htb.?;
            if (c.handle.raw == leaf.raw) {
                try testing.expectEqual(@as(u64, 125_000), h.rate64);
                try testing.expectEqual(@as(u64, 250_000), h.ceil64);
            } else {
                try testing.expectEqual(leaf2.raw, c.handle.raw);
                // The kernel echoes the 64-bit rate back through RATE64.
                try testing.expectEqual(@as(u64, 5_000_000_000), h.rate64);
                try testing.expectEqual(@as(u64, 10_000_000_000), h.ceil64);
            }
        }
    }

    // A leaf qdisc under a class (parent = the class handle).
    try sock.qdiscAdd(
        .{ .ifindex = lo, .handle = .init(0x20, 0), .parent = leaf },
        .{ .fq_codel = .{ .limit = 1200, .target_us = 5_000 } },
    );
    {
        const list = try sock.qdiscs(lo);
        defer testing.allocator.free(list);
        var seen = false;
        for (list) |q| {
            if (!std.mem.eql(u8, q.kind(), "fq_codel")) continue;
            seen = true;
            try testing.expectEqual(leaf.raw, q.parent.raw);
            try testing.expectEqual(@as(?u32, 1200), q.fq_codel.?.limit);
        }
        try testing.expect(seen);
    }

    // u32 + flower filters at two priorities.
    const keys = [_]U32Key{U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32)};
    try sock.filterAdd(
        .{ .ifindex = lo, .parent = one, .prio = 1, .eth_type = ETH_P.IP },
        .{ .u32 = .{ .classid = leaf, .keys = &keys } },
    );
    try sock.filterAdd(
        .{ .ifindex = lo, .parent = one, .prio = 2, .eth_type = ETH_P.IP },
        .{ .flower = .{
            .eth_type = ETH_P.IP,
            .ip_proto = IPPROTO.TCP,
            .ipv4_dst = .{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 24 },
            .dst_port = 80,
            .classid = leaf2,
        } },
    );

    {
        const list = try sock.filters(lo, one);
        defer testing.allocator.free(list);
        var saw_u32 = false;
        var saw_flower = false;
        for (list) |f| {
            try testing.expectEqual(one.raw, f.parent.raw);
            // A dump also carries bookkeeping entries with no classid: a bare
            // per-(chain, protocol, prio) header for every classifier, plus
            // u32's auto-created hash table. Only the real filters carry the
            // class they select.
            if (f.classid() == null) continue;
            if (std.mem.eql(u8, f.kind(), "u32")) {
                saw_u32 = true;
                try testing.expectEqual(@as(u16, 1), f.prio);
                try testing.expectEqual(ETH_P.IP, f.eth_type);
                try testing.expectEqual(leaf.raw, f.classid().?.raw);
                const u = f.u32_sel.?;
                try testing.expectEqual(@as(u8, 1), u.nkeys);
                try testing.expectEqual(@as(i32, 16), u.keys[0].off);
                try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &u.keys[0].val);
            } else if (std.mem.eql(u8, f.kind(), "flower")) {
                saw_flower = true;
                try testing.expectEqual(@as(u16, 2), f.prio);
                try testing.expectEqual(ETH_P.IP, f.eth_type);
                try testing.expectEqual(leaf2.raw, f.classid().?.raw);
                const fl = f.flower.?;
                try testing.expectEqual(IPPROTO.TCP, fl.ip_proto.?);
                try testing.expectEqual(@as(u16, 80), fl.dst_port.?);
                try testing.expectEqualSlices(u8, &.{ 255, 255, 255, 0 }, &fl.ipv4_dst_mask.?);
            }
        }
        try testing.expect(saw_u32);
        try testing.expect(saw_flower);
    }

    // Delete the flower filter, then a class, and watch both disappear.
    try sock.filterDel(
        .{ .ifindex = lo, .parent = one, .prio = 2, .eth_type = ETH_P.IP },
        null,
    );
    {
        const list = try sock.filters(lo, one);
        defer testing.allocator.free(list);
        for (list) |f| try testing.expect(!std.mem.eql(u8, f.kind(), "flower"));
    }

    try sock.classDel(.{ .ifindex = lo, .handle = leaf2, .parent = Handle.unspec });
    {
        const list = try sock.classes(lo, one);
        defer testing.allocator.free(list);
        for (list) |c| try testing.expect(c.handle.raw != leaf2.raw);
    }
}

test "integration (netns/root): filter action list add + dump-decode + del" {
    var sock = try openOrSkip();
    defer sock.close();
    const lo = try loIndex(&sock);

    const one: Handle = .init(1, 0);
    const leaf: Handle = .init(1, 0x10);

    sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};
    sock.qdiscAdd(
        .{ .ifindex = lo, .handle = one, .parent = Handle.root },
        .{ .htb = .{ .defcls = 0x10 } },
    ) catch |e| switch (e) {
        error.AccessDenied => return skip("htb qdisc add (action round-trip)"),
        else => return e,
    };
    defer sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};
    try sock.classAdd(
        .{ .ifindex = lo, .handle = leaf, .parent = one },
        .{ .htb = .{ .rate = 125_000 } },
    );

    // prio 1: a two-action PIPE chain — skbedit hands over to a policer.
    const keys = [_]U32Key{U32Key.ipv4Src(.{ 10, 0, 0, 1 }, 32)};
    try sock.filterAdd(
        .{ .ifindex = lo, .parent = one, .prio = 1, .eth_type = ETH_P.IP },
        .{ .u32 = .{ .classid = leaf, .keys = &keys, .actions = &.{
            .{ .skbedit = .{ .mark = 7, .action = .pipe } },
            .{ .police = .{ .rate = 125_000, .burst = 10 * 1024, .exceed = .shot } },
        } } },
    );
    // prio 2: flower + mirred, a single-action list on the other classifier.
    try sock.filterAdd(
        .{ .ifindex = lo, .parent = one, .prio = 2, .eth_type = ETH_P.IP },
        .{ .flower = .{
            .eth_type = ETH_P.IP,
            .ip_proto = IPPROTO.TCP,
            .dst_port = 80,
            .classid = leaf,
            .actions = &.{.{ .mirred = .{ .eaction = .egress_mirror, .ifindex = lo } }},
        } },
    );

    {
        const list = try sock.filters(lo, one);
        defer testing.allocator.free(list);
        var saw_chain = false;
        var saw_mirred = false;
        for (list) |f| {
            const acts = f.actions();
            if (acts.len == 0) continue;
            if (std.mem.eql(u8, f.kind(), "u32")) {
                saw_chain = true;
                try testing.expectEqual(@as(usize, 2), acts.len);
                // Ordinals survive the round-trip in order.
                try testing.expectEqual(@as(u16, 1), acts[0].order);
                try testing.expectEqual(@as(u16, 2), acts[1].order);
                try testing.expectEqualStrings("skbedit", acts[0].kind());
                try testing.expectEqual(Verdict.pipe, acts[0].gen.action);
                try testing.expectEqual(@as(u32, 7), acts[0].skbedit.?.mark.?);
                try testing.expectEqualStrings("police", acts[1].kind());
                const p = acts[1].police.?;
                try testing.expectEqual(@as(u64, 125_000), p.rate64);
                try testing.expectEqual(Verdict.shot, p.exceed);
                // The kernel echoes the burst back in psched ticks; converting
                // it back must land on the 10 KiB we asked for.
                try testing.expectEqual(
                    @as(u64, 10 * 1024),
                    sock.psched.calcXmitSize(125_000, p.burst),
                );
                // Every installed action is refcounted and carries counters.
                try testing.expect(acts[0].gen.refcnt > 0);
                try testing.expect(acts[0].stats != null);
            } else if (std.mem.eql(u8, f.kind(), "flower")) {
                saw_mirred = true;
                try testing.expectEqual(@as(usize, 1), acts.len);
                try testing.expectEqualStrings("mirred", acts[0].kind());
                try testing.expectEqual(
                    MirredAction.egress_mirror,
                    acts[0].mirred.?.eaction,
                );
                try testing.expectEqual(lo, acts[0].mirred.?.ifindex);
                try testing.expectEqual(Verdict.pipe, acts[0].gen.action);
            }
        }
        try testing.expect(saw_chain);
        try testing.expect(saw_mirred);
    }

    try sock.filterDel(
        .{ .ifindex = lo, .parent = one, .prio = 1, .eth_type = ETH_P.IP },
        null,
    );
    {
        const list = try sock.filters(lo, one);
        defer testing.allocator.free(list);
        for (list) |f| try testing.expect(f.prio != 1);
    }
}

test "integration: the RTM_GETACTION dump needs no privilege" {
    var sock = try openOrSkip();
    defer sock.close();
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    // Exercises the whole standalone path — tcamsg body, LARGE_DUMP_ON, the
    // multi-part receive loop and the TCA_ACT_TAB decode — against a live
    // kernel. An empty shared table answers ENOENT rather than an empty dump.
    if (sock.actions("gact")) |list| {
        defer testing.allocator.free(list);
        for (list) |a| {
            try testing.expectEqualStrings("gact", a.kind());
            try testing.expect(a.order >= 1); // ordinals are 1-based
        }
    } else |e| switch (e) {
        error.NotFound => {},
        error.AccessDenied => return skip("RTM_GETACTION dump"),
        else => return e,
    }
}

test "integration (root, init userns): the shared action table (add, ls, get, del)" {
    var sock = try openOrSkip();
    defer sock.close();
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const slot: u32 = 77;
    sock.actionDel(&.{.{ .kind = "gact", .index = slot }}) catch {};
    sock.actionAdd(&.{
        .{ .gact = .{ .action = .shot, .index = slot } },
    }) catch |e| switch (e) {
        // Unlike qdiscs/classes/filters, the kernel guards the shared action
        // table with `netlink_capable` (act_api.c `tc_ctl_action`), not
        // `netlink_net_capable`: the capability is checked against the
        // **initial** user namespace, so `unshare -rn` is not enough. Real
        // root is. The dump above is unrestricted and covers the decode.
        error.AccessDenied => return skipInitUserns("tc actions add"),
        else => return e,
    };
    defer sock.actionDel(&.{.{ .kind = "gact", .index = slot }}) catch {};

    {
        const list = try sock.actions("gact");
        defer testing.allocator.free(list);
        var seen = false;
        for (list) |a| {
            if (a.gen.index != slot) continue;
            seen = true;
            try testing.expectEqualStrings("gact", a.kind());
            try testing.expectEqual(Verdict.shot, a.gen.action);
            try testing.expect(a.stats != null);
        }
        try testing.expect(seen);
    }

    // The single-object GET form (tcamsg + kind + index, no NLM_F_DUMP).
    const got = (try sock.actionGet(.{ .kind = "gact", .index = slot })).?;
    try testing.expectEqualStrings("gact", got.kind());
    try testing.expectEqual(slot, got.gen.index);
    try testing.expectEqual(Verdict.shot, got.gen.action);

    try sock.actionDel(&.{.{ .kind = "gact", .index = slot }});
    if (sock.actions("gact")) |after| {
        defer testing.allocator.free(after);
        for (after) |a| try testing.expect(a.gen.index != slot);
    } else |e| switch (e) {
        // An empty action table is reported as ENOENT, not an empty dump.
        error.NotFound => {},
        else => return e,
    }
}

test "integration (netns/root): tbf shaping qdisc round-trip" {
    var sock = try openOrSkip();
    defer sock.close();
    const lo = try loIndex(&sock);

    sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};
    sock.qdiscAdd(
        .{ .ifindex = lo, .handle = .init(5, 0), .parent = Handle.root },
        .{ .tbf = .{ .rate = 125_000, .burst = 4096, .latency_us = 400_000 } },
    ) catch |e| switch (e) {
        error.AccessDenied => return skip("tbf qdisc add"),
        else => return e,
    };
    defer sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};

    const list = try sock.qdiscs(lo);
    defer testing.allocator.free(list);
    var seen = false;
    for (list) |q| {
        if (!std.mem.eql(u8, q.kind(), "tbf")) continue;
        seen = true;
        const t = q.tbf.?;
        try testing.expectEqual(@as(u32, 125_000), t.rate.rate);
        try testing.expectEqual(@as(u32, 54_096), t.limit); // rate*latency + burst
    }
    try testing.expect(seen);
}

test "integration (netns/root): the kernel's extended ACK reaches lastErrorMessage" {
    var sock = try openOrSkip();
    defer sock.close();
    const lo = try loIndex(&sock);

    sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};
    // A qdisc kind no kernel has.
    const err = sock.qdiscAdd(
        .{ .ifindex = lo, .handle = .init(9, 0), .parent = Handle.root },
        .{ .raw = .{ .kind = "definitely_not_a_qdisc" } },
    );
    if (err) |_| {
        sock.qdiscDel(.{ .ifindex = lo, .parent = Handle.root }) catch {};
        return error.TestUnexpectedResult;
    } else |e| switch (e) {
        error.AccessDenied => return skip("qdisc add (ext-ACK probe)"),
        // ENOENT is what the kernel answers for an unknown qdisc kind.
        error.NotFound, error.InvalidRequest, error.NotSupported => {},
        else => return e,
    }
    // Kernels since 4.12 attach a reason string; older ones legitimately do
    // not, so only its shape is asserted.
    try testing.expect(sock.lastErrorMessage().len < 256);
}

test {
    // dark-tests aggregator: a bare `pub const x = @import(…)` re-export does
    // not pull x's tests into the test binary.
    _ = handle;
    _ = ratespec;
    _ = qdisc;
    _ = filter;
    _ = action;
    _ = message;
    _ = @import("goldens.zig");
}
