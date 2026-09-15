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
//! **Transport is shared with the sibling `netlink` module.** This module runs
//! no socket, receive buffer, sequence counter, errno table or extended-ACK
//! handling of its own: it drives `netlink.Socket` through the public
//! `nextSeq`/`send`/`recvDatagram`/`requestAck`/`lastErrorMessage` seam and
//! builds its own tc messages on top of `netlink.codec`. Even the multi-part
//! dump loops triage their replies with the shared
//! `netlink.classifyDumpMessage`; what stays here is only tc policy — which
//! request, which reply type, which parser, which client-side filter.
//!
//! Verification: `goldens.zig` asserts the encoders reproduce, byte for byte,
//! requests captured from a real `iproute2` `tc` under `strace`; the tests at
//! the bottom of this file exercise the whole stack against a live kernel in
//! a network namespace (and skip cleanly without privileges).

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;
const linux = std.os.linux;
const native_endian = builtin.cpu.arch.endian();

const netlink = @import("netlink");
pub const codec = netlink.codec;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Traffic control over rtnetlink — qdiscs (netem/htb/tbf/fq_codel/cake), htb classes, u32/flower filters + action families; byte-exact to iproute2 (retires `tc` shell-outs)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{.linux64},
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
pub const Mq = qdisc.Mq;
pub const Cake = qdisc.Cake;
pub const CakeWire = qdisc.CakeWire;
pub const CakeDiffservMode = qdisc.CakeDiffservMode;
pub const CakeFlowMode = qdisc.CakeFlowMode;
pub const CakeAtmMode = qdisc.CakeAtmMode;
pub const CakeAckFilter = qdisc.CakeAckFilter;
pub const Qdisc = qdisc.Qdisc;
pub const Class = qdisc.Class;
pub const TCA = qdisc.TCA;
pub const TCA_NETEM = qdisc.TCA_NETEM;
pub const TCA_HTB = qdisc.TCA_HTB;
pub const TCA_TBF = qdisc.TCA_TBF;
pub const TCA_FQ_CODEL = qdisc.TCA_FQ_CODEL;
pub const TCA_CAKE = qdisc.TCA_CAKE;
pub const parseCakeOptions = qdisc.parseCakeOptions;
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

const max_dump_attempts = 4; // NLM_F_DUMP_INTR restarts before giving up

/// How long one receive may block before the request fails with
/// `error.RecvFailed`, set by `Socket.open` (A1 F12). Without it a reply that
/// never comes — the kernel's answer filtered as not ours, a lost datagram —
/// blocked the dump loop forever. The kernel answers a tc request within
/// milliseconds even under load; ten seconds leaves room for a busy rtnl lock.
/// It bounds each receive, not a whole dump, so a large table streaming in
/// is never cut off. `Socket.setRecvTimeout` changes it, 0 blocks forever.
pub const default_recv_timeout_ms: u32 = 10_000;

/// `SO_RCVTIMEO`'s `getsockopt` read-back is not required to echo the exact
/// value `setsockopt` was given: the kernel stores the timeout as a jiffy
/// count and rounds UP to the next whole tick (`DIV_ROUND_UP`), so the
/// value read back can exceed what was requested by up to one tick. The
/// tick width is `1000 / CONFIG_HZ` ms and is a kernel build option, not a
/// module or a caller decision — this host runs `CONFIG_HZ=1000` (1ms
/// ticks, exact round-trip for whole milliseconds), but a `scripts/vm/`
/// Debian guest measured 52ms back for a 50ms request (A1 tc.md F-VM1),
/// consistent with a 4ms tick (`CONFIG_HZ=250`, a common distro default).
/// Confirmed black-box on this host by requesting sub-millisecond values
/// directly (`.zig-cache/probe/tc_f_vm1/probe.zig`): the read-back is
/// always >= what was requested and always rounds up to the next 1000us
/// step here, never down. 20ms comfortably covers even the coarsest
/// mainstream tick (`CONFIG_HZ=100`, 10ms) while still catching a
/// genuinely wrong value (e.g. a units bug sending ~500ms for a 50ms
/// request).
const recv_timeout_tick_slop_ms: u64 = 20;

/// A blocking tc client over one `NETLINK_ROUTE` socket. One instance per
/// thread/loop; no shared state.
pub const Socket = struct {
    gpa: std.mem.Allocator,
    /// The shared rtnetlink transport: the socket itself, its receive buffer,
    /// sequence numbers, the write+ACK engine, typed errno mapping and the
    /// kernel's extended-ACK strings all come from here.
    nl: netlink.Socket,
    /// psched calibration used for every rate/burst computation. Read from
    /// `/proc/net/psched` at open time; override with `openWithPsched` to
    /// build requests for a host other than this one.
    psched: Psched,

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
        try nl.setRecvTimeout(default_recv_timeout_ms);
        return .{ .gpa = gpa, .nl = nl, .psched = ps };
    }

    pub fn close(self: *Socket) void {
        self.nl.close();
        self.* = undefined;
    }

    /// Bound how long one receive may block (`SO_RCVTIMEO`); 0 blocks
    /// forever. `open` sets `default_recv_timeout_ms`. A timeout fails the
    /// request in progress with `error.RecvFailed`.
    pub fn setRecvTimeout(self: *Socket, millis: u32) error{Unexpected}!void {
        return self.nl.setRecvTimeout(millis);
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
            try self.nl.send(req);

            var out: std.ArrayList(Action) = .empty;
            errdefer out.deinit(self.gpa);
            while (true) {
                const dgram = try self.nl.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    switch (netlink.classifyDumpMessage(m, self.nl.portid, seq)) {
                        .skip => {},
                        .restart => {
                            // Only free `out` here on the path that keeps
                            // going (a fresh one is declared next retry
                            // iteration, so this avoids leaking it). The
                            // path that gives up must NOT also free it here:
                            // `return error.InconsistentDump` still runs the
                            // `errdefer` above, and freeing twice is a
                            // double-free (ArrayList.deinit leaves the
                            // receiver `undefined`, so the second call frees
                            // a garbage pointer) -- see F1 in A1/tc.md.
                            if (attempt < max_dump_attempts) {
                                out.deinit(self.gpa);
                                continue :retry;
                            }
                            return error.InconsistentDump;
                        },
                        .done => return out.toOwnedSlice(self.gpa),
                        .failed => |code| return netlink.writeErrorFromCode(code),
                        .overrun => return error.SystemResources,
                        .malformed => return error.MalformedReply,
                        .record => |rec| {
                            // The kernel's action *dump* path (tc_dump_action)
                            // echoes the request's nlmsg_type, so these records
                            // arrive as RTM_GETACTION — unlike the single-object
                            // GET path (tca_get_fill), which is handed
                            // RTM_NEWACTION as its event and does emit that.
                            // Accepting only RTM_NEWACTION here silently dropped
                            // every dumped action and returned an empty table:
                            // no error, no short read, just nothing. Both types
                            // are accepted so the reader does not depend on
                            // which of the two the running kernel echoes.
                            if (rec.type != RTM_GETACTION and rec.type != RTM_NEWACTION) continue;
                            // One RTM_NEWACTION carries the whole table slice,
                            // so the messages are flattened into one list.
                            var acts = (action.actionsOf(rec.payload) catch
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
        try self.nl.send(req);
        // Deliberately not `classifyDumpMessage`: this is a single-reply GET,
        // not a multi-part dump, so `NLM_F_DUMP_INTR` carries no restart
        // semantics here and must not be triaged as one.
        while (true) {
            const dgram = try self.nl.recvDatagram();
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
                    // Same nlmsg_type caveat as `actions()`: depending on the
                    // path taken, the kernel answers a GET with either the
                    // RTM_NEWACTION event or an echo of the RTM_GETACTION
                    // request. Matching only the former left this loop blocked
                    // in recvDatagram() forever — an unrecognised type falls to
                    // `else` and we wait for a reply that already arrived.
                    RTM_GETACTION, RTM_NEWACTION => {
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
        return dumpVia(&self.nl, self.gpa, T, parseFn, msg_type, reply_type, ifindex, parent, mode);
    }

    /// The dump engine's actual body, generic over `transport` (F6, A1/tc.md):
    /// production passes `&self.nl` (a `*netlink.Socket`, which already
    /// offers exactly this shape); tests pass a scripted fixture so the
    /// retry-attempt cap and the `reply_type` filter can be exercised
    /// without a real socket, a network namespace or root. `transport` must
    /// offer `nextSeq() u32`, `send(bytes) !void`, `recvDatagram() ![]const
    /// u8` and a `portid` field/value.
    fn dumpVia(
        transport: anytype,
        gpa: std.mem.Allocator,
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
            const seq = transport.nextSeq();
            const req = try message.buildDump(
                gpa,
                seq,
                msg_type,
                ifindex,
                parent orelse Handle.unspec,
            );
            defer gpa.free(req);
            try transport.send(req);

            var out: std.ArrayList(T) = .empty;
            errdefer out.deinit(gpa);
            while (true) {
                const dgram = try transport.recvDatagram();
                var it: codec.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    switch (netlink.classifyDumpMessage(m, transport.portid, seq)) {
                        .skip => {},
                        .restart => {
                            // See the matching comment in `actions()` above:
                            // only free `out` on the path that retries (a
                            // fresh one is declared next iteration). The
                            // give-up path must leave it for the `errdefer`
                            // -- freeing here too is a double-free, since
                            // `ArrayList.deinit` sets the receiver to
                            // `undefined` (F1 in A1/tc.md).
                            if (attempt < max_dump_attempts) {
                                out.deinit(gpa);
                                continue :retry;
                            }
                            return error.InconsistentDump;
                        },
                        .done => return out.toOwnedSlice(gpa),
                        .failed => |code| return netlink.writeErrorFromCode(code),
                        .overrun => return error.SystemResources,
                        .malformed => return error.MalformedReply,
                        .record => |rec| {
                            if (rec.type != reply_type) continue;
                            const item = parseFn(rec.payload) catch return error.MalformedReply;
                            if (item.ifindex != ifindex) continue;
                            if (parent) |p| {
                                if (!parentMatches(mode, p, item.parent, item.handle)) continue;
                            }
                            try out.append(gpa, item);
                        },
                    }
                }
            }
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

/// The sequence number every message in `DumpCorpus` carries, and the port id
/// `classifyDumpMessage` is asked to match it against. A message built here
/// has `pid == 0`, so 0 is the identity that makes the triage return `.record`
/// rather than `.skip`.
const dump_seq: u32 = 0x1234_5678;
const dump_portid: u32 = 0;

/// Whole `RTM_GET*` **reply datagrams** for `fuzzDumpParse`, in the format
/// `Smith.slice` reads (see `testkit.fuzz`): a little-endian u32 length, then
/// the frame.
///
/// ⭐ This target used to be `parseQdisc` on a bare payload, which is what
/// `qdisc.fuzzParseOptions` already does. What was untested is the half of
/// `Socket.dump` above the syscall: the `nlmsghdr` framing, the multi-part
/// triage, and the decision to hand a payload to a parser at all. That is what
/// runs here, over datagrams this module's own builders produce — netlink
/// messages are length-prefixed and 4-byte aligned, so a hand-edited literal
/// is refused at the header and a hex corpus would be a little-endian one.
const DumpCorpus = struct {
    scratch: [32768]u8 = undefined,
    store: [32768]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *DumpCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = sd;
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *DumpCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();
        const ps = ratespec.golden_psched;

        // A two-message qdisc dump followed by NLMSG_DONE — the ordinary
        // shape, and the only one that exercises "record, record, done".
        var qd: std.ArrayList(u8) = .empty;
        {
            const a = try message.buildQdiscSet(gpa, dump_seq, .add, .{
                .ifindex = 2,
                .handle = Handle.init(1, 0),
                .parent = Handle.root,
            }, .{ .netem = .{ .delay_ns = 50_000_000, .loss_pct = 1 } }, ps);
            try qd.appendSlice(gpa, a);
            const b = try message.buildQdiscSet(gpa, dump_seq, .add, .{
                .ifindex = 2,
                .handle = Handle.init(0x8001, 0),
                .parent = Handle.init(1, 1),
            }, .{ .fq_codel = .{ .limit = 10240, .target_us = 5000 } }, ps);
            try qd.appendSlice(gpa, b);
            try appendControl(gpa, &qd, codec.NLMSG_DONE, &.{});
        }
        self.push(qd.items);

        // A class dump: htb, so the datagram carries the two 1 KiB rate
        // tables — the largest frame this module can produce, and the reason
        // the harness's buffer is 8192 and not 256.
        var cd: std.ArrayList(u8) = .empty;
        {
            const a = try message.buildClassSet(gpa, dump_seq, .add, .{
                .ifindex = 2,
                .handle = Handle.init(1, 0x10),
                .parent = Handle.init(1, 0),
            }, .{ .htb = .{ .rate = 5_000_000_000, .ceil = 10_000_000_000, .prio = 1 } }, ps);
            try cd.appendSlice(gpa, a);
            try appendControl(gpa, &cd, codec.NLMSG_DONE, &.{});
        }
        self.push(cd.items);

        // A filter dump: u32 with an action list, then flower.
        var fd: std.ArrayList(u8) = .empty;
        {
            const a = try message.buildFilterSetWith(gpa, dump_seq, .add, .{
                .ifindex = 2,
                .parent = Handle.init(1, 0),
                .prio = 10,
                .eth_type = filter.ETH_P.IP,
            }, .{ .u32 = .{
                .classid = Handle.init(1, 0x10),
                .keys = &.{filter.U32Key.ipv4Dst(.{ 10, 0, 0, 1 }, 32)},
                .actions = &.{.{ .gact = .{ .action = .shot } }},
            } }, ps);
            try fd.appendSlice(gpa, a);
            const b = try message.buildFilterSetWith(gpa, dump_seq, .add, .{
                .ifindex = 2,
                .parent = Handle.clsact,
                .prio = 1,
                .eth_type = filter.ETH_P.IPV6,
            }, .{ .flower = .{
                .eth_type = filter.ETH_P.IPV6,
                .ip_proto = filter.IPPROTO.UDP,
                .dst_port = 53,
            } }, ps);
            try fd.appendSlice(gpa, b);
            try appendControl(gpa, &fd, codec.NLMSG_DONE, &.{});
        }
        self.push(fd.items);

        // ── the triage branches a healthy dump never reaches ───────────────
        // NLMSG_ERROR carrying -EPERM: `.failed`.
        var err: std.ArrayList(u8) = .empty;
        {
            var body: [4]u8 = undefined;
            std.mem.writeInt(i32, &body, -@as(i32, @intFromEnum(linux.E.PERM)), native_endian);
            try appendControl(gpa, &err, codec.NLMSG_ERROR, &body);
        }
        self.push(err.items);

        // NLMSG_ERROR with a payload too short to hold an errno: `.malformed`.
        var short_err: std.ArrayList(u8) = .empty;
        try appendControl(gpa, &short_err, codec.NLMSG_ERROR, &[_]u8{ 0, 0 });
        self.push(short_err.items);

        // NLMSG_OVERRUN and NLMSG_NOOP: `.overrun` and `.skip`.
        var overrun: std.ArrayList(u8) = .empty;
        try appendControl(gpa, &overrun, codec.NLMSG_OVERRUN, &.{});
        try appendControl(gpa, &overrun, codec.NLMSG_NOOP, &.{});
        self.push(overrun.items);

        // A record whose seq is somebody else's: `.skip`, the self-healing
        // path after an aborted earlier dump.
        var stale: std.ArrayList(u8) = .empty;
        {
            const a = try message.buildQdiscSet(gpa, dump_seq +% 1, .add, .{
                .ifindex = 2,
                .handle = Handle.init(1, 0),
                .parent = Handle.root,
            }, .{ .mq = .{} }, ps);
            try stale.appendSlice(gpa, a);
        }
        self.push(stale.items);

        // A record flagged NLM_F_DUMP_INTR: `.restart`.
        var intr: std.ArrayList(u8) = .empty;
        {
            const hdr = try codec.appendHeader(
                gpa,
                &intr,
                RTM_NEWQDISC,
                codec.NLM_F_MULTI | codec.NLM_F_DUMP_INTR,
                dump_seq,
                0,
            );
            try message.appendTcmsg(gpa, &intr, 2, Handle.init(1, 0), Handle.root, 0);
            codec.finishHeader(&intr, hdr);
        }
        self.push(intr.items);

        // ── the refusals ───────────────────────────────────────────────────
        // A header claiming 0x40 octets over a 10-octet datagram, which is
        // where `MessageIterator` must stop instead of reading on.
        self.push(&[_]u8{ 0x40, 0x00, 0x00, 0x00, 0x24, 0x00, 0x02, 0x00, 0x00, 0x00 });
        // A whole message header with no payload behind it: the tcmsg is
        // missing, so the parser refuses what the framer accepted.
        var headless: std.ArrayList(u8) = .empty;
        {
            const hdr = try codec.appendHeader(gpa, &headless, RTM_NEWQDISC, codec.NLM_F_MULTI, dump_seq, 0);
            codec.finishHeader(&headless, hdr);
        }
        self.push(headless.items);

        return self.entries[0..self.n];
    }

    fn appendControl(
        gpa: std.mem.Allocator,
        list: *std.ArrayList(u8),
        msg_type: u16,
        body: []const u8,
    ) !void {
        const hdr = try codec.appendHeader(gpa, list, msg_type, codec.NLM_F_MULTI, dump_seq, 0);
        if (body.len != 0) try codec.appendPadded(gpa, list, body);
        codec.finishHeader(list, hdr);
    }
};

/// What one datagram produced: the numbers a corpus guard can pin, and the
/// numbers the collapsed harness could never move off zero.
const DumpTally = struct {
    messages: usize = 0,
    records: usize = 0,
    kinds: usize = 0,
    controls: usize = 0,
};

/// The pure half of `Socket.dump`: frame, triage, parse. Shared by the fuzz
/// target and its corpus guard so the guard measures the same walk.
fn walkDump(dgram: []const u8) DumpTally {
    var t: DumpTally = .{};
    var it: codec.MessageIterator = .{ .buf = dgram };
    while (it.next() catch return t) |m| {
        t.messages += 1;
        switch (codec.classifyDumpMessage(m, dump_portid, dump_seq)) {
            .record => |rec| {
                t.records += 1;
                switch (rec.type) {
                    RTM_NEWQDISC => if (parseQdisc(rec.payload)) |q| {
                        if (q.kind().len != 0) t.kinds += 1;
                    } else |_| {},
                    RTM_NEWTCLASS => if (qdisc.parseClass(rec.payload)) |c| {
                        if (c.kind().len != 0) t.kinds += 1;
                    } else |_| {},
                    RTM_NEWTFILTER => if (filter.parseFilter(rec.payload)) |f| {
                        if (f.kind().len != 0) t.kinds += 1;
                    } else |_| {},
                    else => {},
                }
            },
            .skip => {},
            else => t.controls += 1,
        }
    }
    return t;
}

test "fuzz: a dump datagram never crashes the framer, the triage or the parsers" {
    var corpus: DumpCorpus = .{};
    try testing.fuzz({}, fuzzDumpParse, .{ .corpus = try corpus.build() });
}

fn fuzzDumpParse(_: void, smith: *std.testing.Smith) !void {
    // 8192, not 256: an htb class reply carries two 1 KiB rate tables, so the
    // largest datagram this module can produce is over 2 KiB — and a seed
    // longer than the buffer is not a big seed, `Smith.slice` reads it back as
    // the EMPTY one.
    var raw: [8192]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and the target parsed an EMPTY slice with
    // the reply sitting unread in `raw`.
    //
    // ⛔ Measured 2026-09-07 over the corpus above: **0 of 10 seeds non-empty,
    // 0 messages framed, 0 records classified and 0 kinds read before; 10 of
    // 10 non-empty, 15 messages framed, 6 records, 5 kinds and 7 control
    // verdicts (done / failed / malformed / overrun / restart) after.**
    const len: usize = smith.slice(&raw);
    std.mem.doNotOptimizeAway(walkDump(raw[0..len]));
}

test "corpus: every dump seed reaches the framer, and the walked counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets, through the SAME `walkDump`. `nonempty` is
    // the reach claim and the only check that catches a seed grown past the
    // harness's buffer, which `Smith.slice` reads back as the EMPTY one.
    //
    // ⛔ There is no acceptance count here on purpose. An empty datagram is a
    // legal netlink reply — `MessageIterator` yields nothing and the walk
    // "succeeds" — so anything phrased as "did it parse" reads 10 of 10 while
    // the framer never runs. `messages`, `records`, `kinds` and `controls` are
    // counts of work done, which the empty datagram cannot fake.
    var corpus: DumpCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var total: DumpTally = .{};
    for (entries) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [8192]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        const t = walkDump(raw[0..len]);
        total.messages += t.messages;
        total.records += t.records;
        total.kinds += t.kinds;
        total.controls += t.controls;
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 15), total.messages);
    try testing.expectEqual(@as(usize, 6), total.records);
    try testing.expectEqual(@as(usize, 5), total.kinds);
    try testing.expectEqual(@as(usize, 7), total.controls);
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
    if (verboseSkip()) std.debug.print("SKIPPED: {s} (needs CAP_NET_ADMIN in a netns: `unshare -rn zig build test-tc`)\n", .{what});
    return error.SkipZigTest;
}

/// The stronger requirement of the standalone action family: the kernel
/// checks `CAP_NET_ADMIN` against the **initial** user namespace there, so a
/// `unshare -rn` namespace does not grant it.
fn skipInitUserns(comptime what: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print(
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

fn recvTimeoutMs(sock: *const Socket) !u64 {
    var tv: linux.timeval = undefined;
    var len: linux.socklen_t = @sizeOf(linux.timeval);
    const rc = linux.getsockopt(sock.nl.handle(), linux.SOL.SOCKET, linux.SO.RCVTIMEO, @ptrCast(&tv), &len);
    if (linux.errno(rc) != .SUCCESS) return error.GetsockoptFailed;
    return @as(u64, @intCast(tv.sec)) * 1000 + @as(u64, @intCast(tv.usec)) / 1000;
}

test "F12: open bounds each receive by default_recv_timeout_ms, setRecvTimeout changes it, and a reply that never comes fails instead of blocking" {
    // 0 would mean "block forever", the defect itself.
    try testing.expect(default_recv_timeout_ms != 0);
    var sock = try openOrSkip();
    defer sock.close();
    try testing.expectEqual(@as(u64, default_recv_timeout_ms), try recvTimeoutMs(&sock));

    try sock.setRecvTimeout(50);
    // Read back BEFORE receiving: a broken setter must fail here, not hang below.
    // Not an exact-equality check: see `recv_timeout_tick_slop_ms` (A1 F-VM1) --
    // the kernel rounds the stored timeout up to its own tick granularity, so
    // the value read back can be slightly more than 50 depending on the host's
    // `CONFIG_HZ`, but it can never be less.
    const got_ms = try recvTimeoutMs(&sock);
    try testing.expect(got_ms >= 50);
    try testing.expect(got_ms <= 50 + recv_timeout_tick_slop_ms);
    // Nothing was sent, so nothing will arrive.
    try testing.expectError(error.RecvFailed, sock.nl.recvDatagram());

    try sock.setRecvTimeout(0);
    try testing.expectEqual(@as(u64, 0), try recvTimeoutMs(&sock));
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
        // Regression guard: the dump used to come back empty because the
        // reply's nlmsg_type is RTM_GETACTION, not RTM_NEWACTION. An empty
        // table would make the loop below vacuous, so assert non-empty
        // before relying on it.
        try testing.expect(list.len > 0);
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

// ── F6: a scripted transport for the dump engine ────────────────────────────
//
// `Socket.dump`'s retry-attempt cap and its `reply_type` filter (A1/tc.md
// F6) had no test: exercising them for real needs a kernel that keeps
// answering `NLM_F_DUMP_INTR` on demand, or a foreign-type record mixed into
// a real dump — neither is reachable through `openOrSkip`'s live socket.
// `dumpVia` being generic over `transport: anytype` (same idiom `netlink`'s
// own `dumpOver`/`collectDumpPass` already use, with their own
// `ScriptedTransport` fixture) means the retry loop can be driven by a
// fixture instead, with no real socket and no privilege.
const F6Step = union(enum) {
    /// One `NLM_F_DUMP_INTR` message — triggers `.restart`.
    restart,
    /// `NLMSG_DONE` — ends the dump.
    done,
    /// A dump record of `msg_type` carrying a minimal, valid `tcmsg` (just
    /// `ifindex`; no `TCA_*` attributes needed for `qdisc.parseQdisc`).
    record: struct { msg_type: u16, ifindex: u32 },
};

const F6ScriptedTransport = struct {
    gpa: std.mem.Allocator,
    portid: u32,
    seq: u32 = 0,
    steps: []const F6Step,
    i: usize = 0,
    buf: std.ArrayList(u8) = .empty,

    fn deinit(self: *F6ScriptedTransport) void {
        self.buf.deinit(self.gpa);
    }

    fn nextSeq(self: *F6ScriptedTransport) u32 {
        self.seq += 1;
        return self.seq;
    }

    fn send(self: *F6ScriptedTransport, _: []const u8) DumpError!void {
        _ = self;
    }

    fn recvDatagram(self: *F6ScriptedTransport) DumpError![]const u8 {
        // Exhausting the script is a bug in the test, not the mutation under
        // test — fail loudly rather than let the retry loop spin.
        if (self.i >= self.steps.len) @panic("F6ScriptedTransport: script exhausted");
        const step = self.steps[self.i];
        self.i += 1;
        self.buf.clearRetainingCapacity();
        switch (step) {
            .restart => {
                const h = codec.appendHeader(self.gpa, &self.buf, codec.NLMSG_DONE, codec.NLM_F_DUMP_INTR, self.seq, self.portid) catch return error.SystemResources;
                codec.finishHeader(&self.buf, h);
            },
            .done => {
                const h = codec.appendHeader(self.gpa, &self.buf, codec.NLMSG_DONE, 0, self.seq, self.portid) catch return error.SystemResources;
                codec.finishHeader(&self.buf, h);
            },
            .record => |r| {
                const h = codec.appendHeader(self.gpa, &self.buf, r.msg_type, 0, self.seq, self.portid) catch return error.SystemResources;
                var payload: [qdisc.tcmsg_len]u8 = @splat(0);
                std.mem.writeInt(i32, payload[4..8], @bitCast(r.ifindex), native_endian);
                codec.appendPadded(self.gpa, &self.buf, &payload) catch return error.SystemResources;
                codec.finishHeader(&self.buf, h);
            },
        }
        return self.buf.items;
    }
};

test "F6: the dump engine tolerates exactly `max_dump_attempts` restarts, not one more" {
    // Default max_dump_attempts = 4: three NLM_F_DUMP_INTR restarts, then a
    // real record + NLMSG_DONE on the fourth attempt must still succeed.
    const gpa = testing.allocator;
    var t: F6ScriptedTransport = .{
        .gpa = gpa,
        .portid = 77,
        .steps = &.{
            .restart,
            .restart,
            .restart,
            .{ .record = .{ .msg_type = RTM_NEWQDISC, .ifindex = 5 } },
            .done,
        },
    };
    defer t.deinit();
    const items = try Socket.dumpVia(&t, gpa, Qdisc, qdisc.parseQdisc, RTM_GETQDISC, RTM_NEWQDISC, 5, null, .exact);
    defer gpa.free(items);
    try testing.expectEqual(@as(usize, 1), items.len);
    try testing.expectEqual(@as(u32, 5), items[0].ifindex);
}

test "F6: a dump record whose type does not match reply_type is excluded" {
    // A record typed RTM_NEWTCLASS arrives mixed into an RTM_GETQDISC dump
    // (e.g. a confused kernel path, or a future reply_type bug) — the
    // `rec.type != reply_type` guard must drop it, not fold it into results
    // that are supposed to be one type of object.
    const gpa = testing.allocator;
    var t: F6ScriptedTransport = .{
        .gpa = gpa,
        .portid = 77,
        .steps = &.{
            .{ .record = .{ .msg_type = RTM_NEWTCLASS, .ifindex = 5 } }, // wrong type
            .{ .record = .{ .msg_type = RTM_NEWQDISC, .ifindex = 5 } }, // right type
            .done,
        },
    };
    defer t.deinit();
    const items = try Socket.dumpVia(&t, gpa, Qdisc, qdisc.parseQdisc, RTM_GETQDISC, RTM_NEWQDISC, 5, null, .exact);
    defer gpa.free(items);
    try testing.expectEqual(@as(usize, 1), items.len);
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
    _ = @import("bench.zig");
}
