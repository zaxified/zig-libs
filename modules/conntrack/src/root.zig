// SPDX-License-Identifier: MIT
//! conntrack — pure-Zig **ctnetlink** client: the real netlink API of the Linux
//! connection tracker (`NETLINK_NETFILTER` / `NFNL_SUBSYS_CTNETLINK`), the one
//! `conntrack -L/-G/-I/-D/-E` speaks. Dump the flow table, look a flow up by
//! tuple, insert, delete, flush, and subscribe to the conntrack event
//! multicast groups — typed, bounds-checked, no libc, no `conntrack`
//! shell-out.
//!
//! The sibling `procnet` module only *reads* `/proc/net/nf_conntrack`, a lossy
//! text view that many kernels no longer build at all
//! (`CONFIG_NF_CONNTRACK_PROCFS=n` — including the host this module was
//! developed on). ctnetlink is the supported interface: richer (counters,
//! zone, mark, id, TCP state, timestamps), writable, and event-driven.
//!
//! ```zig
//! const conntrack = @import("conntrack");
//!
//! var sock = try conntrack.Socket.open(gpa);
//! defer sock.close();
//!
//! const flows = try sock.dump(.unspec);   // every tracked flow
//! defer gpa.free(flows);
//! for (flows) |f| {
//!     if (f.hasStatus(conntrack.IPS.ASSURED)) { … }
//! }
//! ```
//!
//! Wire format, byte-order rules and the typed model live in `wire.zig` and
//! are re-exported here; this file adds the socket, the dump/ACK engines and
//! the event seam.
//!
//! Provenance: clean-room from the kernel UAPI headers plus byte-exact captures
//! of real conntrack-tools ↔ kernel traffic (`goldens.zig` documents the exact
//! capture command). No libnetfilter_conntrack source was consulted. See
//! `/NOTICE`.

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
const netlink = @import("netlink");
const codec = netlink.codec;
const native_endian = builtin.cpu.arch.endian();

pub const meta = .{
    .platform = .linux, // AF_NETLINK raw syscalls — conscious ceiling
    .role = .client,
    .concurrency = .single_owner, // one Socket per thread/loop; blocking I/O
    .model_after = "kernel UAPI linux/netfilter/nfnetlink{,_conntrack}.h + conntrack-tools wire behaviour",
    .deps = .{ "netlink", "netaddr" }, // wire codec / IP address types
};

// ── wire layer re-exports ───────────────────────────────────────────────────

pub const wire = @import("wire.zig");

pub const Flow = wire.Flow;
pub const Tuple = wire.Tuple;
pub const Counters = wire.Counters;
pub const Family = wire.Family;
pub const Direction = wire.Direction;
pub const TcpState = wire.TcpState;
pub const TcpFlags = wire.TcpFlags;
pub const NewSpec = wire.NewSpec;
pub const IPS = wire.IPS;
pub const IPPROTO = wire.IPPROTO;
pub const CTA = wire.CTA;
pub const DecodeError = wire.DecodeError;
pub const BuildError = wire.BuildError;
pub const decodeFlow = wire.decodeFlow;
pub const decodeTuple = wire.decodeTuple;
pub const parseNfgenmsg = wire.parseNfgenmsg;
pub const buildDumpRequest = wire.buildDumpRequest;
pub const buildGetRequest = wire.buildGetRequest;
pub const buildDeleteRequest = wire.buildDeleteRequest;
pub const buildFlushRequest = wire.buildFlushRequest;
pub const buildNewRequest = wire.buildNewRequest;
pub const msg_ct_new = wire.msg_ct_new;
pub const msg_ct_get = wire.msg_ct_get;
pub const msg_ct_delete = wire.msg_ct_delete;

// ── event multicast groups ──────────────────────────────────────────────────

/// `enum nfnetlink_groups` as a **bind mask**: the kernel numbers groups from
/// 1 while `sockaddr_nl.nl_groups` is a bit set, so group *n* is bit *n-1*.
/// Every conntrack group fits in the 32-bit legacy mask.
pub const Group = struct {
    pub const CONNTRACK_NEW: u32 = 1 << 0; // NFNLGRP_CONNTRACK_NEW = 1
    pub const CONNTRACK_UPDATE: u32 = 1 << 1; // = 2
    pub const CONNTRACK_DESTROY: u32 = 1 << 2; // = 3
    pub const CONNTRACK_EXP_NEW: u32 = 1 << 3;
    pub const CONNTRACK_EXP_UPDATE: u32 = 1 << 4;
    pub const CONNTRACK_EXP_DESTROY: u32 = 1 << 5;

    /// The three flow-lifecycle groups — what `conntrack -E` subscribes to.
    pub const all_conntrack: u32 = CONNTRACK_NEW | CONNTRACK_UPDATE | CONNTRACK_DESTROY;
};

/// Which lifecycle transition an event message reports.
pub const EventKind = enum { new, update, destroy };

/// One decoded event.
pub const Event = struct {
    kind: EventKind,
    flow: Flow,
};

// ── errors ──────────────────────────────────────────────────────────────────

pub const OpenError = error{
    OutOfMemory,
    /// Binding to a multicast group needs `CAP_NET_ADMIN` in the namespace.
    AccessDenied,
    /// Kernel without `AF_NETLINK`/`NETLINK_NETFILTER`
    /// (`CONFIG_NETFILTER_NETLINK=n`).
    ProtocolNotSupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
};

pub const SendError = error{ SendFailed, AccessDenied, SystemResources };

pub const RecvError = error{
    OutOfMemory,
    RecvFailed,
    /// A reply failed wire-format validation (bounds/length checks).
    MalformedReply,
    /// The kernel dropped messages because the receive buffer was full
    /// (`ENOBUFS`). On an event socket that means events were **lost** and the
    /// caller must re-dump to resynchronise.
    Overrun,
    /// Nothing to read on a non-blocking socket, or the receive timeout
    /// expired (`EAGAIN`).
    WouldBlock,
    SystemResources,
};

/// Errors of the multi-part dump path. A superset of `netlink.DumpError`, so
/// `netlink.errorFromCode` is reused verbatim.
pub const DumpError = netlink.DumpError || RecvError || SendError;

/// Errors of the single-reply paths (get/delete/flush/insert/update). A
/// superset of `netlink.RequestError`, so `netlink.writeErrorFromCode` is
/// reused verbatim: `NotFound` is what an untracked tuple yields, `Exists` an
/// `NLM_F_EXCL` insert of a flow the kernel already knows.
///
/// `TooManyMessages` is this module's own addition (**W2 audit finding,
/// campaign C-06, `conntrack` F6**): `awaitFlow` used to loop on
/// `recvDatagram` until a message matching `(portid, seq)` arrived, with no
/// upper bound — a kernel that answers neither `NLMSG_ERROR` nor
/// `IPCTNL_MSG_CT_NEW` on that sequence spun the caller forever.
pub const RequestError = netlink.RequestError || RecvError || SendError || error{TooManyMessages};

/// Everything a write op can fail with: request construction + transport +
/// the kernel's mapped errno.
pub const WriteError = RequestError || BuildError;

const max_dump_attempts = 4; // NLM_F_DUMP_INTR restarts before giving up

/// Ceiling on how many netlink messages `awaitFlow` may consume before
/// giving up. See the sibling `ethtool`/`devlink`/`nl80211` clients'
/// identical constant for the full rationale: the kernel is the only
/// verified sender on this socket (`netlink.Socket.recvDatagramStrict`
/// drops any datagram whose sender pid is not 0), so this is a robustness
/// ceiling against a malfunctioning driver, not an attacker-facing bound.
const max_await_messages: u32 = 65536;

// ── socket ──────────────────────────────────────────────────────────────────

/// A blocking `NETLINK_NETFILTER` socket. One instance per thread/loop; no
/// shared state.
///
/// **Transport is the sibling `netlink` module's.** Socket creation and bind,
/// port-id capture, `NETLINK_EXT_ACK`, the sequence counter, the
/// `MSG_PEEK|MSG_TRUNC` buffer-growth loop, the extended-ACK capture and the
/// ACK/error engine all come from `netlink.Socket`, opened on
/// `linux.NETLINK.NETFILTER` via `openProtocolGroups`; the multi-part reply
/// triage is `netlink.classifyDumpMessage`. What stays here is ctnetlink
/// policy only: which request, which reply type, which decoder, which errno
/// mapping, and the event seam.
pub const Socket = struct {
    /// The shared netlink transport, bound to `NETLINK_NETFILTER`.
    nl: netlink.Socket,

    /// Open a request/response socket (no multicast groups).
    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        return openWithGroups(gpa, 0);
    }

    /// Open a socket subscribed to conntrack event groups — e.g.
    /// `openEvents(gpa, Group.all_conntrack)`, the `conntrack -E` set. Needs
    /// `CAP_NET_ADMIN` in the network namespace. Request/response ops still
    /// work on the same socket, but then a reply and an event can arrive in
    /// either order; prefer one socket per job.
    pub fn openEvents(gpa: std.mem.Allocator, groups: u32) OpenError!Socket {
        return openWithGroups(gpa, groups);
    }

    fn openWithGroups(gpa: std.mem.Allocator, groups: u32) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("conntrack.Socket is Linux-only (AF_NETLINK raw syscalls)");
        return .{
            .nl = try netlink.Socket.openProtocolGroups(gpa, linux.NETLINK.NETFILTER, groups),
        };
    }

    pub fn close(self: *Socket) void {
        self.nl.close();
        self.* = undefined;
    }

    /// Next request sequence number (never 0, so a stale reply from an
    /// unbootstrapped state cannot match).
    pub fn nextSeq(self: *Socket) u32 {
        return self.nl.nextSeq();
    }

    /// The kernel's reason for the last failed request, from the extended ACK
    /// (`NLMSGERR_ATTR_MSG`). Empty when the kernel attached none. Valid until
    /// the next request on this socket.
    pub fn lastErrorMessage(self: *const Socket) []const u8 {
        return self.nl.lastErrorMessage();
    }

    /// The raw file descriptor, for poll/epoll integration or `fcntl(O_NONBLOCK)`.
    /// Do not close it — that is `close`'s job.
    pub fn handle(self: *const Socket) i32 {
        return self.nl.handle();
    }

    /// Bound how long a receive may block (`SO_RCVTIMEO`); 0 restores the
    /// default of blocking forever. A timeout surfaces as `error.WouldBlock`.
    pub fn setRecvTimeout(self: *Socket, millis: u32) error{Unexpected}!void {
        return self.nl.setRecvTimeout(millis);
    }

    // ── high-level operations ──────────────────────────────────────────────

    /// Dump the conntrack table (`IPCTNL_MSG_CT_GET` + `NLM_F_DUMP`).
    /// `.unspec` dumps every family; `.ipv4`/`.ipv6` scope it kernel-side.
    /// Needs `CAP_NET_ADMIN` in the network namespace. `Flow` is pointer-free,
    /// so the result is released with a single `gpa.free(flows)`.
    pub fn dump(self: *Socket, family: Family) DumpError![]Flow {
        return dumpOver(self.nl.gpa, self, family);
    }

    // ── transport hooks the dump engine needs (see `dumpOver`) ─────────────

    /// The kernel-assigned port id replies are matched against.
    fn portId(self: *const Socket) u32 {
        return self.nl.portid;
    }

    /// Copy the extended-ACK reason string out of a failed reply.
    fn captureExtAck(self: *Socket, m: codec.Message) void {
        self.nl.captureExtAck(m);
    }

    /// Look one flow up by tuple (`IPCTNL_MSG_CT_GET`, no dump flag). Null
    /// when the kernel does not track it (`ENOENT`).
    pub fn get(self: *Socket, family: Family, dir: Direction, tuple: Tuple) WriteError!?Flow {
        const seq = self.nextSeq();
        const req = try wire.buildGetRequest(self.nl.gpa, seq, family, dir, tuple);
        defer self.nl.gpa.free(req);
        try self.send(req);
        return self.awaitFlow(seq) catch |err| switch (err) {
            error.NotFound => null,
            else => err,
        };
    }

    /// Delete one flow, keyed on `tuple` in direction `dir`
    /// (`IPCTNL_MSG_CT_DELETE`). `expect_id` makes it a compare-and-delete —
    /// see `wire.buildDeleteRequest` for exactly what the kernel does with it.
    /// `error.NotFound` means the flow was already gone (or the id did not
    /// match).
    pub fn delete(
        self: *Socket,
        family: Family,
        dir: Direction,
        tuple: Tuple,
        expect_id: ?u32,
    ) WriteError!void {
        const seq = self.nextSeq();
        const req = try wire.buildDeleteRequest(self.nl.gpa, seq, family, dir, tuple, expect_id);
        defer self.nl.gpa.free(req);
        try self.send(req);
        return self.awaitAck(seq);
    }

    /// Drop **every** entry of `family` (`.unspec` = the whole table). This is
    /// what a tuple-less `IPCTNL_MSG_CT_DELETE` does in the kernel; it carries
    /// its own name here so that no caller can trigger it by accident.
    pub fn flush(self: *Socket, family: Family) WriteError!void {
        const seq = self.nextSeq();
        const req = try wire.buildFlushRequest(self.nl.gpa, seq, family);
        defer self.nl.gpa.free(req);
        try self.send(req);
        return self.awaitAck(seq);
    }

    /// Insert a new entry (`IPCTNL_MSG_CT_NEW` with `NLM_F_CREATE|NLM_F_EXCL`,
    /// what `conntrack -I` sends). `error.Exists` when the kernel already
    /// tracks the tuple. `spec.timeout` is effectively mandatory: the kernel
    /// rejects a timeout-less insert with `EINVAL`.
    pub fn insert(self: *Socket, family: Family, spec: NewSpec) WriteError!void {
        return self.newOp(family, spec, codec.NLM_F_REQUEST | codec.NLM_F_ACK |
            codec.NLM_F_EXCL | codec.NLM_F_CREATE);
    }

    /// Update the entry matching `spec.orig`/`spec.reply` in place
    /// (`IPCTNL_MSG_CT_NEW` without `NLM_F_CREATE`) — how to set a mark,
    /// re-arm a timeout or move the TCP state of an existing flow.
    pub fn update(self: *Socket, family: Family, spec: NewSpec) WriteError!void {
        return self.newOp(family, spec, codec.NLM_F_REQUEST | codec.NLM_F_ACK);
    }

    fn newOp(self: *Socket, family: Family, spec: NewSpec, flags: u16) WriteError!void {
        const seq = self.nextSeq();
        const req = try wire.buildNewRequest(self.nl.gpa, seq, family, flags, spec);
        defer self.nl.gpa.free(req);
        try self.send(req);
        return self.awaitAck(seq);
    }

    // ── event seam ─────────────────────────────────────────────────────────

    /// Block until the kernel delivers a datagram of events, then hand back an
    /// iterator over it. **This is the only blocking call in the event path**:
    /// the caller owns the loop and may instead put `handle()` in poll/epoll
    /// (or set `setRecvTimeout`) and call this only when it will not block.
    ///
    /// The iterator borrows this socket's receive buffer, so it stays valid
    /// until the next call on this socket. `error.Overrun` means the kernel
    /// dropped events and a re-dump is needed to resynchronise.
    pub fn nextEvents(self: *Socket) RecvError!EventIterator {
        const dgram = try self.recvDatagram();
        return .{ .msgs = .{ .buf = dgram } };
    }

    // ── transport (all of it `netlink.Socket`'s) ───────────────────────────

    /// Send one complete netlink message to the kernel.
    pub fn send(self: *Socket, msg: []const u8) SendError!void {
        return self.nl.send(msg);
    }

    /// Receive one whole datagram, growing the socket's buffer as needed via a
    /// `MSG_PEEK|MSG_TRUNC` size probe so nothing is lost to truncation.
    /// Datagrams not sent by the kernel (sender pid != 0) are dropped — any
    /// user process may address our port id.
    ///
    /// `netlink.Socket.recvDatagramStrict` is the variant that keeps
    /// `Overrun` (dropped events) and `WouldBlock` (receive timeout) apart,
    /// which is exactly what an event consumer needs.
    pub fn recvDatagram(self: *Socket) RecvError![]const u8 {
        return self.nl.recvDatagramStrict();
    }

    /// Wait for the `NLMSG_ERROR` reply to `seq`: errno 0 = ACK (success),
    /// anything else = a mapped error. Replies for other ports/sequences are
    /// skipped, as are multicast events arriving meanwhile.
    fn awaitAck(self: *Socket, seq: u32) RequestError!void {
        return self.nl.awaitAckStrict(seq);
    }

    /// Wait for the single `IPCTNL_MSG_CT_NEW` answer to a GET on `seq`.
    /// **W2 audit finding, campaign C-06 (`conntrack` F6)**: this used to
    /// loop on `recvDatagram` with no upper bound — a kernel that answers
    /// neither `NLMSG_ERROR` nor `IPCTNL_MSG_CT_NEW` on this sequence spun
    /// the caller forever. `awaitFlowOver` is the bounded engine, factored
    /// out (same reason `dumpOver` is) so the existing `ScriptedTransport`
    /// test fixture can drive it without a real socket.
    fn awaitFlow(self: *Socket, seq: u32) RequestError!Flow {
        self.nl.ext_ack_len = 0;
        return awaitFlowOver(self, seq);
    }
};

/// The body of `Socket.awaitFlow`, taking `transport: anytype` for the same
/// reason `dumpOver` does: `Socket` already defines `recvDatagram()`,
/// `portId()` and `captureExtAck(msg)` (see below `dump`, above) precisely so
/// it satisfies this shape, and the `ScriptedTransport` test fixture near
/// `dumpOver`'s tests satisfies the same shape without a real socket.
fn awaitFlowOver(transport: anytype, seq: u32) RequestError!Flow {
    var msgs: u32 = 0;
    while (true) {
        if (msgs >= max_await_messages) return error.TooManyMessages;
        const dgram = try transport.recvDatagram();
        msgs += 1;
        var it: codec.MessageIterator = .{ .buf = dgram };
        while (it.next() catch return error.MalformedReply) |m| {
            if (m.pid != transport.portId() or m.seq != seq) continue;
            switch (m.type) {
                codec.NLMSG_ERROR => {
                    const code = m.errorCode() catch return error.MalformedReply;
                    transport.captureExtAck(m);
                    // A bare ACK carries no entry — treat it like ENOENT.
                    if (code == 0) return error.NotFound;
                    return netlink.writeErrorFromCode(code);
                },
                codec.NLMSG_OVERRUN => return error.Overrun,
                wire.msg_ct_new => return wire.decodeFlow(m.payload) catch
                    error.MalformedReply,
                else => {},
            }
        }
    }
}

/// The multi-part dump engine, factored out of `Socket.dump` so it is a **seam**
/// like `EventIterator`: everything here is ctnetlink policy (which request,
/// which reply type, which decoder, the `NLM_F_DUMP_INTR` retry budget), while
/// `transport` owns the blocking I/O. In production that is a `*Socket`; in the
/// tests it is a scripted fixture, which is the only way to reach the restart
/// path deterministically — a live dump on a quiet host never sets
/// `NLM_F_DUMP_INTR`.
///
/// `transport` must offer `nextSeq()`, `send(bytes)`, `recvDatagram()`,
/// `portId()` and `captureExtAck(msg)`.
///
/// **Ownership**: `out` is declared once, *outside* the retry loop, and the
/// single `errdefer` is its only destructor. A restart calls
/// `clearRetainingCapacity` rather than `deinit`, because `continue :retry` does
/// not run an errdefer but `return error.InconsistentDump` on the next line
/// does — deinit-ing on restart and then letting the errdefer fire freed the
/// same buffer twice (`std.ArrayList.deinit` leaves `self.* = undefined`, so the
/// second free is on a garbage pointer).
fn dumpOver(gpa: std.mem.Allocator, transport: anytype, family: Family) DumpError![]Flow {
    var out: std.ArrayList(Flow) = .empty;
    errdefer out.deinit(gpa);

    var attempt: usize = 0;
    retry: while (true) {
        attempt += 1;
        const seq = transport.nextSeq();
        const req = wire.buildDumpRequest(seq, family);
        try transport.send(&req);

        while (true) {
            const dgram = try transport.recvDatagram();
            var it: codec.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                switch (netlink.classifyDumpMessage(m, transport.portId(), seq)) {
                    .skip => {},
                    .restart => {
                        // The table changed under the dump: what we have may be
                        // inconsistent, so start over with a fresh sequence.
                        // Only the *contents* are stale — keep the capacity.
                        out.clearRetainingCapacity();
                        if (attempt < max_dump_attempts) continue :retry;
                        return error.InconsistentDump;
                    },
                    .done => return out.toOwnedSlice(gpa),
                    .failed => |code| {
                        transport.captureExtAck(m);
                        return netlink.errorFromCode(code);
                    },
                    .overrun => return error.Overrun,
                    .malformed => return error.MalformedReply,
                    .record => |rec| {
                        if (rec.type != wire.msg_ct_new) continue;
                        const f = wire.decodeFlow(rec.payload) catch return error.MalformedReply;
                        try out.append(gpa, f);
                    },
                }
            }
        }
    }
}

/// Walks one received datagram, yielding every conntrack event in it. Pure: it
/// never blocks and never touches a socket, so a caller with its own event loop
/// can feed it bytes from anywhere (a test fixture, a replayed capture).
pub const EventIterator = struct {
    msgs: codec.MessageIterator,

    pub fn next(it: *EventIterator) DecodeError!?Event {
        while (try it.msgs.next()) |m| {
            const kind = eventKind(m) orelse continue;
            return .{ .kind = kind, .flow = try wire.decodeFlow(m.payload) };
        }
        return null;
    }
};

/// Classify an event message. The kernel's `ctnetlink_conntrack_event` sends a
/// destroy as `IPCTNL_MSG_CT_DELETE`, a brand-new flow as `IPCTNL_MSG_CT_NEW`
/// with `NLM_F_CREATE|NLM_F_EXCL`, and every other change as a bare
/// `IPCTNL_MSG_CT_NEW` — the flags are the only thing separating "new" from
/// "update". Anything else (NLMSG_DONE, a stray reply) is null.
pub fn eventKind(m: codec.Message) ?EventKind {
    return switch (m.type) {
        wire.msg_ct_delete => .destroy,
        wire.msg_ct_new => if (m.flags & codec.NLM_F_CREATE != 0) .new else .update,
        else => null,
    };
}

// ── offline tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const goldens = @import("goldens.zig");

test "re-exports keep the wire layer reachable from the module root" {
    try testing.expectEqual(@as(u16, 0x0100), msg_ct_new);
    try testing.expectEqual(@as(u16, 0x0101), msg_ct_get);
    try testing.expectEqual(@as(u16, 0x0102), msg_ct_delete);
    try testing.expectEqual(@as(u8, 2), @intFromEnum(Family.ipv4));
    try testing.expectEqual(@as(u8, 10), @intFromEnum(Family.ipv6));
}

test "event classification follows ctnetlink_conntrack_event" {
    const new: codec.Message = .{
        .type = wire.msg_ct_new,
        .flags = codec.NLM_F_CREATE | codec.NLM_F_EXCL,
        .seq = 0,
        .pid = 0,
        .payload = &.{},
    };
    const upd: codec.Message = .{ .type = wire.msg_ct_new, .flags = 0, .seq = 0, .pid = 0, .payload = &.{} };
    const del: codec.Message = .{ .type = wire.msg_ct_delete, .flags = 0, .seq = 0, .pid = 0, .payload = &.{} };
    const done: codec.Message = .{ .type = codec.NLMSG_DONE, .flags = 0, .seq = 0, .pid = 0, .payload = &.{} };
    try testing.expectEqual(EventKind.new, eventKind(new).?);
    try testing.expectEqual(EventKind.update, eventKind(upd).?);
    try testing.expectEqual(EventKind.destroy, eventKind(del).?);
    try testing.expectEqual(@as(?EventKind, null), eventKind(done));
}

test "EventIterator decodes a replayed multi-message datagram" {
    // The captured dump reply is a stream of IPCTNL_MSG_CT_NEW messages — the
    // same shape an update-event datagram has (NLM_F_MULTI is not a flag
    // eventKind looks at), so it doubles as an event fixture.
    var it: EventIterator = .{ .msgs = .{ .buf = &goldens.dump_reply_three_flows } };
    var n: usize = 0;
    while (try it.next()) |ev| {
        try testing.expectEqual(EventKind.update, ev.kind);
        try testing.expect(ev.flow.orig.isComplete());
        n += 1;
    }
    try testing.expectEqual(@as(usize, 3), n);

    // A destroy datagram: the captured `conntrack -D` request is a genuine
    // IPCTNL_MSG_CT_DELETE message, byte-for-byte the shape of a destroy event.
    var del: EventIterator = .{ .msgs = .{ .buf = &goldens.delete_request_udp4 } };
    const ev = (try del.next()).?;
    try testing.expectEqual(EventKind.destroy, ev.kind);
    try testing.expect(ev.flow.orig.src.?.eql(.{ .v4 = .{ 10, 0, 0, 1 } }));
    try testing.expectEqual(@as(?Event, null), try del.next());
}

test "EventIterator rejects a malformed message without over-reading" {
    // nlmsg_len = 200 inside a 20-byte buffer.
    var bad: [20]u8 = @splat(0);
    std.mem.writeInt(u32, bad[0..4], 200, native_endian);
    std.mem.writeInt(u16, bad[4..6], wire.msg_ct_new, native_endian);
    var it: EventIterator = .{ .msgs = .{ .buf = &bad } };
    try testing.expectError(error.Truncated, it.next());

    // Well-formed header, truncated nfgenmsg.
    var short: [18]u8 = @splat(0);
    std.mem.writeInt(u32, short[0..4], 18, native_endian);
    std.mem.writeInt(u16, short[4..6], wire.msg_ct_delete, native_endian);
    var it2: EventIterator = .{ .msgs = .{ .buf = &short } };
    try testing.expectError(error.Truncated, it2.next());
}

test "group masks match the kernel's 1-based nfnetlink_groups enum" {
    try testing.expectEqual(@as(u32, 0b001), Group.CONNTRACK_NEW);
    try testing.expectEqual(@as(u32, 0b010), Group.CONNTRACK_UPDATE);
    try testing.expectEqual(@as(u32, 0b100), Group.CONNTRACK_DESTROY);
    try testing.expectEqual(@as(u32, 0b111), Group.all_conntrack);
}

// ── dump-engine tests (scripted transport, no kernel involved) ─────────────

/// A scripted stand-in for `Socket` in `dumpOver`: hands out canned datagrams in
/// order and counts requests. It exists because the `NLM_F_DUMP_INTR` restart
/// path — and with it the retry budget — is unreachable from a live test: it
/// needs the kernel's conntrack table to churn under the dump, four times
/// running. Everything the engine does *around* the collected flows (ownership,
/// how many requests it sends, what it returns when the budget runs out) is
/// otherwise untested.
const ScriptedTransport = struct {
    /// The datagrams the engine will "receive", in order.
    script: []const []const u8,
    pos: usize = 0,
    /// How many dump requests the engine sent — i.e. attempts made.
    requests: usize = 0,
    /// The identity the canned datagrams carry, so `classifyDumpMessage` matches
    /// them instead of skipping them as stale.
    pid: u32,
    seq: u32,

    fn nextSeq(self: *ScriptedTransport) u32 {
        return self.seq;
    }
    fn portId(self: *const ScriptedTransport) u32 {
        return self.pid;
    }
    fn captureExtAck(_: *ScriptedTransport, _: codec.Message) void {}
    fn send(self: *ScriptedTransport, _: []const u8) SendError!void {
        self.requests += 1;
    }
    fn recvDatagram(self: *ScriptedTransport) RecvError![]const u8 {
        // Running off the end means the engine asked for more than the scenario
        // scripted — a test bug, surfaced as an error rather than a hang.
        if (self.pos == self.script.len) return error.RecvFailed;
        defer self.pos += 1;
        return self.script[self.pos];
    }
};

/// The `(pid, seq)` the captured `conntrack -L` reply was addressed to; read out
/// of the golden rather than retyped.
fn goldenDumpIdentity() struct { pid: u32, seq: u32 } {
    var it: codec.MessageIterator = .{ .buf = &goldens.dump_reply_three_flows };
    const m = (it.next() catch unreachable).?;
    return .{ .pid = m.pid, .seq = m.seq };
}

/// A bare control datagram carrying `flags` — `NLM_F_DUMP_INTR` for the
/// "table changed under the dump" signal the kernel stamps on `netlink_dump`
/// output, or plain `NLM_F_MULTI` for the terminating `NLMSG_DONE`.
fn controlDatagram(pid: u32, seq: u32, flags: u16) [codec.header_len]u8 {
    var b: [codec.header_len]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], codec.header_len, native_endian);
    std.mem.writeInt(u16, b[4..6], codec.NLMSG_DONE, native_endian);
    std.mem.writeInt(u16, b[6..8], flags, native_endian);
    std.mem.writeInt(u32, b[8..12], seq, native_endian);
    std.mem.writeInt(u32, b[12..16], pid, native_endian);
    return b;
}

test "dump engine: a clean multi-part reply is collected and handed over" {
    const id = goldenDumpIdentity();
    const done = controlDatagram(id.pid, id.seq, codec.NLM_F_MULTI);
    var t: ScriptedTransport = .{
        .script = &.{ &goldens.dump_reply_three_flows, &done },
        .pid = id.pid,
        .seq = id.seq,
    };
    const flows = try dumpOver(testing.allocator, &t, .unspec);
    defer testing.allocator.free(flows);
    try testing.expectEqual(@as(usize, 3), flows.len);
    try testing.expectEqual(@as(usize, 1), t.requests);
}

test "dump engine: NLM_F_DUMP_INTR restarts and the retry replaces the stale flows" {
    const id = goldenDumpIdentity();
    const intr = controlDatagram(id.pid, id.seq, codec.NLM_F_MULTI | codec.NLM_F_DUMP_INTR);
    const done = controlDatagram(id.pid, id.seq, codec.NLM_F_MULTI);
    var t: ScriptedTransport = .{
        .script = &.{
            &goldens.dump_reply_three_flows, &intr, // first pass: interrupted
            &goldens.dump_reply_three_flows, &done, // second pass: completes
        },
        .pid = id.pid,
        .seq = id.seq,
    };
    const flows = try dumpOver(testing.allocator, &t, .unspec);
    defer testing.allocator.free(flows);
    // 3, not 6: the interrupted pass's flows are discarded, not appended to.
    try testing.expectEqual(@as(usize, 3), flows.len);
    try testing.expectEqual(@as(usize, 2), t.requests);
}

test "dump engine: an exhausted DUMP_INTR budget errors without freeing twice" {
    // The W2-07 regression. Four interrupted attempts take the *error* return,
    // which is the one path where an errdefer fires — so a `deinit` in the
    // restart branch would free the already-freed buffer a second time. The
    // flows collected before each restart matter: they make the ArrayList own a
    // real allocation, without which the double free is a no-op.
    const id = goldenDumpIdentity();
    const intr = controlDatagram(id.pid, id.seq, codec.NLM_F_MULTI | codec.NLM_F_DUMP_INTR);
    var t: ScriptedTransport = .{
        .script = &.{
            &goldens.dump_reply_three_flows, &intr,
            &goldens.dump_reply_three_flows, &intr,
            &goldens.dump_reply_three_flows, &intr,
            &goldens.dump_reply_three_flows, &intr,
        },
        .pid = id.pid,
        .seq = id.seq,
    };
    try testing.expectError(error.InconsistentDump, dumpOver(testing.allocator, &t, .unspec));
    try testing.expectEqual(@as(usize, max_dump_attempts), t.requests);
    // The whole script was consumed: the budget is 4 attempts, not 3 or 5.
    try testing.expectEqual(t.script.len, t.pos);
}

test "dump engine: a kernel error reply is mapped and stops the dump" {
    const id = goldenDumpIdentity();
    var err_dgram: [codec.header_len + 4]u8 = @splat(0);
    std.mem.writeInt(u32, err_dgram[0..4], err_dgram.len, native_endian);
    std.mem.writeInt(u16, err_dgram[4..6], codec.NLMSG_ERROR, native_endian);
    std.mem.writeInt(u32, err_dgram[8..12], id.seq, native_endian);
    std.mem.writeInt(u32, err_dgram[12..16], id.pid, native_endian);
    std.mem.writeInt(i32, err_dgram[16..20], -1, native_endian); // -EPERM
    var t: ScriptedTransport = .{
        .script = &.{ &goldens.dump_reply_three_flows, &err_dgram },
        .pid = id.pid,
        .seq = id.seq,
    };
    // The flows collected before the error are released by the engine's
    // errdefer; std.testing.allocator fails the test if they are not.
    try testing.expectError(error.AccessDenied, dumpOver(testing.allocator, &t, .unspec));
}

// ── C-06 regression: awaitFlow must not spin forever ───────────────────────
// W2-nn (`conntrack` F6, campaign C-06): `awaitFlow` looped on `recvDatagram`
// until a message matching `(portid, seq)` arrived, with no upper bound — a
// kernel that answers neither `NLMSG_ERROR` nor `IPCTNL_MSG_CT_NEW` on that
// sequence spun the caller forever. Reuses `ScriptedTransport`, the same
// fixture `dumpOver`'s tests above already use.

test "awaitFlow errors out instead of looping forever on a never-matching reply" {
    // A datagram addressed to a different (pid, seq) than the one awaitFlow
    // is waiting for, so it is skipped forever instead of ever matching.
    const bogus = controlDatagram(999, 999, 0);
    var script_buf: [max_await_messages][]const u8 = undefined;
    for (&script_buf) |*s| s.* = &bogus;
    var t: ScriptedTransport = .{ .script = &script_buf, .pid = 1, .seq = 42 };
    try testing.expectError(error.TooManyMessages, awaitFlowOver(&t, 42));
    try testing.expectEqual(t.script.len, t.pos);
}

test "fuzz: the dump engine survives any interleaving of dump replies" {
    try testing.fuzz({}, fuzzDumpEngine, .{});
}

/// The dump *engine* had no fuzz reach at all — `wire.zig`'s harness stops at
/// `decodeFlow`, so nothing exercised the retry budget, the errdefer or the
/// ownership of the collected flows. This drives `dumpOver` with an arbitrary
/// interleaving of the datagram kinds a kernel can send, on `std.testing`'s
/// allocator, so a leak, a double free or a use-after-free on any exit path is a
/// finding rather than a silent survivor. (The W2-07 double free needed four
/// consecutive `NLM_F_DUMP_INTR`, which is exactly the kind of sequence a
/// scripted unit test only reaches if somebody already suspects it.)
fn fuzzDumpEngine(_: void, smith: *std.testing.Smith) !void {
    const id = goldenDumpIdentity();
    const intr = controlDatagram(id.pid, id.seq, codec.NLM_F_MULTI | codec.NLM_F_DUMP_INTR);
    const done = controlDatagram(id.pid, id.seq, codec.NLM_F_MULTI);

    var failed: [codec.header_len + 4]u8 = @splat(0);
    std.mem.writeInt(u32, failed[0..4], failed.len, native_endian);
    std.mem.writeInt(u16, failed[4..6], codec.NLMSG_ERROR, native_endian);
    std.mem.writeInt(u32, failed[8..12], id.seq, native_endian);
    std.mem.writeInt(u32, failed[12..16], id.pid, native_endian);
    std.mem.writeInt(i32, failed[16..20], -@as(i32, smith.value(u8)), native_endian);

    var junk: [128]u8 = undefined;
    smith.bytes(&junk);

    var script: [16][]const u8 = undefined;
    const n = smith.valueRangeAtMost(u8, 1, script.len);
    for (script[0..n]) |*d| {
        d.* = switch (smith.value(u8) % 5) {
            0 => &goldens.dump_reply_three_flows,
            1 => &intr,
            2 => &done,
            3 => &failed,
            else => junk[0..smith.valueRangeAtMost(u8, 0, junk.len)],
        };
    }

    var t: ScriptedTransport = .{ .script = script[0..n], .pid = id.pid, .seq = id.seq };
    const flows = dumpOver(testing.allocator, &t, .unspec) catch return;
    testing.allocator.free(flows);
}

// ── live tests (real kernel; skip cleanly when they cannot run) ─────────────
//
// Full coverage needs CAP_NET_ADMIN in a network namespace:
//
//     unshare -rn zig build test-conntrack
//
// Without it the ctnetlink socket still opens but every operation answers
// EPERM, and without `nf_conntrack` the kernel answers EPERM/EOPNOTSUPP too —
// in both cases the tests below print a SKIPPED line and pass. The repo's
// plain `zig build test` must stay green for an unprivileged user.

fn liveSocket(what: []const u8) ?Socket {
    if (builtin.os.tag != .linux) return null;
    var sock = Socket.open(testing.allocator) catch |err| {
        if (verboseSkip()) std.debug.print(
            "\nLIVE conntrack {s} test SKIPPED: cannot open a NETLINK_NETFILTER socket ({s}).\n",
            .{ what, @errorName(err) },
        );
        return null;
    };
    // Never let a live test hang a CI run: no ctnetlink reply takes seconds.
    sock.setRecvTimeout(5000) catch {};
    return sock;
}

test "live: dump the conntrack table over a real ctnetlink socket" {
    var sock = liveSocket("dump") orelse return;
    defer sock.close();

    const flows = sock.dump(.unspec) catch |err| switch (err) {
        // EPERM (no CAP_NET_ADMIN) / EOPNOTSUPP (nf_conntrack absent).
        error.AccessDenied,
        error.InvalidRequest,
        error.WouldBlock,
        error.Unexpected,
        => {
            if (verboseSkip()) std.debug.print(
                "\nLIVE conntrack dump test SKIPPED: the kernel refused the dump ({s}) — " ++
                    "needs CAP_NET_ADMIN and a loaded nf_conntrack.\n",
                .{@errorName(err)},
            );
            return;
        },
        else => return err,
    };
    defer testing.allocator.free(flows);

    // Whatever came back must be internally consistent.
    for (flows) |f| {
        try testing.expect(f.orig.isComplete());
        try testing.expect(f.reply.isComplete());
        try testing.expect(f.family == .ipv4 or f.family == .ipv6);
        try testing.expectEqual(f.family, f.orig.family());
        const proto = f.orig.proto.?;
        if (proto == IPPROTO.TCP or proto == IPPROTO.UDP) {
            try testing.expect(f.orig.src_port != null);
            try testing.expect(f.orig.dst_port != null);
        }
    }
    // Success-path diagnostic: gated because scripts/test-lib.sh treats any
    // stderr from a passing step as a failure — a rule that only holds if
    // passing tests stay silent.
    if (verboseSkip()) std.debug.print("\nLIVE conntrack dump: {d} flow(s) decoded.\n", .{flows.len});
}

test "live: insert -> get -> dump -> delete round-trip (needs a netns)" {
    var sock = liveSocket("round-trip") orelse return;
    defer sock.close();

    // Documentation-range addresses (RFC 5737) on high ports: nothing real can
    // collide with this tuple.
    const orig: Tuple = .{
        .src = .{ .v4 = .{ 198, 51, 100, 17 } },
        .dst = .{ .v4 = .{ 203, 0, 113, 42 } },
        .proto = IPPROTO.UDP,
        .src_port = 59321,
        .dst_port = 59322,
    };
    const spec: NewSpec = .{
        .orig = orig,
        .reply = orig.invert(),
        .timeout = 120,
        .mark = 0x5a5a,
        // IPS_CONFIRMED is mandatory here: the kernel diffs the status we send
        // against the one it already put on the fresh entry and rejects a
        // request that would clear IPS_CONFIRMED with EBUSY (see NewSpec.status).
        .status = IPS.SEEN_REPLY | IPS.CONFIRMED,
    };

    sock.insert(.ipv4, spec) catch |err| switch (err) {
        error.AccessDenied,
        error.NotSupported,
        error.InvalidRequest,
        error.WouldBlock,
        error.Unexpected,
        => {
            if (verboseSkip()) std.debug.print(
                "\nLIVE conntrack round-trip test SKIPPED: insert refused ({s}{s}{s}) — " ++
                    "run it as `unshare -rn zig build test-conntrack`.\n",
                .{
                    @errorName(err),
                    if (sock.lastErrorMessage().len > 0) ": " else "",
                    sock.lastErrorMessage(),
                },
            );
            return;
        },
        error.Exists => {
            if (verboseSkip()) std.debug.print(
                "\nLIVE conntrack round-trip test SKIPPED: the test tuple is already tracked.\n",
                .{},
            );
            return;
        },
        else => return err,
    };
    // From here on the entry exists and must be cleaned up on any failure.
    errdefer sock.delete(.ipv4, .orig, orig, null) catch {};

    // 1) get it back by its original tuple.
    const got = (try sock.get(.ipv4, .orig, orig)) orelse return error.TestUnexpectedResult;
    try testing.expect(got.orig.src.?.eql(orig.src.?));
    try testing.expectEqual(@as(u16, 59321), got.orig.src_port.?);
    try testing.expectEqual(@as(u16, 59322), got.reply.src_port.?);
    try testing.expectEqual(@as(u32, 0x5a5a), got.mark.?);
    try testing.expect(got.timeout.? <= 120);
    try testing.expect(got.hasStatus(IPS.SEEN_REPLY | IPS.CONFIRMED));
    try testing.expect(got.id != null);

    // 2) …and by the reply tuple, which must name the same entry.
    const via_reply = (try sock.get(.ipv4, .reply, orig.invert())) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(got.id.?, via_reply.id.?);

    // 3) it shows up in a dump exactly once.
    const flows = try sock.dump(.ipv4);
    defer testing.allocator.free(flows);
    var seen: usize = 0;
    for (flows) |f| {
        if (f.id == got.id) seen += 1;
    }
    try testing.expectEqual(@as(usize, 1), seen);

    // 4) a compare-and-delete against the wrong id must not remove anything.
    try testing.expectError(
        error.NotFound,
        sock.delete(.ipv4, .orig, orig, got.id.? ^ 0xffff_ffff),
    );
    try testing.expect((try sock.get(.ipv4, .orig, orig)) != null);

    // 5) …and against the right one removes exactly it.
    try sock.delete(.ipv4, .orig, orig, got.id.?);
    try testing.expectEqual(@as(?Flow, null), try sock.get(.ipv4, .orig, orig));
    try testing.expectError(error.NotFound, sock.delete(.ipv4, .orig, orig, null));

    // Success-path diagnostic: gated because scripts/test-lib.sh treats any
    // stderr from a passing step as a failure — a rule that only holds if
    // passing tests stay silent.
    if (verboseSkip()) std.debug.print(
        "\nLIVE conntrack round-trip: insert/get/dump/delete OK (id 0x{x}).\n",
        .{got.id.?},
    );
}

test "live: an event socket sees the flow another socket creates" {
    if (builtin.os.tag != .linux) return;
    var events = Socket.openEvents(testing.allocator, Group.all_conntrack) catch |err| {
        if (verboseSkip()) std.debug.print(
            "\nLIVE conntrack event test SKIPPED: cannot bind the conntrack event groups ({s}) — " ++
                "needs CAP_NET_ADMIN.\n",
            .{@errorName(err)},
        );
        return;
    };
    defer events.close();
    // The kernel may deliver nothing at all (events compiled out); a bounded
    // wait keeps the test from hanging and turns that into a SKIP.
    events.setRecvTimeout(2000) catch {};

    var ctl = liveSocket("event") orelse return;
    defer ctl.close();

    const orig: Tuple = .{
        .src = .{ .v4 = .{ 198, 51, 100, 18 } },
        .dst = .{ .v4 = .{ 203, 0, 113, 43 } },
        .proto = IPPROTO.UDP,
        .src_port = 59421,
        .dst_port = 59422,
    };
    ctl.insert(.ipv4, .{ .orig = orig, .reply = orig.invert(), .timeout = 60 }) catch |err| {
        if (verboseSkip()) std.debug.print(
            "\nLIVE conntrack event test SKIPPED: insert refused ({s}).\n",
            .{@errorName(err)},
        );
        return;
    };
    defer ctl.delete(.ipv4, .orig, orig, null) catch {};

    // The insert queued a NEW event before its ACK came back, so the first
    // datagrams are already waiting; the loop is the caller-owned seam.
    var found = false;
    var datagrams: usize = 0;
    while (datagrams < 8 and !found) : (datagrams += 1) {
        var it = events.nextEvents() catch |err| {
            if (verboseSkip()) std.debug.print(
                "\nLIVE conntrack event test SKIPPED: no event datagram ({s}).\n",
                .{@errorName(err)},
            );
            return;
        };
        while (try it.next()) |ev| {
            if (ev.flow.orig.src_port == 59421 and ev.kind == .new) found = true;
        }
    }
    try testing.expect(found);
    // Success-path diagnostic: gated because scripts/test-lib.sh treats any
    // stderr from a passing step as a failure — a rule that only holds if
    // passing tests stay silent.
    if (verboseSkip()) std.debug.print("\nLIVE conntrack events: NEW event observed for the inserted flow.\n", .{});
}
