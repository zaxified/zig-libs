// SPDX-License-Identifier: MIT

//! The privileged half of the native backend: a blocking `NETLINK_NETFILTER`
//! socket that commits nftables batches and dumps the ruleset back.
//!
//! ```zig
//! var sock = try nftables.Socket.open(gpa);
//! defer sock.close();
//!
//! var batch = try sock.beginBatch(.{});
//! defer batch.deinit();
//! try batch.addTable(.{ .family = .inet, .name = "filter" });
//! try batch.addChain(.{ .family = .inet, .table = "filter", .name = "input",
//!                       .chain_type = .filter, .hook = .input, .prio = 0,
//!                       .policy = .drop });
//! sock.commit(&batch) catch |err| {
//!     const f = sock.lastFailure().?;       // which command, and why
//!     std.log.err("{s} #{?d}: {s}", .{ f.command, f.index, f.message });
//!     return err;
//! };
//! ```
//!
//! Everything the kernel is told travels through `wire.Batch`, so the atomicity
//! guarantee is structural: one `sendmsg`, all-or-nothing.
//!
//! **Transport is the sibling `netlink` module's.** Socket creation and bind,
//! port-id capture, `NETLINK_EXT_ACK`, the sequence counter, the
//! `MSG_PEEK|MSG_TRUNC` buffer-growth loop, `SO_RCVTIMEO` and the extended-ACK
//! capture all come from `netlink.Socket`, opened on `linux.NETLINK.NETFILTER`
//! via `openProtocol`; the multi-part reply triage of `dumpInto` is
//! `netlink.classifyDumpMessage` (re-exported as `nl.classifyDumpMessage`).
//! Only the policy above them is per-family and lives here: which request,
//! which reply type, which decoder, which errno mapping — plus the batch ACK
//! engine, which is nf_tables-specific (it counts one ACK per staged command
//! and attributes a failure to the offending command, rather than waiting for
//! a single reply to a single sequence number).

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

const nl = @import("nl.zig");
const types = @import("types.zig");
const expr = @import("expr.zig");
const wire = @import("wire.zig");

const native_endian = builtin.cpu.arch.endian();
const Family = types.Family;

// ── errors ──────────────────────────────────────────────────────────────────

pub const OpenError = error{
    OutOfMemory,
    AccessDenied,
    /// Kernel without `AF_NETLINK`/`NETLINK_NETFILTER`.
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
    /// A reply failed wire-format validation.
    MalformedReply,
    /// The kernel dropped messages because the receive buffer was full.
    Overrun,
    /// Nothing to read, or the receive timeout expired.
    WouldBlock,
    SystemResources,
};

/// Errors the kernel can answer a batch with, mapped from errno.
pub const KernelError = error{
    AccessDenied,
    /// `EEXIST` — the object is already there and `NLM_F_EXCL` was set.
    Exists,
    /// `ENOENT` — a referenced table/chain/set/rule does not exist.
    NotFound,
    /// `EINVAL`/`ERANGE` — the kernel rejected the request's contents.
    InvalidRequest,
    /// `EOPNOTSUPP`/`ENOTSUPP` — the kernel lacks the feature.
    NotSupported,
    /// `EBUSY` — the object is in use (e.g. a chain with rules jumping to it).
    Busy,
    /// `ENOSPC` — a set is full.
    NoSpaceLeft,
    /// `EPERM` without CAP_NET_ADMIN, `EAFNOSUPPORT`, anything unmapped.
    KernelRejected,
};

/// `TooManyMessages`: the reply loop consumed `max_await_messages` datagrams
/// without the awaited ACKs (or commit error) arriving. A kernel that stops
/// answering used to spin `commit` forever (sweep NF-2).
pub const CommitError = KernelError || SendError || RecvError || wire.BuildError ||
    error{TooManyMessages};
/// `TooManyMessages`: one dump attempt consumed `max_dump_messages` datagrams
/// without `NLMSG_DONE`, or delivered more than `max_dump_records` payload
/// messages. Ask for a narrower dump (table/chain/family) instead (sweep NF-2).
pub const DumpError = KernelError || SendError || RecvError || wire.BuildError ||
    error{ InconsistentDump, OutOfMemory, TooManyMessages };

fn errorFromErrno(code: i32) KernelError {
    // The kernel reports `-errno`. `minInt(i32)` has no positive counterpart
    // (`-code` overflows) and is no errno: unmapped (sweep NF-1).
    if (code == std.math.minInt(i32)) return error.KernelRejected;
    const e: u32 = @intCast(if (code < 0) -code else code);
    return switch (e) {
        1 => error.KernelRejected, // EPERM
        2 => error.NotFound, // ENOENT
        13 => error.AccessDenied, // EACCES
        16 => error.Busy, // EBUSY
        17 => error.Exists, // EEXIST
        22 => error.InvalidRequest, // EINVAL
        28 => error.NoSpaceLeft, // ENOSPC
        34 => error.InvalidRequest, // ERANGE
        95 => error.NotSupported, // EOPNOTSUPP
        else => error.KernelRejected,
    };
}

/// Everything known about a rejected batch. Valid until the next operation on
/// the socket.
pub const Failure = struct {
    /// Whether one staged command was rejected or the transaction failed as a
    /// whole at commit time.
    stage: wire.Stage,
    /// The `nlmsg_seq` the kernel complained about.
    seq: u32,
    /// Position of the failing command in the batch (null for a commit-stage
    /// failure — the kernel reports those against `BATCH_BEGIN`).
    index: ?usize,
    /// `NFT_MSG_*` name of the failing command, or "BATCH_BEGIN"/"?".
    command: []const u8,
    /// The raw negative errno.
    code: i32,
    /// The kernel's extended-ACK reason string, empty when none was attached.
    message: []const u8,
};

const max_dump_attempts = 4;

/// Datagram budget of one dump attempt and of the batch-ACK wait — the same
/// robustness ceilings as the identical constants in `netlink` (65536): a
/// kernel that never terminates the reply no longer spins the caller forever.
/// `max_dump_records` (4 Mi, `netlink.max_dump_records`) additionally bounds
/// how many payload messages — i.e. how much memory — one dump attempt may
/// collect. Reaching either is `error.TooManyMessages`.
const max_dump_messages: u32 = 65536;
const max_await_messages: u32 = 65536;
const max_dump_records: u32 = netlink.max_dump_records;

// ── socket ──────────────────────────────────────────────────────────────────

/// A blocking `NETLINK_NETFILTER` socket. One instance per thread/loop.
pub const Socket = struct {
    /// The shared netlink transport, bound to `NETLINK_NETFILTER`.
    nl: netlink.Socket,
    failure: ?Failure = null,

    pub fn open(gpa: std.mem.Allocator) OpenError!Socket {
        if (comptime builtin.os.tag != .linux)
            @compileError("nftables.Socket is Linux-only (AF_NETLINK raw syscalls)");
        return .{ .nl = try netlink.Socket.openProtocol(gpa, linux.NETLINK.NETFILTER) };
    }

    pub fn close(self: *Socket) void {
        self.nl.close();
        self.* = undefined;
    }

    /// Next request sequence number (never 0).
    pub fn nextSeq(self: *Socket) u32 {
        return self.nl.nextSeq();
    }

    /// The raw file descriptor, for poll/epoll integration. Do not close it.
    pub fn handle(self: *const Socket) i32 {
        return self.nl.handle();
    }

    /// Bound how long a receive may block (`SO_RCVTIMEO`); 0 restores blocking
    /// forever. A timeout surfaces as `error.WouldBlock`.
    pub fn setRecvTimeout(self: *Socket, millis: u32) error{Unexpected}!void {
        return self.nl.setRecvTimeout(millis);
    }

    /// Details of the last rejected batch, or null. Valid until the next
    /// operation on this socket.
    pub fn lastFailure(self: *const Socket) ?Failure {
        return self.failure;
    }

    /// The kernel's reason string for the last failure ("" when none).
    pub fn lastErrorMessage(self: *const Socket) []const u8 {
        return self.nl.lastErrorMessage();
    }

    // ── batches ────────────────────────────────────────────────────────────

    /// Start a batch whose sequence numbers come from this socket's counter.
    pub fn beginBatch(self: *Socket, opts: wire.BatchOptions) wire.BuildError!wire.Batch {
        return wire.Batch.init(self.nl.gpa, self.nextSeq(), opts);
    }

    /// Send the batch as one `sendmsg` and wait for the kernel's verdict.
    ///
    /// Either every command applies or none does — the kernel aborts the whole
    /// transaction on the first failure, so a returned error means the ruleset
    /// is exactly as it was. `lastFailure()` then names the offending command.
    ///
    /// With `BatchOptions.ack` (the default) every command is acknowledged and
    /// success is positive. With `.ack = false` — `nft`'s framing — success is
    /// the *absence* of an error, so a receive timeout must be set
    /// (`setRecvTimeout`) and a timeout is reported as success.
    pub fn commit(self: *Socket, batch: *wire.Batch) CommitError!void {
        const bytes = try batch.finish();
        // Keep the socket's counter past everything the batch consumed.
        self.nl.seq = batch.next_seq -% 1;
        self.failure = null;
        self.nl.ext_ack_len = 0;
        try self.send(bytes);
        return self.awaitBatch(batch);
    }

    fn awaitBatch(self: *Socket, batch: *const wire.Batch) CommitError!void {
        return awaitBatchOver(self, batch, max_await_messages);
    }

    fn recordFailure(self: *Socket, batch: *const wire.Batch, m: nl.Message, code: i32) void {
        self.nl.captureExtAck(m);
        // The reply's own seq is authoritative; the echoed request header
        // inside `struct nlmsgerr` must agree, and is used when the reply seq
        // is 0 (some kernels report the commit failure that way).
        const seq = if (m.seq != 0)
            m.seq
        else
            (m.errorRequestSeq() catch null) orelse m.seq;
        const entry = batch.entryForSeq(seq);
        self.failure = .{
            .stage = batch.stageForSeq(seq),
            .seq = seq,
            .index = if (entry) |e| e.index else null,
            .command = if (entry) |e|
                e.commandName()
            else if (seq == batch.first_seq)
                "BATCH_BEGIN"
            else
                "?",
            .code = code,
            .message = self.nl.lastErrorMessage(),
        };
    }

    // ── dumps ──────────────────────────────────────────────────────────────

    /// An owned dump result: the decoded items plus the arena their borrowed
    /// slices live in.
    pub fn List(comptime T: type) type {
        return struct {
            arena: std.heap.ArenaAllocator,
            items: []const T,

            pub fn deinit(self: *@This()) void {
                self.arena.deinit();
                self.* = undefined;
            }
        };
    }

    pub const TableList = List(wire.TableInfo);
    pub const ChainList = List(wire.ChainInfo);
    pub const RuleList = List(wire.RuleInfo);
    pub const SetList = List(wire.SetInfo);
    pub const SetElemList = List(wire.SetElemInfo);
    pub const ObjectList = List(wire.ObjectInfo);

    /// `family = null` sweeps every family in one dump — see
    /// `wire.buildDumpRequest`. Each result's `.family` names the concrete
    /// family the kernel reported that object under (`Family.fromNfproto`).
    pub fn listTables(self: *Socket, family: ?Family) DumpError!TableList {
        var out: TableList = .{ .arena = std.heap.ArenaAllocator.init(self.nl.gpa), .items = &.{} };
        errdefer out.arena.deinit();
        var items: std.ArrayList(wire.TableInfo) = .empty;
        const a = out.arena.allocator();
        const req = wire.buildDumpRequest(self.nextSeq(), wire.NFT_MSG.GETTABLE, family);
        try self.dumpInto(&req, wire.NFT_MSG.NEWTABLE, self.nl.seq, struct {
            fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.TableInfo), payload: []const u8) !void {
                var t = try wire.decodeTable(payload);
                t.name = try al.dupe(u8, t.name);
                try list.append(al, t);
            }
        }.f, a, &items);
        out.items = items.items;
        return out;
    }

    /// `family = null` sweeps every family in one dump — see `listTables`.
    pub fn listChains(self: *Socket, family: ?Family) DumpError!ChainList {
        var out: ChainList = .{ .arena = std.heap.ArenaAllocator.init(self.nl.gpa), .items = &.{} };
        errdefer out.arena.deinit();
        var items: std.ArrayList(wire.ChainInfo) = .empty;
        const a = out.arena.allocator();
        const req = wire.buildDumpRequest(self.nextSeq(), wire.NFT_MSG.GETCHAIN, family);
        try self.dumpInto(&req, wire.NFT_MSG.NEWCHAIN, self.nl.seq, struct {
            fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.ChainInfo), payload: []const u8) !void {
                var c = try wire.decodeChain(payload);
                c.table = try al.dupe(u8, c.table);
                c.name = try al.dupe(u8, c.name);
                if (c.chain_type) |t| c.chain_type = try al.dupe(u8, t);
                if (c.dev) |d| c.dev = try al.dupe(u8, d);
                try list.append(al, c);
            }
        }.f, a, &items);
        out.items = items.items;
        return out;
    }

    /// `family = null` sweeps every family in one dump — see `listTables`.
    pub fn listSets(self: *Socket, family: ?Family) DumpError!SetList {
        var out: SetList = .{ .arena = std.heap.ArenaAllocator.init(self.nl.gpa), .items = &.{} };
        errdefer out.arena.deinit();
        var items: std.ArrayList(wire.SetInfo) = .empty;
        const a = out.arena.allocator();
        const req = wire.buildDumpRequest(self.nextSeq(), wire.NFT_MSG.GETSET, family);
        try self.dumpInto(&req, wire.NFT_MSG.NEWSET, self.nl.seq, struct {
            fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.SetInfo), payload: []const u8) !void {
                var s = try wire.decodeSet(payload);
                s.table = try al.dupe(u8, s.table);
                s.name = try al.dupe(u8, s.name);
                try list.append(al, s);
            }
        }.f, a, &items);
        out.items = items.items;
        return out;
    }

    /// Dump the rules of one chain (or of everything when `table`/`chain` are
    /// null). `family = null` additionally sweeps every family in one dump —
    /// see `listTables`. `RuleInfo.expressions` is copied into the result's
    /// arena.
    pub fn listRules(
        self: *Socket,
        family: ?Family,
        table: ?[]const u8,
        chain: ?[]const u8,
    ) DumpError!RuleList {
        var out: RuleList = .{ .arena = std.heap.ArenaAllocator.init(self.nl.gpa), .items = &.{} };
        errdefer out.arena.deinit();
        var items: std.ArrayList(wire.RuleInfo) = .empty;
        const a = out.arena.allocator();
        const seq = self.nextSeq();
        const req = try wire.buildRuleDumpRequest(self.nl.gpa, seq, family, table, chain);
        defer self.nl.gpa.free(req);
        try self.dumpInto(req, wire.NFT_MSG.NEWRULE, seq, struct {
            fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.RuleInfo), payload: []const u8) !void {
                var r = try wire.decodeRule(payload);
                r.table = try al.dupe(u8, r.table);
                r.chain = try al.dupe(u8, r.chain);
                r.expressions = try al.dupe(u8, r.expressions);
                try list.append(al, r);
            }
        }.f, a, &items);
        out.items = items.items;
        return out;
    }

    /// Dump the named stateful objects (counters, quotas, …) with their
    /// current values. `family = null` sweeps every family — see
    /// `listTables`. Reading does not reset anything (`NFT_MSG_GETOBJ`, not
    /// `GETOBJ_RESET`).
    pub fn listObjects(self: *Socket, family: ?Family) DumpError!ObjectList {
        var out: ObjectList = .{ .arena = std.heap.ArenaAllocator.init(self.nl.gpa), .items = &.{} };
        errdefer out.arena.deinit();
        var items: std.ArrayList(wire.ObjectInfo) = .empty;
        const a = out.arena.allocator();
        const req = wire.buildDumpRequest(self.nextSeq(), wire.NFT_MSG.GETOBJ, family);
        try self.dumpInto(&req, wire.NFT_MSG.NEWOBJ, self.nl.seq, struct {
            fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.ObjectInfo), payload: []const u8) !void {
                var o = try wire.decodeObject(payload);
                o.table = try al.dupe(u8, o.table);
                o.name = try al.dupe(u8, o.name);
                o.data = try al.dupe(u8, o.data);
                try list.append(al, o);
            }
        }.f, a, &items);
        out.items = items.items;
        return out;
    }

    /// Dump the elements of one named set.
    pub fn listSetElems(
        self: *Socket,
        family: Family,
        table: []const u8,
        set: []const u8,
    ) DumpError!SetElemList {
        var out: SetElemList = .{ .arena = std.heap.ArenaAllocator.init(self.nl.gpa), .items = &.{} };
        errdefer out.arena.deinit();
        var items: std.ArrayList(wire.SetElemInfo) = .empty;
        const a = out.arena.allocator();
        const seq = self.nextSeq();
        const req = try wire.buildSetElemDumpRequest(self.nl.gpa, seq, family, table, set);
        defer self.nl.gpa.free(req);
        try self.dumpInto(req, wire.NFT_MSG.NEWSETELEM, seq, struct {
            fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.SetElemInfo), payload: []const u8) !void {
                const reply = try wire.decodeSetElemReply(payload);
                var eit = reply.iterator();
                while (try eit.next()) |el| {
                    var copy = el;
                    copy.key = try al.dupe(u8, el.key);
                    if (el.key_end) |k| copy.key_end = try al.dupe(u8, k);
                    if (el.data) |d| copy.data = try al.dupe(u8, d);
                    if (el.verdict) |v| if (v.chain) |c| {
                        copy.verdict.?.chain = try al.dupe(u8, c);
                    };
                    try list.append(al, copy);
                }
            }
        }.f, a, &items);
        out.items = items.items;
        return out;
    }

    fn dumpInto(
        self: *Socket,
        req: []const u8,
        want_type: u8,
        seq: u32,
        comptime append: anytype,
        arena: std.mem.Allocator,
        items: anytype,
    ) DumpError!void {
        self.failure = null;
        return dumpOver(self, self.nl.gpa, req, want_type, seq, append, arena, items, max_dump_messages, max_dump_records);
    }

    // `dumpOver`/`awaitBatchOver` call these on their `transport`; the scripted
    // transport of the sweep tests provides the same shapes.
    fn portId(self: *const Socket) u32 {
        return self.nl.portid;
    }

    fn captureExtAck(self: *Socket, m: nl.Message) void {
        self.nl.captureExtAck(m);
    }

    // ── transport (all of it `netlink.Socket`'s) ───────────────────────────

    /// Send one complete netlink datagram to the kernel.
    pub fn send(self: *Socket, msg: []const u8) SendError!void {
        return self.nl.send(msg);
    }

    /// Receive one whole datagram, growing the socket's buffer as needed via a
    /// `MSG_PEEK|MSG_TRUNC` size probe so nothing is lost to truncation.
    /// `Overrun` (the kernel dropped messages) and `WouldBlock` (nothing
    /// queued, or `setRecvTimeout` expired — how a successful un-acked batch
    /// looks) are reported as themselves.
    pub fn recvDatagram(self: *Socket) RecvError![]const u8 {
        return self.nl.recvDatagramStrict();
    }
};

// ── reply engines (free functions over a `transport`) ───────────────────────

/// The sequence number a failure reply is about: its own `seq`, or — for the
/// kernels that report a commit failure with seq 0 — the one in the echoed
/// request header.
fn replySeq(m: nl.Message) u32 {
    if (m.seq != 0) return m.seq;
    return (m.errorRequestSeq() catch null) orelse m.seq;
}

/// Is `seq` one of this batch's own sequence numbers — BATCH_BEGIN, the
/// commands, BATCH_END: `[first_seq, next_seq)` modulo 2^32 (`Batch.init`
/// wraps, so a batch may cross 0)?
fn inBatchWindow(batch: *const wire.Batch, seq: u32) bool {
    return seq -% batch.first_seq < batch.next_seq -% batch.first_seq;
}

/// The body of `Socket.awaitBatch`. `transport` offers `recvDatagram()`,
/// `portId()` and `recordFailure(batch, msg, code)`. Bounded by
/// `max_dgrams` datagrams (`error.TooManyMessages`). An `NLMSG_ERROR` whose
/// sequence number does not belong to this batch (`inBatchWindow`) is
/// somebody else's — a stale ACK left queued by an earlier exchange — and is
/// skipped, never counted as an ACK or reported as this batch's failure; the
/// window test runs before the payload is parsed, so a foreign short message
/// is skipped too (sweep NF-3, REV-5). In the un-acked mode a datagram whose
/// messages were ALL skipped does not end the wait: the batch's own error may
/// be right behind it (`WouldBlock` still means success) (sweep REV-3).
fn awaitBatchOver(transport: anytype, batch: *const wire.Batch, max_dgrams: u32) CommitError!void {
    const expected: usize = if (batch.opts.ack) batch.commandCount() else 0;
    var acks: usize = 0;
    var dgrams: u32 = 0;
    while (true) {
        if (dgrams >= max_dgrams) return error.TooManyMessages;
        const dgram = transport.recvDatagram() catch |err| switch (err) {
            // No reply at all is how a successful un-acked batch looks.
            error.WouldBlock => if (expected == 0) return else return err,
            else => return err,
        };
        dgrams += 1;
        var own = false;
        var skipped = false;
        var it: nl.MessageIterator = .{ .buf = dgram };
        while (it.next() catch return error.MalformedReply) |m| {
            if (m.pid != transport.portId()) {
                skipped = true;
                continue;
            }
            switch (m.type) {
                nl.NLMSG_ERROR => {
                    if (m.seq != 0 and !inBatchWindow(batch, m.seq)) {
                        skipped = true;
                        continue;
                    }
                    const code = m.errorCode() catch return error.MalformedReply;
                    if (!inBatchWindow(batch, replySeq(m))) {
                        skipped = true;
                        continue;
                    }
                    own = true;
                    if (code == 0) {
                        acks += 1;
                        if (acks >= expected and expected > 0) return;
                        continue;
                    }
                    transport.recordFailure(batch, m, code);
                    return errorFromErrno(code);
                },
                nl.NLMSG_OVERRUN => return error.Overrun,
                else => own = true, // NOOP / echo
            }
        }
        // Un-acked batch: nothing more is coming — unless all we saw was
        // someone else's traffic.
        if (expected == 0 and (own or !skipped)) return;
    }
}

/// The body of `Socket.dumpInto`. `transport` offers `send`, `recvDatagram`,
/// `portId`, `captureExtAck` and `nextSeq`. Per attempt: at most `max_dgrams`
/// datagrams, `max_records` payload messages and `max_records` produced items
/// (one message may decode to many, e.g. set elements) —
/// `error.TooManyMessages`.
///
/// `NLM_F_DUMP_INTR` does not restart at once: the kernel keeps the
/// interrupted dump running and answers a new request with `-EBUSY` until it
/// reached its `NLMSG_DONE`. The attempt is marked interrupted, the rest of
/// that dump is read and discarded (inside the datagram budget), and only at
/// its DONE is the request re-sent under a FRESH sequence number, patched into
/// an owned copy — the old dump's tail must not be taken for the new one's
/// (sweep NF-4, REV-2). A DONE carrying an errno, or an error, ends the dump
/// with that error.
fn dumpOver(
    transport: anytype,
    gpa: std.mem.Allocator,
    req: []const u8,
    want_type: u8,
    first_seq: u32,
    comptime append: anytype,
    arena: std.mem.Allocator,
    items: anytype,
    max_dgrams: u32,
    max_records: u32,
) DumpError!void {
    var seq = first_seq;
    var fresh: ?[]u8 = null; // owned copy, allocated on the first restart
    defer if (fresh) |f| gpa.free(f);
    var cur = req;
    var attempt: usize = 0;
    retry: while (true) {
        attempt += 1;
        try transport.send(cur);
        items.clearRetainingCapacity();
        var dgrams: u32 = 0;
        var records: u32 = 0;
        var interrupted = false;
        while (true) {
            if (dgrams >= max_dgrams) return error.TooManyMessages;
            const dgram = try transport.recvDatagram();
            dgrams += 1;
            var it: nl.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                var step = nl.classifyDumpMessage(m, transport.portId(), seq);
                if (step == .restart) {
                    interrupted = true;
                    // The flag can sit on the terminating message itself.
                    if (m.type == nl.NLMSG_DONE or m.type == nl.NLMSG_ERROR) {
                        var plain = m;
                        plain.flags &= ~nl.NLM_F_DUMP_INTR;
                        step = nl.classifyDumpMessage(plain, transport.portId(), seq);
                    }
                }
                switch (step) {
                    .skip => {},
                    .restart => {}, // still draining the interrupted dump
                    .done => {
                        if (!interrupted) return;
                        if (attempt >= max_dump_attempts) return error.InconsistentDump;
                        // Invariant: `req` is a request built by `wire` (>= 20 bytes);
                        // the only callers are `Socket.dumpInto`'s fixed builders.
                        std.debug.assert(req.len >= nl.header_len);
                        if (fresh == null) fresh = try gpa.dupe(u8, req);
                        seq = transport.nextSeq();
                        std.mem.writeInt(u32, fresh.?[8..12], seq, native_endian);
                        cur = fresh.?;
                        continue :retry;
                    },
                    .failed => |code| {
                        transport.captureExtAck(m);
                        return errorFromErrno(code);
                    },
                    .overrun => return error.Overrun,
                    .malformed => return error.MalformedReply,
                    .record => |rec| {
                        if (interrupted) continue; // discarded: the dump is restarted
                        if (records >= max_records) return error.TooManyMessages;
                        records += 1;
                        if (rec.type == wire.nftMsg(want_type)) {
                            append(arena, items, rec.payload) catch |err| switch (err) {
                                error.OutOfMemory => return error.OutOfMemory,
                                else => return error.MalformedReply,
                            };
                            if (items.items.len > max_records) return error.TooManyMessages;
                        }
                    },
                }
            }
        }
    }
}

// ── offline tests ───────────────────────────────────────────────────────────

const testing = std.testing;

test "max_dump_attempts is the delivered restart budget, not just any value" {
    // 4 is the shipped `NLM_F_DUMP_INTR` restart budget (`max_dump_attempts`
    // above) — pinned literally so a change to the constant is caught here,
    // not read off the constant itself. `dumpInto`'s retry loop cannot be
    // driven to `.restart` without a live kernel dump interrupted mid-flight
    // (see the F2 audit note in modules/nftables.md), so this only pins the
    // delivered magnitude, not the retry behaviour itself.
    try testing.expectEqual(@as(usize, 4), max_dump_attempts);
}

test "errno mapping covers what nf_tables actually answers" {
    try testing.expectEqual(KernelError.NotFound, errorFromErrno(-2));
    try testing.expectEqual(KernelError.Exists, errorFromErrno(-17));
    try testing.expectEqual(KernelError.InvalidRequest, errorFromErrno(-22));
    try testing.expectEqual(KernelError.Busy, errorFromErrno(-16));
    try testing.expectEqual(KernelError.NotSupported, errorFromErrno(-95));
    try testing.expectEqual(KernelError.NoSpaceLeft, errorFromErrno(-28));
    try testing.expectEqual(KernelError.KernelRejected, errorFromErrno(-1));
    try testing.expectEqual(KernelError.KernelRejected, errorFromErrno(-4095));
}

// ── live tests (real kernel; skip cleanly when they cannot run) ─────────────
//
// Full coverage needs CAP_NET_ADMIN in a network namespace:
//
//     unshare -rn zig build test-nftables
//
// Without it the socket still opens but every batch answers EPERM; the tests
// below then print a SKIPPED line and pass. The repo's plain `zig build test`
// must stay green for an unprivileged user.

const test_table = "zig_nftables_live";

/// ⚠ Returns an error union, not an optional, and that is the whole point.
/// It used to hand back `?Socket`, so every caller read
/// `liveSocket(...) orelse return;` — a bare `return` that reports the test as
/// **PASSED**, which is exactly the shape `testkit.skip`'s own doc comment says
/// it was written to replace. Measured before the change: this file's live
/// tests printed "SKIPPED" and the summary said "2/2 tests passed", so
/// `scripts/test.sh`'s skip count — the line its header calls more important
/// than the times — had nothing to count. With an error union the caller writes
/// `try liveSocket(...)` and the skip cannot be swallowed.
fn liveSocket(what: []const u8) !Socket {
    if (builtin.os.tag != .linux) return testkit.skip("LIVE nftables {s} test: needs Linux", .{what});
    var sock = Socket.open(testing.allocator) catch |err| {
        return testkit.skip(
            "LIVE nftables {s} test: cannot open a NETLINK_NETFILTER socket ({s}).",
            .{ what, @errorName(err) },
        );
    };
    // Never let a live test hang a CI run.
    sock.setRecvTimeout(5000) catch {};
    return sock;
}

fn skipUnprivileged(sock: *Socket, what: []const u8, err: anyerror) void {
    if (verboseSkip()) std.debug.print(
        "\nLIVE nftables {s} test SKIPPED: the kernel refused the batch ({s}{s}{s}) — " ++
            "run it as `unshare -rn zig build test-nftables`.\n",
        .{
            what,
            @errorName(err),
            if (sock.lastErrorMessage().len > 0) ": " else "",
            sock.lastErrorMessage(),
        },
    );
}

/// Best-effort teardown; never fails a test.
fn dropTable(sock: *Socket, family: Family, name: []const u8) void {
    var b = sock.beginBatch(.{}) catch return;
    defer b.deinit();
    b.deleteTable(family, name) catch return;
    sock.commit(&b) catch {};
}

fn dropTestTable(sock: *Socket) void {
    dropTable(sock, .inet, test_table);
}

test "live: native batch round-trip — create, list, delete" {
    var sock = try liveSocket("round-trip");
    defer sock.close();
    dropTestTable(&sock); // a previous crashed run must not fail this one

    var p1 = expr.Program.init(testing.allocator, .inet);
    defer p1.deinit();
    _ = p1.tcpDport(22).counter().accept();
    var p2 = expr.Program.init(testing.allocator, .inet);
    defer p2.deinit();
    _ = p2.ipSaddrPrefix(.{ 10, 0, 0, 0 }, 12).drop();

    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = test_table });
    try b.addChain(.{
        .family = .inet,
        .table = test_table,
        .name = "input",
        .chain_type = .filter,
        .hook = .input,
        .prio = 0,
        .policy = .drop,
    });
    try b.addSet(.{
        .family = .inet,
        .table = test_table,
        .name = "blocked",
        .key_type = .ipv4_addr,
        .id = 1,
    });
    try b.addSetElems(.inet, test_table, "blocked", 1, &.{
        .{ .key = &.{ 198, 51, 100, 7 } },
        .{ .key = &.{ 198, 51, 100, 8 } },
    });
    try b.addRule(.{
        .family = .inet,
        .table = test_table,
        .chain = "input",
        .exprs = try p1.finish(),
    });
    try b.addRule(.{
        .family = .inet,
        .table = test_table,
        .chain = "input",
        .exprs = try p2.finish(),
    });

    sock.commit(&b) catch |err| switch (err) {
        error.KernelRejected, error.AccessDenied, error.NotSupported, error.WouldBlock => {
            skipUnprivileged(&sock, "round-trip", err);
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer dropTestTable(&sock);

    // 1) the table is there.
    var tables = try sock.listTables(.inet);
    defer tables.deinit();
    var found_table = false;
    for (tables.items) |t| {
        if (std.mem.eql(u8, t.name, test_table)) found_table = true;
    }
    try testing.expect(found_table);

    // 2) …with the base chain we asked for.
    var chains = try sock.listChains(.inet);
    defer chains.deinit();
    var found_chain = false;
    for (chains.items) |c| {
        if (!std.mem.eql(u8, c.table, test_table)) continue;
        try testing.expectEqualStrings("input", c.name);
        try testing.expectEqualStrings("filter", c.chain_type.?);
        try testing.expectEqual(@as(?u32, types.NF_INET.LOCAL_IN), c.hooknum);
        try testing.expectEqual(@as(?i32, 0), c.prio);
        try testing.expectEqual(@as(?i32, types.NF.DROP), c.policy);
        found_chain = true;
    }
    try testing.expect(found_chain);

    // 3) …the set, with both elements.
    var sets = try sock.listSets(.inet);
    defer sets.deinit();
    var found_set = false;
    for (sets.items) |s| {
        if (!std.mem.eql(u8, s.table, test_table)) continue;
        try testing.expectEqualStrings("blocked", s.name);
        try testing.expectEqual(@as(u32, 4), s.key_len);
        found_set = true;
    }
    try testing.expect(found_set);

    var elems = try sock.listSetElems(.inet, test_table, "blocked");
    defer elems.deinit();
    try testing.expectEqual(@as(usize, 2), elems.items.len);

    // 4) …and both rules, decoding back to the expressions we sent.
    var rules = try sock.listRules(.inet, test_table, "input");
    defer rules.deinit();
    try testing.expectEqual(@as(usize, 2), rules.items.len);

    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(testing.allocator);
    var it = rules.items[0].exprIterator();
    while (try it.next()) |v| try names.append(testing.allocator, v.name);
    try testing.expectEqual(@as(usize, 6), names.items.len);
    try testing.expectEqualStrings("meta", names.items[0]);
    try testing.expectEqualStrings("payload", names.items[2]);
    try testing.expectEqualStrings("counter", names.items[4]);
    try testing.expectEqualStrings("immediate", names.items[5]);

    // The second rule must contain the bitwise the /12 prefix forces.
    var saw_bitwise = false;
    var it2 = rules.items[1].exprIterator();
    while (try it2.next()) |v| {
        if (std.mem.eql(u8, v.name, "bitwise")) saw_bitwise = true;
    }
    try testing.expect(saw_bitwise);
    try testing.expect(rules.items[0].handle != 0);

    // 5) delete one rule by its handle; the other stays.
    var del = try sock.beginBatch(.{});
    defer del.deinit();
    try del.deleteRule(.inet, test_table, "input", rules.items[0].handle);
    try sock.commit(&del);

    var rules2 = try sock.listRules(.inet, test_table, "input");
    defer rules2.deinit();
    try testing.expectEqual(@as(usize, 1), rules2.items.len);

    // 6) drop the table; everything goes with it.
    var drop = try sock.beginBatch(.{});
    defer drop.deinit();
    try drop.deleteTable(.inet, test_table);
    try sock.commit(&drop);

    var tables2 = try sock.listTables(.inet);
    defer tables2.deinit();
    for (tables2.items) |t| try testing.expect(!std.mem.eql(u8, t.name, test_table));

    // Success-path diagnostic: gated, because the driver treats any stderr
    // from a passing step as a failure (scripts/lib/test-lib.sh) — a rule that
    // only holds if passing tests stay silent.
    if (verboseSkip()) std.debug.print("\nLIVE nftables round-trip: create/list/delete OK.\n", .{});
}

test "live: a bad batch is rolled back atomically and names the failing command" {
    var sock = try liveSocket("atomicity");
    defer sock.close();
    dropTestTable(&sock);

    // Probe first: if we cannot apply even a trivial batch, skip.
    {
        var probe = try sock.beginBatch(.{});
        defer probe.deinit();
        try probe.addTable(.{ .family = .inet, .name = test_table });
        sock.commit(&probe) catch |err| switch (err) {
            error.KernelRejected, error.AccessDenied, error.NotSupported, error.WouldBlock => {
                skipUnprivileged(&sock, "atomicity", err);
                return error.SkipZigTest;
            },
            else => return err,
        };
        var undo = try sock.beginBatch(.{});
        defer undo.deinit();
        try undo.deleteTable(.inet, test_table);
        try sock.commit(&undo);
    }

    // A batch whose *second* command cannot work: a rule in a chain that does
    // not exist. If the transaction were not atomic, the table from command #0
    // would survive.
    var p = expr.Program.init(testing.allocator, .inet);
    defer p.deinit();
    _ = p.accept();

    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = test_table });
    try b.addRule(.{
        .family = .inet,
        .table = test_table,
        .chain = "no_such_chain",
        .exprs = try p.finish(),
    });

    const res = sock.commit(&b);
    try testing.expectError(error.NotFound, res);

    // The failure names command #1 (NEWRULE), not just "the batch".
    const f = sock.lastFailure().?;
    try testing.expectEqual(wire.Stage.message, f.stage);
    try testing.expectEqual(@as(?usize, 1), f.index);
    try testing.expectEqualStrings("NEWRULE", f.command);
    try testing.expectEqual(@as(i32, -2), f.code); // -ENOENT

    // …and nothing was applied: the table from command #0 is not there.
    var tables = try sock.listTables(.inet);
    defer tables.deinit();
    for (tables.items) |t| try testing.expect(!std.mem.eql(u8, t.name, test_table));

    // Success-path diagnostic — see the note above.
    if (verboseSkip()) std.debug.print(
        "\nLIVE nftables atomicity: batch rolled back, failure attributed to " ++
            "command #{?d} ({s}{s}{s}).\n",
        .{
            f.index,
            f.command,
            if (f.message.len > 0) ": " else "",
            f.message,
        },
    );
}

const test_table_ip = "zig_nftables_live_ip";

test "live: an unspec-family dump returns objects from multiple families in one request" {
    // The whole point of Gap A: `nft list ruleset` sends ONE GETTABLE with
    // nfgen_family = 0 and gets every family back, instead of walking all six
    // families itself. This proves the kernel actually does that — not just
    // that this module builds the byte right (see wire.zig's offline
    // "family = null sends NFPROTO_UNSPEC" test for that half) — by putting a
    // table in two *different* families and confirming a single
    // `listTables(null)` call surfaces both, each tagged with its own real
    // family byte.
    var sock = try liveSocket("unspec sweep");
    defer sock.close();
    dropTestTable(&sock);
    dropTable(&sock, .ip, test_table_ip);

    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = test_table });
    try b.addTable(.{ .family = .ip, .name = test_table_ip });
    sock.commit(&b) catch |err| switch (err) {
        error.KernelRejected, error.AccessDenied, error.NotSupported, error.WouldBlock => {
            skipUnprivileged(&sock, "unspec sweep", err);
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer {
        dropTestTable(&sock);
        dropTable(&sock, .ip, test_table_ip);
    }

    var tables = try sock.listTables(null); // nfgen_family = NFPROTO_UNSPEC
    defer tables.deinit();
    var saw_inet = false;
    var saw_ip = false;
    for (tables.items) |t| {
        if (std.mem.eql(u8, t.name, test_table)) {
            try testing.expectEqual(@as(u8, types.NFPROTO.INET), t.family);
            saw_inet = true;
        }
        if (std.mem.eql(u8, t.name, test_table_ip)) {
            try testing.expectEqual(@as(u8, types.NFPROTO.IPV4), t.family);
            saw_ip = true;
        }
    }
    try testing.expect(saw_inet);
    try testing.expect(saw_ip);

    if (verboseSkip()) std.debug.print(
        "\nLIVE nftables unspec sweep: one dump returned both an inet and an ip table.\n",
        .{},
    );
}

const test_table_core = "zig_nftables_live_core";

/// One UDP datagram to `addr`:9 (discard). Only its trip through the output
/// hook matters; nothing listens.
fn sendUdp(addr: [4]u8) !void {
    const fd_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);
    var sa: linux.sockaddr.in = .{
        .port = std.mem.nativeToBig(u16, 9),
        .addr = std.mem.bytesToValue(u32, &addr),
    };
    const rc = linux.sendto(fd, "x", 1, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in));
    if (linux.errno(rc) != .SUCCESS) return error.SendFailed;
}

test "live: interval set, named counter/quota, verdict map and inet ingress against the kernel" {
    // What the goldens cannot show: that the kernel accepts these messages
    // and that they MEAN what the helpers say. Packets prove the interval
    // semantics — [first, last+1) must match the last address and miss the
    // one after it — and the counters are read back through the decoders a
    // consumer uses (`decodeCounter`, `listObjects`).
    var sock = try liveSocket("core objects");
    defer sock.close();
    dropTable(&sock, .ip, test_table_core);
    dropTable(&sock, .inet, test_table_core);

    const range = try wire.interval(4, .{ 127, 0, 0, 5 }, .{ 127, 0, 0, 9 });
    var two: [2]wire.SetElem = undefined;

    // rule 1: ip daddr @r counter      (interval set lookup)
    var p1 = expr.Program.init(testing.allocator, .ip);
    defer p1.deinit();
    _ = p1.payloadLookup(.nh, 16, 4, "r", 1, false).counter().accept();
    // rule 2: ip daddr 127.0.0.77 counter name "hits" quota name "q"
    var p2 = expr.Program.init(testing.allocator, .ip);
    defer p2.deinit();
    _ = p2.ipDaddr(.{ 127, 0, 0, 77 }).counterRef("hits").quotaRef("q").accept();
    // rule 3: udp dport vmap @vm      (verdict map; 9 → accept)
    var p3 = expr.Program.init(testing.allocator, .ip);
    defer p3.deinit();
    _ = p3.l4proto(expr.IPPROTO.UDP).payloadVmap(.th, 2, 2, "vm", 2);

    var b = try sock.beginBatch(.{});
    defer b.deinit();
    try b.addTable(.{ .family = .ip, .name = test_table_core });
    try b.addChain(.{
        .family = .ip,
        .table = test_table_core,
        .name = "out",
        .chain_type = .filter,
        .hook = .output,
        .prio = 0,
    });
    try b.addChain(.{ .family = .ip, .table = test_table_core, .name = "helper" });
    try b.addSet(.{ .family = .ip, .table = test_table_core, .name = "r", .key_type = .ipv4_addr, .flags = &.{.interval}, .id = 1 });
    try b.addSetElems(.ip, test_table_core, "r", 1, range.elems(&two));
    try b.addSet(.{ .family = .ip, .table = test_table_core, .name = "vm", .key_type = .inet_service, .id = 2, .data = .verdict });
    try b.addSetElems(.ip, test_table_core, "vm", 2, &.{
        .{ .key = &expr.portBytes(9), .verdict = .accept },
        .{ .key = &expr.portBytes(10), .verdict = expr.Verdict.jumpTo("helper") },
    });
    try b.addObject(.{ .family = .ip, .table = test_table_core, .name = "hits", .obj = .{ .counter = .{} } });
    try b.addObject(.{
        .family = .ip,
        .table = test_table_core,
        .name = "q",
        .obj = .{ .quota = .{ .bytes = 1 << 20, .over = true } },
    });
    try b.addRule(.{ .family = .ip, .table = test_table_core, .chain = "out", .exprs = try p1.finish() });
    try b.addRule(.{ .family = .ip, .table = test_table_core, .chain = "out", .exprs = try p2.finish() });
    try b.addRule(.{ .family = .ip, .table = test_table_core, .chain = "out", .exprs = try p3.finish() });
    // An inet table with an ingress base chain on lo (NF_INET_INGRESS).
    try b.addTable(.{ .family = .inet, .name = test_table_core });
    try b.addChain(.{
        .family = .inet,
        .table = test_table_core,
        .name = "ing",
        .chain_type = .filter,
        .hook = .ingress,
        .prio = 0,
        .dev = "lo",
    });
    sock.commit(&b) catch |err| switch (err) {
        error.KernelRejected, error.AccessDenied, error.NotSupported, error.WouldBlock => {
            skipUnprivileged(&sock, "core objects", err);
            return error.SkipZigTest;
        },
        else => return err,
    };
    defer {
        dropTable(&sock, .ip, test_table_core);
        dropTable(&sock, .inet, test_table_core);
    }

    // The ingress chain reads back with hooknum 5 on lo.
    var chains = try sock.listChains(.inet);
    defer chains.deinit();
    var saw_ingress = false;
    for (chains.items) |c| {
        if (!std.mem.eql(u8, c.table, test_table_core)) continue;
        try testing.expectEqual(@as(?u32, try types.Hook.ingress.num(.inet)), c.hooknum);
        try testing.expectEqualStrings("lo", c.dev.?);
        saw_ingress = true;
    }
    try testing.expect(saw_ingress);

    // The map reads back as a verdict map with both verdicts.
    var sets = try sock.listSets(.ip);
    defer sets.deinit();
    var saw_map = false;
    for (sets.items) |s| {
        if (!std.mem.eql(u8, s.table, test_table_core) or !std.mem.eql(u8, s.name, "vm")) continue;
        try testing.expect(s.flags & wire.NFT_SET_MAP != 0);
        try testing.expectEqual(@as(?u32, wire.NFT_DATA_VERDICT), s.data_type);
        saw_map = true;
    }
    try testing.expect(saw_map);
    var vm = try sock.listSetElems(.ip, test_table_core, "vm");
    defer vm.deinit();
    try testing.expectEqual(@as(usize, 2), vm.items.len);
    var saw_jump = false;
    for (vm.items) |e| {
        const v = e.verdict.?;
        if (v.code == types.NFT.JUMP) {
            try testing.expectEqualStrings("helper", v.chain.?);
            saw_jump = true;
        } else try testing.expectEqual(types.NF.ACCEPT, v.code);
    }
    try testing.expect(saw_jump);

    // Packets: .9 is the LAST address of the range (must count), .10 the
    // first past it (must not), .4 the one below; .77 hits the named counter.
    sendUdp(.{ 127, 0, 0, 9 }) catch {
        // A fresh `unshare -rn` namespace (how the lane runs this module)
        // starts with `lo` DOWN. This test already holds CAP_NET_ADMIN there
        // (the batch above committed), so bring it up — ifindex 1 is always
        // `lo` in a network namespace — and try once more.
        var rt = netlink.Socket.open(testing.allocator) catch |err|
            return testkit.skip("LIVE nftables core objects: no rtnetlink ({s})", .{@errorName(err)});
        defer rt.close();
        rt.linkUp(1) catch |err|
            return testkit.skip("LIVE nftables core objects: cannot bring lo up ({s})", .{@errorName(err)});
        sendUdp(.{ 127, 0, 0, 9 }) catch |err|
            return testkit.skip("LIVE nftables core objects: no loopback to send on ({s})", .{@errorName(err)});
    };
    try sendUdp(.{ 127, 0, 0, 10 });
    try sendUdp(.{ 127, 0, 0, 4 });
    try sendUdp(.{ 127, 0, 0, 77 });
    try sendUdp(.{ 127, 0, 0, 5 });

    var rules = try sock.listRules(.ip, test_table_core, "out");
    defer rules.deinit();
    try testing.expectEqual(@as(usize, 3), rules.items.len);
    var it = rules.items[0].exprIterator();
    var range_hits: ?u64 = null;
    while (try it.next()) |e| {
        if (std.mem.eql(u8, e.name, "counter")) range_hits = (try expr.decodeCounter(e.data)).?.packets;
    }
    // .9 and .5 are inside [127.0.0.5, 127.0.0.10); .10 and .4 are not.
    try testing.expectEqual(@as(?u64, 2), range_hits);

    var objs = try sock.listObjects(.ip);
    defer objs.deinit();
    var saw_counter = false;
    var saw_quota = false;
    for (objs.items) |o| {
        if (!std.mem.eql(u8, o.table, test_table_core)) continue;
        if (std.mem.eql(u8, o.name, "hits")) {
            try testing.expectEqual(@as(u32, @backingInt(expr.ObjectType.counter)), o.obj_type);
            try testing.expectEqual(@as(u64, 1), o.counter.?.packets);
            // One IPv4 header (20) + UDP header (8) + 1 payload byte.
            try testing.expectEqual(@as(u64, 29), o.counter.?.bytes);
            saw_counter = true;
        }
        if (std.mem.eql(u8, o.name, "q")) {
            try testing.expectEqual(@as(u64, 1 << 20), o.quota.?.bytes);
            try testing.expectEqual(@as(u64, 29), o.quota.?.consumed);
            try testing.expect(o.quota.?.flags & expr.NFT_QUOTA_F_INV != 0);
            saw_quota = true;
        }
    }
    try testing.expect(saw_counter and saw_quota);

    // Listing is a READ: a second dump sees the same count. (GETOBJ_RESET
    // would answer the same first dump and zero the counter behind it —
    // mutation 2026-10-04 found nothing told the two apart.)
    var again = try sock.listObjects(.ip);
    defer again.deinit();
    for (again.items) |o| {
        if (std.mem.eql(u8, o.table, test_table_core) and std.mem.eql(u8, o.name, "hits"))
            try testing.expectEqual(@as(u64, 1), o.counter.?.packets);
    }

    // Delete the named counter after its rule is gone (a referenced object
    // is EBUSY), then confirm it left the dump.
    var del = try sock.beginBatch(.{});
    defer del.deinit();
    try del.deleteRule(.ip, test_table_core, "out", rules.items[1].handle);
    try del.deleteObject(.ip, test_table_core, "hits", .counter);
    try sock.commit(&del);
    var objs2 = try sock.listObjects(.ip);
    defer objs2.deinit();
    for (objs2.items) |o| {
        if (std.mem.eql(u8, o.table, test_table_core))
            try testing.expect(!std.mem.eql(u8, o.name, "hits"));
    }
}

// ── no-panic sweep wave GV (nftables): tests that need the private engines ──
// The public-API half lives in sweep_test.zig.

fn cannedHeader(msg_type: u16, flags: u16, seq: u32, pid: u32) [nl.header_len]u8 {
    var m: [nl.header_len]u8 = @splat(0);
    std.mem.writeInt(u32, m[0..4], nl.header_len, native_endian);
    std.mem.writeInt(u16, m[4..6], msg_type, native_endian);
    std.mem.writeInt(u16, m[6..8], flags, native_endian);
    std.mem.writeInt(u32, m[8..12], seq, native_endian);
    std.mem.writeInt(u32, m[12..16], pid, native_endian);
    return m;
}

/// NLMSG_ERROR carrying `code`.
fn cannedError(code: i32, seq: u32, pid: u32) [nl.header_len + 4]u8 {
    var m: [nl.header_len + 4]u8 = @splat(0);
    m[0..nl.header_len].* = cannedHeader(nl.NLMSG_ERROR, 0, seq, pid);
    std.mem.writeInt(u32, m[0..4], m.len, native_endian);
    std.mem.writeInt(i32, m[nl.header_len..][0..4], code, native_endian);
    return m;
}

/// NFT_MSG_NEWTABLE record naming table "t".
fn cannedTable(seq: u32, pid: u32) [28]u8 {
    var m: [28]u8 = @splat(0);
    m[0..nl.header_len].* = cannedHeader(wire.nftMsg(wire.NFT_MSG.NEWTABLE), nl.NLM_F_MULTI, seq, pid);
    std.mem.writeInt(u32, m[0..4], m.len, native_endian);
    // nfgenmsg (4 zero bytes), then NFTA_TABLE_NAME = "t\0" (len 6, padded to 8).
    std.mem.writeInt(u16, m[20..22], 6, native_endian);
    std.mem.writeInt(u16, m[22..24], wire.NFTA_TABLE.NAME, native_endian);
    m[24] = 't';
    return m;
}

const Scripted = struct {
    script: []const []const u8 = &.{},
    filler: ?[]const u8 = null,
    pos: usize = 0,
    recvs: usize = 0,
    sent: [8]u32 = @splat(0),
    nsent: usize = 0,
    pid: u32,
    next: u32,
    failed_code: i32 = 0,

    fn recvDatagram(self: *Scripted) RecvError![]const u8 {
        self.recvs += 1;
        if (self.pos < self.script.len) {
            defer self.pos += 1;
            return self.script[self.pos];
        }
        return self.filler orelse error.WouldBlock;
    }
    fn portId(self: *const Scripted) u32 {
        return self.pid;
    }
    fn captureExtAck(_: *Scripted, _: nl.Message) void {}
    fn nextSeq(self: *Scripted) u32 {
        self.next += 1;
        return self.next;
    }
    fn send(self: *Scripted, msg: []const u8) SendError!void {
        self.sent[self.nsent] = std.mem.readInt(u32, msg[8..12], native_endian);
        self.nsent += 1;
    }
    fn recordFailure(self: *Scripted, _: *const wire.Batch, _: nl.Message, code: i32) void {
        self.failed_code = code;
    }
};

fn newTableAppend(al: std.mem.Allocator, list: *std.ArrayList(wire.TableInfo), payload: []const u8) !void {
    var t = try wire.decodeTable(payload);
    t.name = try al.dupe(u8, t.name);
    try list.append(al, t);
}

fn oneCommandBatch(ack: bool) !wire.Batch {
    var b = try wire.Batch.init(testing.allocator, 100, .{ .ack = ack });
    errdefer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "t" });
    _ = try b.finish(); // commands: seq 101, END: 102, next_seq 103
    return b;
}

test "the dump/ACK budgets are the delivered magnitudes (sweep NF-2)" {
    try testing.expectEqual(@as(u32, 65536), max_dump_messages);
    try testing.expectEqual(@as(u32, 65536), max_await_messages);
    try testing.expectEqual(@as(u32, 4194304), max_dump_records);
}

test "errorFromErrno is total: minInt(i32) is no errno (sweep NF-1)" {
    try testing.expectEqual(error.KernelRejected, errorFromErrno(std.math.minInt(i32)));
    try testing.expectEqual(error.InvalidRequest, errorFromErrno(-22));
    try testing.expectEqual(error.Exists, errorFromErrno(17));
}

test "awaitBatch gives up instead of spinning when the ACKs never arrive (sweep NF-2)" {
    var b = try oneCommandBatch(true);
    defer b.deinit();
    const noop = cannedHeader(nl.NLMSG_NOOP, 0, 101, 7);
    var t: Scripted = .{ .filler = &noop, .pid = 7, .next = 100 };
    try testing.expectError(error.TooManyMessages, awaitBatchOver(&t, &b, 50));
    try testing.expectEqual(@as(usize, 50), t.recvs);
}

test "awaitBatch ignores an ACK for a foreign sequence number (sweep NF-3)" {
    var b = try oneCommandBatch(true);
    defer b.deinit();
    const stale = cannedError(0, 999, 7);
    const real = cannedError(-22, 101, 7);
    var t: Scripted = .{ .script = &.{ &stale, &real }, .pid = 7, .next = 100 };
    // The stale ACK must not count as the command's ACK: the real error that
    // follows has to reach the caller.
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t, &b, 50));
    try testing.expectEqual(@as(i32, -22), t.failed_code);

    // And a genuine ACK after a stale one still completes the batch.
    const ack = cannedError(0, 101, 7);
    var t2: Scripted = .{ .script = &.{ &stale, &ack }, .pid = 7, .next = 100 };
    try awaitBatchOver(&t2, &b, 50);
    try testing.expectEqual(@as(usize, 2), t2.recvs);
}

test "dump gives up on an endless stream, and on too many records (sweep NF-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);

    const noop = cannedHeader(nl.NLMSG_NOOP, nl.NLM_F_MULTI, 42, 7);
    var t: Scripted = .{ .filler = &noop, .pid = 7, .next = 42 };
    try testing.expectError(error.TooManyMessages, dumpOver(&t, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000));
    try testing.expectEqual(@as(usize, 50), t.recvs);
    try testing.expectEqual(@as(usize, 1), t.nsent);

    // A record of another type still counts: 10 pass, the 11th trips the cap.
    const other = cannedHeader(wire.nftMsg(wire.NFT_MSG.NEWCHAIN), nl.NLM_F_MULTI, 42, 7);
    var t2: Scripted = .{ .filler = &other, .pid = 7, .next = 42 };
    try testing.expectError(error.TooManyMessages, dumpOver(&t2, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 1000, 10));
    try testing.expectEqual(@as(usize, 11), t2.recvs);
}

test "a dump restart uses a fresh seq, so a stale old-seq DONE cannot end the new attempt (sweep NF-4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);

    // Attempt 1: the kernel flags the dump inconsistent and finishes it.
    const intr = cannedHeader(wire.nftMsg(wire.NFT_MSG.NEWTABLE), nl.NLM_F_DUMP_INTR, 42, 7);
    const done_old = cannedHeader(nl.NLMSG_DONE, nl.NLM_F_MULTI, 42, 7);
    // Attempt 2 (seq 43): a stale seq-42 DONE shows up in front of the real
    // answer and must not end it.
    const rec = cannedTable(43, 7);
    var d2: [done_old.len + rec.len]u8 = undefined;
    @memcpy(d2[0..done_old.len], &done_old);
    @memcpy(d2[done_old.len..], &rec);
    const done = cannedHeader(nl.NLMSG_DONE, nl.NLM_F_MULTI, 43, 7);
    var t: Scripted = .{ .script = &.{ &intr, &done_old, &d2, &done }, .pid = 7, .next = 42 };
    try dumpOver(&t, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000);
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expectEqualStrings("t", items.items[0].name);
    try testing.expectEqual(@as(usize, 2), t.nsent);
    try testing.expectEqual(@as(u32, 42), t.sent[0]);
    try testing.expectEqual(@as(u32, 43), t.sent[1]);
}

// ── fix round (review GV-b) ─────────────────────────────────────────────────

/// 20-byte message: header + i32 payload (`code`, default 0).
fn cannedWith(msg_type: u16, flags: u16, seq: u32, pid: u32, code: ?i32) [nl.header_len + 4]u8 {
    var m: [nl.header_len + 4]u8 = @splat(0);
    m[0..nl.header_len].* = cannedHeader(msg_type, flags, seq, pid);
    std.mem.writeInt(u32, m[0..4], m.len, native_endian);
    std.mem.writeInt(i32, m[nl.header_len..][0..4], code orelse 0, native_endian);
    return m;
}

/// A kernel that keeps an interrupted dump running: a request sent before the
/// previous dump's last datagram was delivered is answered with -EBUSY.
const BusyKernel = struct {
    dumps: []const []const []const u8,
    ndump: usize = 0,
    cur: []const []const u8 = &.{},
    pos: usize = 0,
    running: bool = false,
    cur_is_busy: bool = false,
    ebusy_hit: bool = false,
    busy_msg: [nl.header_len + 4]u8 = undefined,
    busy_script: [1][]const u8 = undefined,
    pid: u32,
    next: u32,
    nsent: usize = 0,
    sent: [8]u32 = @splat(0),

    fn recvDatagram(self: *BusyKernel) RecvError![]const u8 {
        if (self.pos >= self.cur.len) return error.WouldBlock;
        const d = self.cur[self.pos];
        self.pos += 1;
        if (self.pos == self.cur.len and !self.cur_is_busy) self.running = false;
        return d;
    }
    fn portId(self: *const BusyKernel) u32 {
        return self.pid;
    }
    fn captureExtAck(_: *BusyKernel, _: nl.Message) void {}
    fn nextSeq(self: *BusyKernel) u32 {
        self.next += 1;
        return self.next;
    }
    fn send(self: *BusyKernel, msg: []const u8) SendError!void {
        const seq = std.mem.readInt(u32, msg[8..12], native_endian);
        self.sent[self.nsent] = seq;
        self.nsent += 1;
        self.pos = 0;
        if (self.running) {
            self.ebusy_hit = true;
            self.cur_is_busy = true;
            self.busy_msg = cannedWith(nl.NLMSG_ERROR, 0, seq, self.pid, -16);
            self.busy_script = .{&self.busy_msg};
            self.cur = &self.busy_script;
        } else {
            self.cur_is_busy = false;
            self.cur = self.dumps[self.ndump];
            self.ndump += 1;
            self.running = true;
        }
    }
};

test "a DUMP_INTR restart first drains the interrupted dump, else the kernel answers EBUSY (sweep REV-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const nt = wire.nftMsg(wire.NFT_MSG.NEWTABLE);
    const intr = cannedWith(nt, nl.NLM_F_DUMP_INTR, 42, 7, null);
    const more = cannedWith(nt, nl.NLM_F_MULTI, 42, 7, null); // discarded
    const done1 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 42, 7, 0);
    const rec = cannedTable(43, 7);
    const done2 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 43, 7, 0);
    const d1: []const []const u8 = &.{ &intr, &more, &done1 };
    const d2: []const []const u8 = &.{ &rec, &done2 };
    var k: BusyKernel = .{ .dumps = &.{ d1, d2 }, .pid = 7, .next = 42 };
    try dumpOver(&k, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000);
    try testing.expect(!k.ebusy_hit);
    try testing.expectEqual(@as(usize, 1), items.items.len);
    try testing.expectEqual(@as(usize, 2), k.nsent);
    try testing.expectEqual(@as(u32, 43), k.sent[1]);
}

test "the interrupted dump's DONE may carry DUMP_INTR itself; a DONE errno ends it with that error (sweep REV-2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const nt = wire.nftMsg(wire.NFT_MSG.NEWTABLE);
    const intr = cannedWith(nt, nl.NLM_F_DUMP_INTR, 42, 7, null);
    const done1 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI | nl.NLM_F_DUMP_INTR, 42, 7, 0);
    const done2 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 43, 7, 0);
    const d1: []const []const u8 = &.{ &intr, &done1 };
    const d2: []const []const u8 = &.{&done2};
    var k: BusyKernel = .{ .dumps = &.{ d1, d2 }, .pid = 7, .next = 42 };
    try dumpOver(&k, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000);
    try testing.expect(!k.ebusy_hit);
    try testing.expectEqual(@as(usize, 2), k.nsent);

    const bad = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 42, 7, -22);
    const d3: []const []const u8 = &.{ &intr, &bad };
    var k2: BusyKernel = .{ .dumps = &.{d3}, .pid = 7, .next = 42 };
    try testing.expectError(error.InvalidRequest, dumpOver(&k2, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000));
    try testing.expectEqual(@as(usize, 1), k2.nsent);
}

test "a DONE carrying a negative errno fails the dump instead of returning a partial list (sweep REV-1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const rec = cannedTable(42, 7);
    const bad = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 42, 7, -22);
    var t: Scripted = .{ .script = &.{ &rec, &bad }, .pid = 7, .next = 42 };
    try testing.expectError(error.InvalidRequest, dumpOver(&t, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000));
}

test "the record cap counts produced items, not only messages (sweep REV-4)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const rec = cannedHeader(wire.nftMsg(wire.NFT_MSG.NEWTABLE), nl.NLM_F_MULTI, 42, 7);
    var t: Scripted = .{ .filler = &rec, .pid = 7, .next = 42 };
    const three = struct {
        fn f(al: std.mem.Allocator, list: *std.ArrayList(wire.TableInfo), _: []const u8) error{ OutOfMemory, Bad }!void {
            for (0..3) |_| try list.append(al, .{ .family = 0 });
        }
    }.f;
    try testing.expectError(error.TooManyMessages, dumpOver(&t, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, three, arena.allocator(), &items, 1000, 10));
    // 3 items per message: the 4th message pushes the count to 12 > 10.
    try testing.expectEqual(@as(usize, 4), t.recvs);
}

test "un-acked: a datagram of only foreign traffic does not end the wait (sweep REV-3)" {
    var b = try oneCommandBatch(false);
    defer b.deinit();
    const stale = cannedError(0, 999, 7);
    const real = cannedError(-22, 101, 7);
    var t: Scripted = .{ .script = &.{ &stale, &real }, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t, &b, 50));
    // Only foreign traffic, then silence (WouldBlock) = still success.
    var t2: Scripted = .{ .script = &.{&stale}, .pid = 7, .next = 100 };
    try awaitBatchOver(&t2, &b, 50);
    try testing.expectEqual(@as(usize, 2), t2.recvs);
}

test "a foreign NLMSG_ERROR too short to carry an errno is skipped, not MalformedReply (sweep REV-5)" {
    var b = try oneCommandBatch(true);
    defer b.deinit();
    const short = cannedHeader(nl.NLMSG_ERROR, 0, 999, 7); // 16 bytes, no payload
    const real = cannedError(-22, 101, 7);
    var t: Scripted = .{ .script = &.{ &short, &real }, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t, &b, 50));
}

test "the batch seq window is modular: a batch crossing seq 0 (sweep REV-8)" {
    var b = try wire.Batch.init(testing.allocator, 0xfffffffe, .{});
    defer b.deinit();
    try b.addTable(.{ .family = .inet, .name = "t" }); // command seq 0xffffffff
    _ = try b.finish(); // BATCH_END seq 0, next_seq 1
    try testing.expectEqual(@as(u32, 1), b.next_seq);
    const stale = cannedError(0, 1, 7); // just outside the window
    const real = cannedError(-22, 0xffffffff, 7);
    var t: Scripted = .{ .script = &.{ &stale, &real }, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t, &b, 50));
    // A commit-stage error reported against BATCH_END's seq 0 is in the window too.
    const at_end = cannedError(-22, 0, 7);
    var t2: Scripted = .{ .script = &.{&at_end}, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t2, &b, 50));
}

// ── delta mutation audit GV-B: tests for the survivors ──────────────────────

/// An NLMSG_ERROR carrying `code` and, after it, the request header it answers
/// (`emb_seq` in its seq field), as the kernel echoes it.
fn cannedErrorEmbedded(code: i32, seq: u32, pid: u32, emb_seq: u32) [nl.header_len + 4 + nl.header_len]u8 {
    var m: [nl.header_len + 4 + nl.header_len]u8 = @splat(0);
    m[0..nl.header_len].* = cannedHeader(nl.NLMSG_ERROR, 0, seq, pid);
    std.mem.writeInt(u32, m[0..4], m.len, native_endian);
    std.mem.writeInt(i32, m[nl.header_len..][0..4], code, native_endian);
    m[nl.header_len + 4 ..][0..nl.header_len].* = cannedHeader(0, 0, emb_seq, 0);
    return m;
}

test "acked: a seq-0 error echoing a foreign request is skipped, not taken as ours (sweep audit GV-B1)" {
    var b = try oneCommandBatch(true);
    defer b.deinit();
    const foreign = cannedErrorEmbedded(-22, 0, 7, 999);
    const ack = cannedError(0, 101, 7);
    var t: Scripted = .{ .script = &.{ &foreign, &ack }, .pid = 7, .next = 100 };
    try awaitBatchOver(&t, &b, 50);
    try testing.expectEqual(@as(usize, 2), t.recvs);
}

test "an in-window nlmsg_seq wins over the echoed request's seq (sweep audit GV-B2)" {
    var b = try oneCommandBatch(true);
    defer b.deinit();
    const ours = cannedErrorEmbedded(-22, 101, 7, 999);
    var t: Scripted = .{ .script = &.{&ours}, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t, &b, 50));
}

test "un-acked: a datagram of only foreign traffic keeps waiting, whatever makes it foreign (sweep audit GV-B3)" {
    var b = try oneCommandBatch(false);
    defer b.deinit();
    const real = cannedError(-22, 101, 7);
    // (a) another port id
    const other_pid = cannedError(0, 101, 99);
    var t: Scripted = .{ .script = &.{ &other_pid, &real }, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t, &b, 50));
    // (b) a seq-0 error echoing a foreign request
    const echo = cannedErrorEmbedded(0, 0, 7, 999);
    var t2: Scripted = .{ .script = &.{ &echo, &real }, .pid = 7, .next = 100 };
    try testing.expectError(error.InvalidRequest, awaitBatchOver(&t2, &b, 50));
}

test "un-acked: a datagram with one own message ends the wait even beside foreign ones (sweep audit GV-B4)" {
    var b = try oneCommandBatch(false);
    defer b.deinit();
    const real = cannedError(-22, 101, 7);
    const foreign = cannedError(0, 999, 7);
    const own_ack = cannedError(0, 101, 7);
    var mixed: [foreign.len + own_ack.len]u8 = undefined;
    @memcpy(mixed[0..foreign.len], &foreign);
    @memcpy(mixed[foreign.len..], &own_ack);
    var t: Scripted = .{ .script = &.{ &mixed, &real }, .pid = 7, .next = 100 };
    try awaitBatchOver(&t, &b, 50);
    try testing.expectEqual(@as(usize, 1), t.recvs);

    // A NOOP/echo of ours counts as own traffic as well.
    const noop = cannedHeader(nl.NLMSG_NOOP, 0, 101, 7);
    var mixed2: [foreign.len + noop.len]u8 = undefined;
    @memcpy(mixed2[0..foreign.len], &foreign);
    @memcpy(mixed2[foreign.len..], &noop);
    var t2: Scripted = .{ .script = &.{ &mixed2, &real }, .pid = 7, .next = 100 };
    try awaitBatchOver(&t2, &b, 50);
    try testing.expectEqual(@as(usize, 1), t2.recvs);
}

test "un-acked: an empty datagram carries nothing foreign, so it ends the wait (sweep audit GV-B5)" {
    var b = try oneCommandBatch(false);
    defer b.deinit();
    const real = cannedError(-22, 101, 7);
    const empty: []const u8 = &.{};
    var t: Scripted = .{ .script = &.{ empty, &real }, .pid = 7, .next = 100 };
    try awaitBatchOver(&t, &b, 50);
    try testing.expectEqual(@as(usize, 1), t.recvs);
}

test "the interrupted dump may end in an NLMSG_ERROR that carries DUMP_INTR (sweep audit GV-B6)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const nt = wire.nftMsg(wire.NFT_MSG.NEWTABLE);
    const intr = cannedWith(nt, nl.NLM_F_DUMP_INTR, 42, 7, null);
    const ack1 = cannedWith(nl.NLMSG_ERROR, nl.NLM_F_MULTI | nl.NLM_F_DUMP_INTR, 42, 7, 0);
    const done2 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 43, 7, 0);
    const d1: []const []const u8 = &.{ &intr, &ack1 };
    const d2: []const []const u8 = &.{&done2};
    var k: BusyKernel = .{ .dumps = &.{ d1, d2 }, .pid = 7, .next = 42 };
    try dumpOver(&k, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000);
    try testing.expect(!k.ebusy_hit);
    try testing.expectEqual(@as(usize, 2), k.nsent);
}

test "a dump interrupted on every attempt gives up after max_dump_attempts sends, one owned copy (sweep audit GV-B7)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const nt = wire.nftMsg(wire.NFT_MSG.NEWTABLE);
    var msgs: [8][nl.header_len + 4]u8 = undefined;
    var dumps: [4][]const []const u8 = undefined;
    var parts: [4][2][]const u8 = undefined;
    for (0..4) |i| {
        const seq: u32 = 42 + @as(u32, @intCast(i));
        msgs[2 * i] = cannedWith(nt, nl.NLM_F_DUMP_INTR, seq, 7, null);
        msgs[2 * i + 1] = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, seq, 7, 0);
        parts[i] = .{ &msgs[2 * i], &msgs[2 * i + 1] };
        dumps[i] = &parts[i];
    }
    var k: BusyKernel = .{ .dumps = &dumps, .pid = 7, .next = 42 };
    try testing.expectError(error.InconsistentDump, dumpOver(&k, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000));
    try testing.expectEqual(@as(usize, 4), k.nsent);
}

test "records of an interrupted dump are discarded unexamined, even malformed ones (sweep audit GV-B8)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const nt = wire.nftMsg(wire.NFT_MSG.NEWTABLE);
    const intr = cannedWith(nt, nl.NLM_F_DUMP_INTR, 42, 7, null);
    const junk = cannedHeader(nt, nl.NLM_F_MULTI, 42, 7); // no nfgenmsg: decodeTable rejects it
    const done1 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 42, 7, 0);
    const done2 = cannedWith(nl.NLMSG_DONE, nl.NLM_F_MULTI, 43, 7, 0);
    const d1: []const []const u8 = &.{ &intr, &junk, &done1 };
    const d2: []const []const u8 = &.{&done2};
    var k: BusyKernel = .{ .dumps = &.{ d1, d2 }, .pid = 7, .next = 42 };
    try dumpOver(&k, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 1000);
    try testing.expectEqual(@as(usize, 2), k.nsent);
}

test "a dump of exactly max_records items is complete (sweep audit GV-B9)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var items: std.ArrayList(wire.TableInfo) = .empty;
    const req = wire.buildDumpRequest(42, wire.NFT_MSG.GETTABLE, null);
    const rec = cannedTable(42, 7);
    const done = cannedHeader(nl.NLMSG_DONE, nl.NLM_F_MULTI, 42, 7);
    var script: [11][]const u8 = undefined;
    for (script[0..10]) |*s| s.* = &rec;
    script[10] = &done;
    var t: Scripted = .{ .script = &script, .pid = 7, .next = 42 };
    try dumpOver(&t, testing.allocator, &req, wire.NFT_MSG.NEWTABLE, 42, newTableAppend, arena.allocator(), &items, 50, 10);
    try testing.expectEqual(@as(usize, 10), items.items.len);
}
