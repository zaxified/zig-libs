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

pub const CommitError = KernelError || SendError || RecvError || wire.BuildError;
pub const DumpError = KernelError || SendError || RecvError || wire.BuildError ||
    error{ InconsistentDump, OutOfMemory };

fn errorFromErrno(code: i32) KernelError {
    // The kernel reports `-errno`.
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
        const expected: usize = if (batch.opts.ack) batch.commandCount() else 0;
        var acks: usize = 0;
        while (true) {
            const dgram = self.recvDatagram() catch |err| switch (err) {
                // No reply at all is how a successful un-acked batch looks.
                error.WouldBlock => if (expected == 0) return else return err,
                else => return err,
            };
            var it: nl.MessageIterator = .{ .buf = dgram };
            while (it.next() catch return error.MalformedReply) |m| {
                if (m.pid != self.nl.portid) continue;
                switch (m.type) {
                    nl.NLMSG_ERROR => {
                        const code = m.errorCode() catch return error.MalformedReply;
                        if (code == 0) {
                            acks += 1;
                            if (acks >= expected and expected > 0) return;
                            continue;
                        }
                        self.recordFailure(batch, m, code);
                        return errorFromErrno(code);
                    },
                    nl.NLMSG_OVERRUN => return error.Overrun,
                    else => {}, // NOOP / echo
                }
            }
            if (expected == 0) return; // un-acked batch: nothing more is coming
        }
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

    pub fn listTables(self: *Socket, family: Family) DumpError!TableList {
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

    pub fn listChains(self: *Socket, family: Family) DumpError!ChainList {
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

    pub fn listSets(self: *Socket, family: Family) DumpError!SetList {
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
    /// null). `RuleInfo.expressions` is copied into the result's arena.
    pub fn listRules(
        self: *Socket,
        family: Family,
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
        var attempt: usize = 0;
        retry: while (true) {
            attempt += 1;
            self.failure = null;
            try self.send(req);
            items.clearRetainingCapacity();
            while (true) {
                const dgram = try self.recvDatagram();
                var it: nl.MessageIterator = .{ .buf = dgram };
                while (it.next() catch return error.MalformedReply) |m| {
                    switch (nl.classifyDumpMessage(m, self.nl.portid, seq)) {
                        .skip => {},
                        .restart => {
                            if (attempt < max_dump_attempts) continue :retry;
                            return error.InconsistentDump;
                        },
                        // NLMSG_DONE, or a bare ACK = an empty dump.
                        .done => return,
                        .failed => |code| {
                            self.nl.captureExtAck(m);
                            return errorFromErrno(code);
                        },
                        .overrun => return error.Overrun,
                        .malformed => return error.MalformedReply,
                        .record => |rec| {
                            if (rec.type == wire.nftMsg(want_type))
                                append(arena, items, rec.payload) catch |err| switch (err) {
                                    error.OutOfMemory => return error.OutOfMemory,
                                    else => return error.MalformedReply,
                                };
                        },
                    }
                }
            }
        }
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

// ── offline tests ───────────────────────────────────────────────────────────

const testing = std.testing;

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

fn liveSocket(what: []const u8) ?Socket {
    if (builtin.os.tag != .linux) return null;
    var sock = Socket.open(testing.allocator) catch |err| {
        if (verboseSkip()) std.debug.print(
            "\nLIVE nftables {s} test SKIPPED: cannot open a NETLINK_NETFILTER socket ({s}).\n",
            .{ what, @errorName(err) },
        );
        return null;
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
fn dropTestTable(sock: *Socket) void {
    var b = sock.beginBatch(.{}) catch return;
    defer b.deinit();
    b.deleteTable(.inet, test_table) catch return;
    sock.commit(&b) catch {};
}

test "live: native batch round-trip — create, list, delete" {
    var sock = liveSocket("round-trip") orelse return;
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
    // from a passing step as a failure (scripts/test-lib.sh) — a rule that
    // only holds if passing tests stay silent.
    if (verboseSkip()) std.debug.print("\nLIVE nftables round-trip: create/list/delete OK.\n", .{});
}

test "live: a bad batch is rolled back atomically and names the failing command" {
    var sock = liveSocket("atomicity") orelse return;
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
