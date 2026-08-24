// SPDX-License-Identifier: MIT

//! raft-kv — a replicated key-value store that survives losing its leader.
//!
//! Three `node` processes form a cluster: the `raft` module's model-checked
//! consensus kernel makes every safety decision (elections, log truncation,
//! commit), and this app gives it what the simulator abstracts away — real
//! TCP, real election timers, and a real disk (`kv`, fsync on every write).
//! Kill the leader and the survivors elect a new one; restart the corpse and
//! it catches up; lose the majority and writes REFUSE instead of lying.
//!
//! The client is in the same binary: `put`/`get`/`del` walk the cluster
//! following "not the leader" redirects, and `dump` shows any single node's
//! applied state (explicitly not linearizable — it exists so you can watch a
//! follower converge).

const std = @import("std");
const node = @import("node.zig");
const wire = @import("wire.zig");
const raft = @import("raft");

const usage =
    \\raft-kv — replicated KV store over the raft module's model-checked kernel
    \\
    \\  raft-kv node --id <n> --peers <a:p,a:p,a:p> --data <dir>
    \\  raft-kv put  --cluster <a:p,a:p,a:p> <key> <value>
    \\  raft-kv get  --cluster <a:p,a:p,a:p> <key>
    \\  raft-kv del  --cluster <a:p,a:p,a:p> <key>
    \\  raft-kv dump --node <a:p>
    \\  raft-kv status --cluster <a:p,a:p,a:p>
    \\
    \\Options:
    \\  --id <n>          this node's index into --peers (0-based)
    \\  --peers <list>    every node's listen address, comma-separated;
    \\                    the SAME list, in the SAME order, on every node
    \\  --data <dir>      where this node persists term/vote/log (created)
    \\  --cluster <list>  node addresses the client may try
    \\  --budget <secs>   client retry budget (default 10)
    \\
    \\A three-terminal cluster on loopback:
    \\
    \\  raft-kv node --id 0 --peers 127.0.0.1:7801,127.0.0.1:7802,127.0.0.1:7803 --data n0
    \\  raft-kv node --id 1 --peers 127.0.0.1:7801,127.0.0.1:7802,127.0.0.1:7803 --data n1
    \\  raft-kv node --id 2 --peers 127.0.0.1:7801,127.0.0.1:7802,127.0.0.1:7803 --data n2
    \\
    \\then: raft-kv put --cluster 127.0.0.1:7801,127.0.0.1:7802,127.0.0.1:7803 city Brno
    \\
    \\Exit status: 0 done · 1 error · 2 key not found.
    \\
;

const failure_exit: u8 = 1;
const notfound_exit: u8 = 2;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // DebugAllocator panicking on leak makes the app a leak detector for the
    // modules' ownership contracts, same as the sibling apps.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse {
        std.debug.print("{s}", .{usage});
        return failure_exit;
    };
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage});
        return 0;
    }

    if (std.mem.eql(u8, mode, "node")) return runNode(gpa, io, &args);
    if (std.mem.eql(u8, mode, "put")) return client(gpa, io, &args, .c_put, true);
    if (std.mem.eql(u8, mode, "get")) return client(gpa, io, &args, .c_get, false);
    if (std.mem.eql(u8, mode, "del")) return client(gpa, io, &args, .c_del, false);
    if (std.mem.eql(u8, mode, "dump")) return dump(gpa, io, &args);
    if (std.mem.eql(u8, mode, "status")) return status(gpa, io, &args);

    std.debug.print("raft-kv: unknown command '{s}'\n{s}", .{ mode, usage });
    return failure_exit;
}

// ── node ────────────────────────────────────────────────────────────────────

fn runNode(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var id: ?u32 = null;
    var peers_arg: ?[]const u8 = null;
    var data: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--id")) {
            id = std.fmt.parseInt(u32, try nextValue(args, "--id"), 10) catch return badArg("--id");
        } else if (std.mem.eql(u8, arg, "--peers")) {
            peers_arg = try nextValue(args, "--peers");
        } else if (std.mem.eql(u8, arg, "--data")) {
            data = try nextValue(args, "--data");
        } else return unknown(arg);
    }
    const peers = try splitList(gpa, peers_arg orelse return missing("--peers"));
    defer gpa.free(peers);
    const nid = id orelse return missing("--id");
    if (peers.len < 2 or nid >= peers.len) {
        std.debug.print("raft-kv: --id must index into --peers, and a cluster needs at least 2 nodes\n", .{});
        return failure_exit;
    }
    node.serve(gpa, io, .{
        .id = nid,
        .peers = peers,
        .data = data orelse return missing("--data"),
    }) catch |err| {
        std.debug.print("raft-kv: node stopped: {t}\n", .{err});
        return failure_exit;
    };
    return 0;
}

// ── client ──────────────────────────────────────────────────────────────────

fn client(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator, kind: wire.Kind, wants_value: bool) !u8 {
    var cluster_arg: ?[]const u8 = null;
    var budget_s: u64 = 10;
    var key: ?[]const u8 = null;
    var value: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cluster")) {
            cluster_arg = try nextValue(args, "--cluster");
        } else if (std.mem.eql(u8, arg, "--budget")) {
            budget_s = std.fmt.parseInt(u64, try nextValue(args, "--budget"), 10) catch return badArg("--budget");
        } else if (key == null) {
            key = arg;
        } else if (value == null and wants_value) {
            value = arg;
        } else return unknown(arg);
    }
    const cluster = try splitList(gpa, cluster_arg orelse return missing("--cluster"));
    defer gpa.free(cluster);
    const k = key orelse return missing("<key>");
    if (k.len > wire.max_key) return badArg("<key> (too long)");
    const v = value orelse if (wants_value) return missing("<value>") else "";
    if (v.len > wire.max_value) return badArg("<value> (too long)");

    const frame = try wire.encodeClient(gpa, kind, k, v);
    defer gpa.free(frame);

    // Walk the cluster following redirects until the budget runs out. A node
    // that is down, mid-election, or not the leader is NORMAL here — that is
    // the situation the retry exists for.
    const deadline = nowMs() + budget_s * 1000;
    var attempt: usize = 0;
    var target: usize = 0;
    while (nowMs() < deadline) : (attempt += 1) {
        if (attempt > 0) io.sleep(.fromMilliseconds(150), .awake) catch break;

        var resp_buf: [wire.max_value + 64]u8 = undefined;
        const resp = exchangeAddr(gpa, io, cluster[target], frame, &resp_buf) catch {
            target = (target + 1) % cluster.len;
            continue;
        };
        if (resp.len < 1) {
            target = (target + 1) % cluster.len;
            continue;
        }
        const resp_kind = std.enums.fromInt(wire.Resp, resp[0]) orelse {
            target = (target + 1) % cluster.len;
            continue;
        };
        switch (resp_kind) {
            .ok => {
                // Program OUTPUT goes to stdout; std.debug.print is stderr
                // and a pipeline reading the value would read nothing.
                if (kind == .c_get) {
                    try printOut(io, "{s}\n", .{resp[1..]});
                } else {
                    try printOut(io, "ok\n", .{});
                }
                return 0;
            },
            .notfound => {
                std.debug.print("raft-kv: not found\n", .{});
                return notfound_exit;
            },
            .redirect => {
                if (resp.len >= 5) {
                    const hint = std.mem.readInt(u32, resp[1..5], .little);
                    if (hint != raft.no_vote and hint < cluster.len) {
                        target = hint;
                        continue;
                    }
                }
                target = (target + 1) % cluster.len;
            },
            .err => {
                std.debug.print("raft-kv: node answered: {s} — retrying\n", .{resp[1..]});
                target = (target + 1) % cluster.len;
            },
            else => target = (target + 1) % cluster.len,
        }
    }
    std.debug.print("raft-kv: gave up after {d}s (no reachable leader / no majority?)\n", .{budget_s});
    return failure_exit;
}

fn dump(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var addr: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--node")) {
            addr = try nextValue(args, "--node");
        } else return unknown(arg);
    }
    const frame = try wire.encodeClient(gpa, .c_dump, "", "");
    defer gpa.free(frame);
    const resp_buf = try gpa.alloc(u8, wire.limits.max_frame);
    defer gpa.free(resp_buf);
    const resp = exchangeAddr(gpa, io, addr orelse return missing("--node"), frame, resp_buf) catch |err| {
        std.debug.print("raft-kv: {s}: {t}\n", .{ addr.?, err });
        return failure_exit;
    };
    if (resp.len < 14 or resp[0] != @intFromEnum(wire.Resp.dump)) {
        std.debug.print("raft-kv: malformed dump reply\n", .{});
        return failure_exit;
    }
    const role: []const u8 = switch (resp[1]) {
        'l' => "leader",
        'c' => "candidate",
        else => "follower",
    };
    const term = std.mem.readInt(u64, resp[2..10], .little);
    const count = std.mem.readInt(u32, resp[10..14], .little);
    // One writer for all lines — see status() for why per-line writers
    // overwrite each other when stdout is a regular file.
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    const out = &stdout.interface;
    try out.print("role={s} term={d} keys={d}\n", .{ role, term, count });
    var off: usize = 14;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        if (resp.len < off + 2) break;
        const klen = std.mem.readInt(u16, resp[off..][0..2], .little);
        off += 2;
        if (resp.len < off + klen + 4) break;
        const k = resp[off..][0..klen];
        off += klen;
        const vlen = std.mem.readInt(u32, resp[off..][0..4], .little);
        off += 4;
        if (resp.len < off + vlen) break;
        try out.print("{s}={s}\n", .{ k, resp[off..][0..vlen] });
        off += vlen;
    }
    try out.flush();
    return 0;
}

/// One line per node: who is up, who leads, which term, how many keys —
/// the three `dump` calls you would otherwise type while watching a
/// failover, as one command. Exit 0 if any node answered.
fn status(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var cluster_arg: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cluster")) {
            cluster_arg = try nextValue(args, "--cluster");
        } else return unknown(arg);
    }
    const cluster = try splitList(gpa, cluster_arg orelse return missing("--cluster"));
    defer gpa.free(cluster);

    const frame = try wire.encodeClient(gpa, .c_dump, "", "");
    defer gpa.free(frame);

    const resp_buf = try gpa.alloc(u8, wire.limits.max_frame);
    defer gpa.free(resp_buf);
    // ONE writer for the whole table. A fresh `File.stdout().writer` per
    // line writes POSITIONALLY from its own offset 0 — to a terminal or a
    // pipe that reads as appending, but redirected to a regular file every
    // line lands on top of the previous one. Measured: `status > out` kept
    // only the last line.
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    const out = &stdout.interface;
    var up: usize = 0;
    for (cluster, 0..) |addr, i| {
        const resp = exchangeAddr(gpa, io, addr, frame, resp_buf) catch |err| {
            try out.print("node {d}  {s}  DOWN ({t})\n", .{ i, addr, err });
            continue;
        };
        if (resp.len < 14 or resp[0] != @intFromEnum(wire.Resp.dump)) {
            try out.print("node {d}  {s}  malformed reply\n", .{ i, addr });
            continue;
        }
        up += 1;
        const role: []const u8 = switch (resp[1]) {
            'l' => "leader",
            'c' => "candidate",
            else => "follower",
        };
        try out.print("node {d}  {s}  {s}  term={d}  keys={d}\n", .{
            i,
            addr,
            role,
            std.mem.readInt(u64, resp[2..10], .little),
            std.mem.readInt(u32, resp[10..14], .little),
        });
    }
    try out.flush();
    return if (up == 0) failure_exit else 0;
}

fn exchangeAddr(gpa: std.mem.Allocator, io: std.Io, addr_text: []const u8, frame: []const u8, resp_buf: []u8) ![]u8 {
    _ = gpa;
    const colon = std.mem.lastIndexOfScalar(u8, addr_text, ':') orelse return error.BadAddress;
    const port = std.fmt.parseInt(u16, addr_text[colon + 1 ..], 10) catch return error.BadAddress;
    const addr = std.Io.net.IpAddress.parse(addr_text[0..colon], port) catch return error.BadAddress;
    var stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [1024]u8 = undefined;
    var rbuf: [1024]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var r = stream.reader(io, &rbuf);
    try wire.writeFrame(&w.interface, frame);
    return wire.readFrame(&r.interface, resp_buf);
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buf);
    try stdout.interface.print(fmt, args);
    try stdout.interface.flush();
}

/// `std.time`'s wall/monotonic timestamp helpers are gone in 0.16; same
/// direct `clock_gettime` the sibling apps use.
fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1_000_000;
}

/// Split "a:p,a:p,a:p" into slices borrowing the argument.
fn splitList(gpa: std.mem.Allocator, text: []const u8) ![][]const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(gpa);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        if (part.len > 0) try list.append(gpa, part);
    }
    return list.toOwnedSlice(gpa);
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) ![]const u8 {
    return args.next() orelse {
        std.debug.print("raft-kv: {s} needs a value\n{s}", .{ flag, usage });
        return error.MissingValue;
    };
}

fn missing(flag: []const u8) u8 {
    std.debug.print("raft-kv: {s} is required\n{s}", .{ flag, usage });
    return failure_exit;
}

fn badArg(flag: []const u8) u8 {
    std.debug.print("raft-kv: {s} does not parse\n", .{flag});
    return failure_exit;
}

fn unknown(arg: []const u8) !u8 {
    std.debug.print("raft-kv: unknown option '{s}'\n{s}", .{ arg, usage });
    return failure_exit;
}
