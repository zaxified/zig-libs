// SPDX-License-Identifier: MIT

//! `trace` against real Linux routers: `tools/kernel_oracle.py` builds a
//! client -> r1 -> r2 -> r3 -> server chain of network namespaces per
//! scenario (clean, a router whose Time Exceeded is dropped, a router that
//! rejects with Administratively Prohibited, a server that drops
//! everything), runs this program inside the client namespace (`--trace`),
//! and judges every hop against the addresses the topology was built with --
//! and against traceroute(8), which measures the same path its own way. The
//! transport is recorded (every packet sent, every packet or timeout
//! received) on a virtual clock; the transcripts are frozen in
//! `src/kernel_oracle_vectors.zig` and replayed through `traceWith` by
//! `src/kernel_oracle_test.zig` in `test-traceroute`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-traceroute` runs it and
//! `zig build check-interop` compiles it. It needs python3, `unshare`, `ip`,
//! `nft`, `ping` and `traceroute`; no root, no network. A missing one is a
//! failure.
//!
//!   zig build interop-traceroute              # re-take, write src/kernel_oracle_vectors.zig
//!   zig build interop-traceroute -- --check   # re-take, compare the verdicts with the committed file

const std = @import("std");
const traceroute = @import("traceroute");
const netaddr = @import("netaddr");

const scratch = ".zig-cache/interop-traceroute";
const script = "modules/traceroute/tools/kernel_oracle.py";
const vectors = "modules/traceroute/src/kernel_oracle_vectors.zig";

/// The options every recorded trace uses; the replay uses the same ones.
pub const udp_source_port: u16 = 43210;

/// Wraps the live transport: forwards every call, records each send and each
/// receive (packet or timeout) as one JSON array, and answers `nowFn` from a
/// virtual clock -- +1 ms per reading, +the whole timeout on a timeout -- so
/// the transcript, RTTs included, replays bit for bit.
const Recorder = struct {
    inner: traceroute.Transport,
    w: *std.json.Stringify,
    clock: u64 = 1_000_000_000,
    failed: bool = false,

    fn transport(self: *Recorder) traceroute.Transport {
        return .{
            .ctx = self,
            .strip_ip_header = self.inner.strip_ip_header,
            .sendFn = sendFn,
            .sendUdpFn = if (self.inner.sendUdpFn != null) sendUdpFn else null,
            .recvFn = recvFn,
            .nowFn = nowFn,
        };
    }

    fn rec(self: *Recorder, comptime f: anytype, args: anytype) void {
        @call(.auto, f, .{self.w} ++ args) catch {
            self.failed = true;
        };
    }

    fn sendFn(ctx: *anyopaque, ttl: u8, packet: []const u8) traceroute.TransportError!void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.rec(writeSend, .{ ttl, packet });
        return self.inner.sendFn(self.inner.ctx, ttl, packet);
    }

    fn sendUdpFn(ctx: *anyopaque, ttl: u8, dst_port: u16, payload: []const u8) traceroute.TransportError!void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.rec(writeSendUdp, .{ ttl, dst_port, payload });
        return self.inner.sendUdpFn.?(self.inner.ctx, ttl, dst_port, payload);
    }

    fn recvFn(ctx: *anyopaque, buf: []u8, timeout_ns: u64) traceroute.TransportError!?traceroute.Packet {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        const got = try self.inner.recvFn(self.inner.ctx, buf, timeout_ns);
        if (got) |p| {
            self.rec(writeRecv, .{ buf[0..p.len], p.from });
        } else {
            self.clock += timeout_ns;
            self.rec(writeTimeout, .{});
        }
        return got;
    }

    fn nowFn(ctx: *anyopaque) u64 {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.clock += 1_000_000;
        return self.clock;
    }

    fn writeSend(w: *std.json.Stringify, ttl: u8, packet: []const u8) !void {
        try w.beginArray();
        try w.write("send");
        try w.write(ttl);
        try w.print("\"{x}\"", .{packet});
        try w.endArray();
    }

    fn writeSendUdp(w: *std.json.Stringify, ttl: u8, port: u16, payload: []const u8) !void {
        try w.beginArray();
        try w.write("send_udp");
        try w.write(ttl);
        try w.write(port);
        try w.print("\"{x}\"", .{payload});
        try w.endArray();
    }

    fn writeRecv(w: *std.json.Stringify, bytes: []const u8, from: ?netaddr.Ip) !void {
        try w.beginArray();
        try w.write("recv");
        try w.print("\"{x}\"", .{bytes});
        if (from) |a| try writeIp(w, a) else try w.write(null);
        try w.endArray();
    }

    fn writeTimeout(w: *std.json.Stringify) !void {
        try w.beginArray();
        try w.write("timeout");
        try w.endArray();
    }
};

fn writeIp(w: *std.json.Stringify, a: netaddr.Ip) !void {
    var buf: [netaddr.max_ip_text_len]u8 = undefined;
    try w.write(netaddr.formatIp(a, &buf));
}

/// `--trace DEST icmp|udp MAX_HOPS PROBES TIMEOUT_MS`: runs inside the client
/// namespace. One JSON object on stdout: the transcript and the trace.
fn traceMode(gpa: std.mem.Allocator, io: std.Io, dest_text: []const u8, method_text: []const u8, opts_in: traceroute.Options) !u8 {
    const dest = netaddr.parseIp(dest_text) orelse return error.BadAddress;
    var opts = opts_in;
    opts.method = std.meta.stringToEnum(traceroute.Method, method_text) orelse return error.BadMethod;
    if (opts.method == .udp) opts.source_port = udp_source_port;
    var lt = try traceroute.LinuxTransport.openWith(dest, opts);
    defer lt.close();
    if (opts.method == .udp) opts.ident = lt.ident();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var s: std.json.Stringify = .{ .writer = &out.writer };
    try s.beginObject();
    try s.objectField("ident");
    try s.write(opts.ident);
    try s.objectField("events");
    try s.beginArray();
    var rec: Recorder = .{ .inner = lt.transport(), .w = &s };
    var tr = try traceroute.traceWith(gpa, rec.transport(), dest, opts);
    defer tr.deinit(gpa);
    try s.endArray();
    if (rec.failed) return error.RecordFailed;
    try s.objectField("reached");
    try s.write(tr.reached);
    try s.objectField("unreachable_code");
    try s.write(tr.unreachable_code);
    try s.objectField("hops");
    try s.beginArray();
    for (tr.hops) |hop| {
        try s.beginArray();
        for (hop.probes) |p| {
            try s.beginArray();
            try s.write(@tagName(p.kind));
            if (p.address) |a| try writeIp(&s, a) else try s.write(null);
            try s.write(p.code);
            try s.write(p.rtt_ns);
            try s.endArray();
        }
        try s.endArray();
    }
    try s.endArray();
    try s.endObject();
    var stdout = std.Io.File.stdout().writerStreaming(io, &.{});
    try stdout.interface.writeAll(out.written());
    try stdout.interface.writeAll("\n");
    return 0;
}

/// The verdict lines (`//= `) of a vectors file: what `--check` compares.
/// Router packets carry fields a re-take never reproduces (IPv4 IDs, the
/// quoted probe's ID), so the raw transcript is refreshed, not compared.
fn verdictLines(arena: std.mem.Allocator, text: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, std.mem.trimStart(u8, line, " "), "//= ")) {
            try out.writer.writeAll(line);
            try out.writer.writeByte('\n');
        }
    }
    return out.written();
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    const self_path = args.next() orelse return 2;
    var check = false;
    if (args.next()) |a| {
        if (std.mem.eql(u8, a, "--trace")) {
            const dest = args.next() orelse return 2;
            const method = args.next() orelse return 2;
            const max_hops = try std.fmt.parseInt(u8, args.next() orelse return 2, 10);
            const probes = try std.fmt.parseInt(u8, args.next() orelse return 2, 10);
            const timeout_ms = try std.fmt.parseInt(u32, args.next() orelse return 2, 10);
            return traceMode(gpa, io, dest, method, .{ .max_hops = max_hops, .probes_per_hop = probes, .timeout_ms = timeout_ms });
        } else if (std.mem.eql(u8, a, "--check")) {
            check = true;
        } else {
            std.debug.print("usage: interop-traceroute [--check]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    const env = try init.environ.createMap(arena);
    const fresh_path = scratch ++ "/kernel_oracle_vectors.zig";
    try cwd.writeFile(io, .{ .sub_path = fresh_path, .data = "" });
    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", script, "judge", self_path, fresh_path },
        .environ_map = &env,
        .stdin = .close,
    }) catch |e| {
        std.debug.print("could not spawn python3 ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    const rc: u8 = switch (try child.wait(io)) {
        .exited => |code| code,
        else => 1,
    };
    const raw = try cwd.readFileAlloc(io, fresh_path, arena, .limited(16 << 20));
    var ast = try std.zig.Ast.parse(arena, try arena.dupeZ(u8, raw), .zig);
    if (ast.errors.len != 0) {
        std.debug.print("interop-traceroute: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(16 << 20));
        if (!std.mem.eql(u8, try verdictLines(arena, old), try verdictLines(arena, fresh))) {
            std.debug.print("interop-traceroute: committed verdicts differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-traceroute: verdicts fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}
