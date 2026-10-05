// SPDX-License-Identifier: MIT

//! `probe` and `query` against real Linux kernels: `tools/kernel_oracle.py`
//! builds a client -> router -> server topology of network namespaces for
//! each scenario (a lowered-MTU link, none, jumbo frames, a router whose
//! firewall eats its own ICMP errors), runs this program inside the client
//! namespace (`--probe`), and judges what it found against the MTU the links
//! were configured with -- and against iputils `tracepath`, which measures
//! the same path its own way. Every attempt the live prober made is recorded
//! (`Options.on_attempt`); the transcripts are frozen in
//! `src/kernel_oracle_vectors.zig` and replayed through `searchWith` by
//! `src/kernel_oracle_test.zig` in `test-pathmtu`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-pathmtu` runs it and
//! `zig build check-interop` compiles it. It needs python3, `unshare`, `ip`,
//! `nft` and `tracepath`; no root, no network. A missing one is a failure.
//!
//!   zig build interop-pathmtu              # re-take, write src/kernel_oracle_vectors.zig
//!   zig build interop-pathmtu -- --check   # re-take, compare with the committed file

const std = @import("std");
const pathmtu = @import("pathmtu");
const netaddr = @import("netaddr");

const scratch = ".zig-cache/interop-pathmtu";
const script = "modules/pathmtu/tools/kernel_oracle.py";
const vectors = "modules/pathmtu/src/kernel_oracle_vectors.zig";

const Recorder = struct {
    w: *std.json.Stringify,
    failed: bool = false,

    fn observer(self: *Recorder) pathmtu.AttemptObserver {
        return .{ .ctx = self, .onAttempt = onAttempt };
    }

    fn onAttempt(ctx: *anyopaque, wire_size: u16, outcome: pathmtu.ProbeOutcome) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.write(wire_size, outcome) catch {
            self.failed = true;
        };
    }

    fn write(self: *Recorder, wire_size: u16, outcome: pathmtu.ProbeOutcome) !void {
        try self.w.beginArray();
        try self.w.write(wire_size);
        try self.w.write(@tagName(outcome));
        switch (outcome) {
            .frag_needed => |hint| try self.w.write(hint),
            else => try self.w.write(null),
        }
        try self.w.endArray();
    }
};

fn writeResult(s: *std.json.Stringify, r: anytype) !void {
    if (r) |res| {
        try s.beginObject();
        try s.objectField("mtu");
        try s.write(res.mtu);
        try s.objectField("blackhole");
        try s.write(res.blackhole);
        try s.objectField("iface_mtu");
        try s.write(res.iface_mtu);
        try s.endObject();
    } else |e| {
        try s.write(@errorName(e));
    }
}

/// `--probe DEST IFACE TIMEOUT_MS RETRIES`: runs inside the client namespace.
/// One JSON object on stdout: the kernel cache before, the probe with every
/// attempt, the kernel cache after.
fn probeMode(gpa: std.mem.Allocator, io: std.Io, dest_text: []const u8, iface: []const u8, timeout_ms: u32, retries: u8) !u8 {
    const dest = netaddr.parseIp(dest_text) orelse return error.BadAddress;
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    var s: std.json.Stringify = .{ .writer = &out.writer };
    try s.beginObject();
    try s.objectField("query_before");
    try writeResult(&s, pathmtu.query(dest, .{ .iface = iface }));
    try s.objectField("attempts");
    try s.beginArray();
    var rec: Recorder = .{ .w = &s };
    const probed = pathmtu.probe(dest, .{ .iface = iface, .timeout_ms = timeout_ms, .retries = retries, .on_attempt = rec.observer() });
    try s.endArray();
    if (rec.failed) return error.RecordFailed;
    try s.objectField("probe");
    try writeResult(&s, probed);
    try s.objectField("query_after");
    try writeResult(&s, pathmtu.query(dest, .{ .iface = iface }));
    try s.endObject();
    var stdout = std.Io.File.stdout().writerStreaming(io, &.{});
    try stdout.interface.writeAll(out.written());
    try stdout.interface.writeAll("\n");
    return 0;
}

fn afterLine(text: []const u8, n: usize) []const u8 {
    var rest = text;
    for (0..n) |_| {
        const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse return "";
        rest = rest[nl + 1 ..];
    }
    return rest;
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
        if (std.mem.eql(u8, a, "--probe")) {
            const dest = args.next() orelse return 2;
            const iface = args.next() orelse return 2;
            const timeout_ms = try std.fmt.parseInt(u32, args.next() orelse return 2, 10);
            const retries = try std.fmt.parseInt(u8, args.next() orelse return 2, 10);
            return probeMode(gpa, io, dest, iface, timeout_ms, retries);
        } else if (std.mem.eql(u8, a, "--check")) {
            check = true;
        } else {
            std.debug.print("usage: interop-pathmtu [--check]\n", .{});
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
        std.debug.print("interop-pathmtu: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(16 << 20));
        if (!std.mem.eql(u8, afterLine(old, 2), afterLine(fresh, 2))) {
            std.debug.print("interop-pathmtu: committed vectors differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-pathmtu: vectors fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}
