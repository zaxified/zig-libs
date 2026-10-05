// SPDX-License-Identifier: MIT

//! `query` and the packet codec against a real NTP server: `tools/ntp_oracle.py`
//! runs chronyd 4.8 (unprivileged, `-x`, in `unshare -rn`) per scenario --
//! synchronized at stratum 3 and 10, unsynchronized, rate limiting with
//! Kiss-o'-Death RATE, denying the client -- and asks it through this
//! program (`--live`: `query`; `--raw`: the codec path a consumer drives
//! itself, recording every reply's bytes), through beevik/ntp (the Go
//! reference client, `tools/go_oracle`), and judges the raw replies' offset
//! and delay with ntplib on the very same bytes. Frozen in
//! `src/ntp_oracle_vectors.zig`, replayed by `src/ntp_oracle_test.zig` in
//! `test-sntp`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-sntp` runs it and
//! `zig build check-interop` compiles it. It needs python3, `unshare`, `ip`,
//! go (beevik/ntp in the module cache, GOPROXY=off), chronyd 4 and ntplib
//! (`ZIGLIBS_CHRONYD`, `ZIGLIBS_NTPLIB_PY`; defaults under
//! `~/.local/share/zig-libs/`); no root, no network.
//!
//!   zig build interop-sntp              # re-take, write src/ntp_oracle_vectors.zig
//!   zig build interop-sntp -- --check   # re-take, compare the verdict lines

const std = @import("std");
const sntp = @import("sntp");

const scratch = ".zig-cache/interop-sntp";
const script = "modules/sntp/tools/ntp_oracle.py";
const vectors = "modules/sntp/src/ntp_oracle_vectors.zig";

fn writeTs(s: *std.json.Stringify, t: sntp.Timestamp) !void {
    try s.print("\"{x}\"", .{&t.toBytes()});
}

fn writeReply(s: *std.json.Stringify, r: sntp.Reply) !void {
    try s.objectField("stratum");
    try s.write(r.stratum);
    try s.objectField("leap");
    try s.write(@intFromEnum(r.leap));
    try s.objectField("version");
    try s.write(r.version);
    try s.objectField("refid");
    try s.print("\"{x}\"", .{&r.reference_id});
}

/// `--live ADDR PORT VERSION TIMEOUT_MS`: one `query`.
fn liveMode(io: std.Io, out: *std.Io.Writer, addr: []const u8, port: u16, version: u3, timeout_ms: u32) !void {
    const server = try std.Io.net.IpAddress.parse(addr, port);
    var s: std.json.Stringify = .{ .writer = out };
    var kiss: sntp.KissOfDeath = undefined;
    try s.beginObject();
    if (sntp.query(io, server, .{ .version = version, .timeout_ms = timeout_ms }, &kiss)) |r| {
        try writeReply(&s, r.reply);
        try s.objectField("offset_ns");
        try s.print("{d}", .{r.offset_ns});
        try s.objectField("roundtrip_ns");
        try s.print("{d}", .{r.roundtrip_ns});
    } else |e| {
        try s.objectField("error");
        try s.write(@errorName(e));
        if (e == error.KissOfDeath) {
            try s.objectField("kiss");
            try s.write(@tagName(kiss.code));
        }
    }
    try s.endObject();
}

/// `--raw ADDR PORT VERSION COUNT`: COUNT exchanges built from the public
/// codec (what a consumer with its own socket does): T1, the request, the
/// reply's bytes, T4, and what `decodeResponse` + `Sample` made of them.
fn rawMode(io: std.Io, out: *std.Io.Writer, addr: []const u8, port: u16, version: u3, count: u32) !void {
    const server = try std.Io.net.IpAddress.parse(addr, port);
    const bind_addr: std.Io.net.IpAddress = switch (server) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    const sock = try bind_addr.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var s: std.json.Stringify = .{ .writer = out };
    try s.beginArray();
    for (0..count) |_| {
        const t1 = try sntp.nowTimestamp();
        const request = (sntp.Packet{ .version = version, .mode = .client, .transmit = t1 }).encode();
        try sock.send(io, &server, &request);
        var buf: [256]u8 = undefined;
        const timeout: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(500), .clock = .awake } };
        const got = sock.receiveTimeout(io, &buf, timeout.toDeadline(io)) catch |e| switch (e) {
            error.Timeout => {
                try s.write(null);
                continue;
            },
            else => return e,
        };
        const t4 = try sntp.nowTimestamp();
        try s.beginObject();
        try s.objectField("t1");
        try writeTs(&s, t1);
        try s.objectField("t4");
        try writeTs(&s, t4);
        try s.objectField("reply");
        try s.print("\"{x}\"", .{got.data});
        var kiss: sntp.KissOfDeath = undefined;
        if (sntp.decodeResponse(got.data, &kiss)) |r| {
            try writeReply(&s, r);
            try s.objectField("originate_ok");
            try s.write(if (sntp.verifyOriginate(r, t1)) |_| true else |_| false);
            const sample: sntp.Sample = .{ .originate = t1, .receive = r.receive, .transmit = r.transmit, .destination = t4 };
            try s.objectField("offset_ns");
            try s.print("{d}", .{sample.offsetNanos()});
            try s.objectField("roundtrip_ns");
            try s.print("{d}", .{sample.roundtripDelayNanos()});
        } else |e| {
            try s.objectField("error");
            try s.write(@errorName(e));
            if (e == error.KissOfDeath) {
                try s.objectField("kiss");
                try s.write(@tagName(kiss.code));
            }
        }
        try s.endObject();
    }
    try s.endArray();
}

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
        if (std.mem.eql(u8, a, "--live") or std.mem.eql(u8, a, "--raw")) {
            const addr = args.next() orelse return 2;
            const port = try std.fmt.parseInt(u16, args.next() orelse return 2, 10);
            const version = try std.fmt.parseInt(u3, args.next() orelse return 2, 10);
            const n = try std.fmt.parseInt(u32, args.next() orelse return 2, 10);
            var out: std.Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            if (a[2] == 'l') try liveMode(io, &out.writer, addr, port, version, n) else try rawMode(io, &out.writer, addr, port, version, n);
            var stdout = std.Io.File.stdout().writerStreaming(io, &.{});
            try stdout.interface.writeAll(out.written());
            try stdout.interface.writeAll("\n");
            return 0;
        } else if (std.mem.eql(u8, a, "--check")) {
            check = true;
        } else {
            std.debug.print("usage: interop-sntp [--check]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    const env = try init.environ.createMap(arena);
    const fresh_path = scratch ++ "/ntp_oracle_vectors.zig";
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
        std.debug.print("interop-sntp: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(16 << 20));
        if (!std.mem.eql(u8, try verdictLines(arena, old), try verdictLines(arena, fresh))) {
            std.debug.print("interop-sntp: committed verdicts differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-sntp: verdicts fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}
