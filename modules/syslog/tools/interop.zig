// SPDX-License-Identifier: MIT

//! Every message shape against a real rsyslogd: `tools/rsyslog_oracle.py`
//! draws messages (every PRI, timestamps at and past every edge, every byte
//! class in every header field, hostile SD names and values, MSG shapes,
//! RFC 3164 lines), this program encodes each with `buildDatagram` and
//! `writeOctetCounted` (RFC 5424) or `bsd.bufPrint` (RFC 3164), and rsyslogd
//! -- run unconfined from a copy, in `unshare -rn` -- must parse each back to
//! what the message meant. Frozen in `src/rsyslog_oracle_vectors.zig`,
//! replayed by `src/rsyslog_oracle_test.zig` in `test-syslog`.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-syslog` runs it and
//! `zig build check-interop` compiles it. It needs python3, rsyslogd 8 (with
//! imudp, imtcp, mmpstrucdata), `unshare` and `ip`; no root, no network. A
//! missing one is a failure.
//!
//!   zig build interop-syslog              # re-take, write src/rsyslog_oracle_vectors.zig
//!   zig build interop-syslog -- --check   # re-take, compare with the committed file

const std = @import("std");
const syslog = @import("syslog");

const scratch = ".zig-cache/interop-syslog";
const script = "modules/syslog/tools/rsyslog_oracle.py";
const vectors = "modules/syslog/src/rsyslog_oracle_vectors.zig";

/// A case as the generator describes it: strings hex-encoded (they may be
/// any bytes, which JSON cannot carry).
const CaseIn = struct {
    kind: []const u8,
    facility: u5 = 0,
    severity: u3 = 0,
    ts: ?struct { i64, ?i16 } = null,
    hostname: ?[]const u8 = null,
    app_name: ?[]const u8 = null,
    procid: ?[]const u8 = null,
    msgid: ?[]const u8 = null,
    sd: []const struct { id: []const u8, params: []const [2][]const u8 } = &.{},
    tag: []const u8 = "",
    pid: ?[]const u8 = null,
    msg: []const u8 = "",
    // journal / jsend / jname
    fields: []const [2][]const u8 = &.{},
    message: []const u8 = "",
    priority: ?u3 = null,
    identifier: ?[]const u8 = null,
    name: []const u8 = "",
};

const linux = std.os.linux;

/// What `journal.Emitter` put on the wire, caught by a socket of our own: one
/// datagram, byte for byte, which the oracle then hands to journald.
const Capture = struct {
    fd: linux.fd_t,

    fn bind(path: []const u8) !Capture {
        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
        @memcpy(addr.path[0..path.len], path);
        const s = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(s) != .SUCCESS) return error.SocketFailed;
        const fd: linux.fd_t = @intCast(s);
        if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.BindFailed;
        return .{ .fd = fd };
    }

    fn recv(c: *Capture, buf: []u8) ![]u8 {
        const rc = linux.read(c.fd, buf.ptr, buf.len);
        if (linux.errno(rc) != .SUCCESS) return error.ReadFailed;
        return buf[0..rc];
    }
};

fn journalFields(arena: std.mem.Allocator, in: []const [2][]const u8) ![]syslog.journal.Field {
    const out = try arena.alloc(syslog.journal.Field, in.len);
    for (in, out) |f, *o| o.* = .{ .name = try unhex(arena, f[0]), .value = try unhex(arena, f[1]) };
    return out;
}

fn unhex(a: std.mem.Allocator, h: []const u8) ![]const u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

fn unhexOpt(a: std.mem.Allocator, h: ?[]const u8) !?[]const u8 {
    return if (h) |v| try unhex(a, v) else null;
}

fn timestamp(ts: ?struct { i64, ?i16 }) ?syslog.Timestamp {
    const t = ts orelse return null;
    return .{ .unix_ms = t[0], .offset_minutes = t[1] };
}

fn python(io: std.Io, arena: std.mem.Allocator, env: *const std.process.Environ.Map, argv: []const []const u8, stdout_path: ?[]const u8) !u8 {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .environ_map = env,
        .stdin = .close,
        .stdout = if (stdout_path != null) .pipe else .inherit,
        .stderr = .inherit,
    }) catch |e| {
        std.debug.print("could not spawn python3 ({t}) -- the oracle needs it\n", .{e});
        return error.NoPython;
    };
    if (stdout_path) |p| {
        var rbuf: [4096]u8 = undefined;
        var r = child.stdout.?.readerStreaming(io, &rbuf);
        const all = try r.interface.allocRemaining(arena, .limited(64 << 20));
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = all });
    }
    const term = try child.wait(io);
    return switch (term) {
        .exited => |code| code,
        else => 1,
    };
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

    var check = false;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--check")) {
            check = true;
        } else {
            std.debug.print("usage: interop-syslog [--check]\n", .{});
            return 2;
        }
    }

    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, scratch) catch {};
    const env = try init.environ.createMap(arena);
    const cases_path = scratch ++ "/cases.json";
    const ours_path = scratch ++ "/ours.json";
    const fresh_path = scratch ++ "/rsyslog_oracle_vectors.zig";
    if (try python(io, arena, &env, &.{ "python3", script, "gen" }, cases_path) != 0) return 1;

    const text = try cwd.readFileAlloc(io, cases_path, arena, .limited(64 << 20));
    const cases = try std.json.parseFromSliceLeaky([]const CaseIn, arena, text, .{});
    const cap_path = scratch ++ "/capture.sock";
    cwd.deleteFile(io, cap_path) catch {};
    var cap = try Capture.bind(cap_path);
    defer _ = linux.close(cap.fd);
    var emitter = try syslog.journal.Emitter.open(cap_path);
    defer emitter.close();
    var unix_emitter = try syslog.UnixEmitter.open(cap_path);
    defer unix_emitter.close();
    const dgram_in = try arena.alloc(u8, 1 << 20);
    var out: std.Io.Writer.Allocating = .init(arena);
    var s: std.json.Stringify = .{ .writer = &out.writer };
    try s.beginArray();
    for (cases) |c| {
        const msg = try unhex(arena, c.msg);
        var line_buf: [8192]u8 = undefined;
        var dgram_buf: [syslog.default_udp_limit * 2]u8 = undefined;
        try s.beginArray();
        if (std.mem.eql(u8, c.kind, "5424")) {
            const sd = try arena.alloc(syslog.SdElement, c.sd.len);
            for (c.sd, sd) |in, *el| {
                const params = try arena.alloc(syslog.SdParam, in.params.len);
                for (in.params, params) |p, *q| q.* = .{ .name = try unhex(arena, p[0]), .value = try unhex(arena, p[1]) };
                el.* = .{ .id = try unhex(arena, in.id), .params = params };
            }
            const m: syslog.Message = .{
                .facility = @enumFromInt(c.facility),
                .severity = @enumFromInt(c.severity),
                .timestamp = timestamp(c.ts),
                .hostname = try unhexOpt(arena, c.hostname),
                .app_name = try unhexOpt(arena, c.app_name),
                .procid = try unhexOpt(arena, c.procid),
                .msgid = try unhexOpt(arena, c.msgid),
                .structured_data = sd,
                .msg = msg,
            };
            const line = try syslog.bufPrint(&m, &line_buf);
            const dgram = syslog.buildDatagram(&m, &dgram_buf, .{});
            var frame: std.Io.Writer.Allocating = .init(arena);
            try syslog.writeOctetCounted(&frame.writer, line);
            try s.print("\"{x}\"", .{line});
            try s.print("\"{x}\"", .{dgram});
            try s.print("\"{x}\"", .{frame.written()});
            try unix_emitter.send(&m);
            try s.print("\"{x}\"", .{try cap.recv(dgram_in)});
        } else if (std.mem.eql(u8, c.kind, "journal") or std.mem.eql(u8, c.kind, "jsend")) {
            if (std.mem.eql(u8, c.kind, "journal")) {
                try emitter.send(try journalFields(arena, c.fields));
            } else {
                try emitter.sendMessage(.{
                    .message = try unhex(arena, c.message),
                    .priority = if (c.priority) |p| @enumFromInt(p) else null,
                    .identifier = try unhexOpt(arena, c.identifier),
                    .fields = try journalFields(arena, c.fields),
                });
            }
            const got = try cap.recv(dgram_in);
            try s.print("\"{x}\"", .{got});
            try s.print("\"{x}\"", .{got});
            try s.write("");
            try s.write("");
        } else if (std.mem.eql(u8, c.kind, "jname")) {
            const verdict: []const u8 = if (syslog.journal.validFieldName(try unhex(arena, c.name))) |_| "ok" else |e| @errorName(e);
            try s.print("\"{x}\"", .{verdict});
            try s.write("");
            try s.write("");
            try s.write("");
        } else {
            const m: syslog.bsd.Message = .{
                .facility = @enumFromInt(c.facility),
                .severity = @enumFromInt(c.severity),
                .timestamp = timestamp(c.ts),
                .hostname = try unhexOpt(arena, c.hostname),
                .tag = try unhex(arena, c.tag),
                .pid = try unhexOpt(arena, c.pid),
                .msg = msg,
            };
            const line = try syslog.bsd.bufPrint(&m, &line_buf);
            try s.print("\"{x}\"", .{line});
            try s.print("\"{x}\"", .{line});
            try s.write("");
            try unix_emitter.sendBsd(&m);
            try s.print("\"{x}\"", .{try cap.recv(dgram_in)});
        }
        try s.endArray();
    }
    try s.endArray();
    try cwd.writeFile(io, .{ .sub_path = ours_path, .data = out.written() });

    try cwd.writeFile(io, .{ .sub_path = fresh_path, .data = "" });
    const rc = try python(io, arena, &env, &.{ "python3", script, "judge", cases_path, ours_path, fresh_path }, null);
    const raw = try cwd.readFileAlloc(io, fresh_path, arena, .limited(64 << 20));
    var ast = try std.zig.Ast.parse(arena, try arena.dupeZ(u8, raw), .zig);
    if (ast.errors.len != 0) {
        std.debug.print("interop-syslog: the generated vectors do not parse as Zig\n", .{});
        return 1;
    }
    const fresh = try ast.renderAlloc(arena);
    if (check) {
        const old = try cwd.readFileAlloc(io, vectors, arena, .limited(64 << 20));
        if (!std.mem.eql(u8, afterLine(old, 2), afterLine(fresh, 2))) {
            std.debug.print("interop-syslog: committed vectors differ from a fresh run\n", .{});
            return 1;
        }
        std.debug.print("interop-syslog: vectors fresh\n", .{});
    } else {
        try cwd.writeFile(io, .{ .sub_path = vectors, .data = fresh });
    }
    return rc;
}
