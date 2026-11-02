// SPDX-License-Identifier: MIT

//! Comparative benchmark: `syslog`'s encoders, local send and parsers against
//! what is out there, the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-syslog` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Needs go 1.26 and cargo
//! with the pinned packages fetched (`tools/README.md`). Run from the repository
//! root. Arguments filter workloads.
//!
//! No foreign implementation does everything, so each row names its pair, and the
//! pairs do the same work. One op = 64 messages of a fixed seed; texts are
//! 60-140 bytes of ASCII, written by this driver into
//! `.zig-cache/bench-syslog/`, where the foreign sides read them. Every encoder
//! row reads the clock once per message, as the foreign formatters cannot be
//! told not to, and prints an RFC 3339 / RFC 3164 stamp from it.
//!
//! The reference is Go: `log/syslog` (the client) and go-syslog (the parser and
//! the 5424 builder), which together do every row but one. The fastest is Rust:
//! the `syslog` crate for encoding and sending, `syslog_rfc5424` and `syslog_loose`
//! for parsing.
//!
//!   fmt_5424      RFC 5424 line, no SD, into a reused buffer.
//!                 Ours `nowTimestamp` + `bufPrint` (milliseconds).
//!                 ref Go go-syslog v4.6.0 `SyslogMessage.String()`, which returns
//!                 a new string (its API has no other).
//!                 alt Rust `syslog` 7.0.0 `Formatter5424::format` into a cleared
//!                 Vec (microseconds, two bytes more; the crate's choice).
//!   fmt_5424_sd   The same with one SD element of three params, values escaped.
//!                 Rust's API takes the SD by value as nested BTreeMaps, so a clone
//!                 of a prepared map per message is its cost of doing this; Go's
//!                 keeps a prepared map and sorts it per message; ours is a slice
//!                 of the caller's, not copied.
//!   fmt_3164      RFC 3164 line, HOSTNAME and PID, into a reused buffer.
//!                 Ours `bsd.bufPrint`; Rust `Formatter3164::format`, a fastest-only
//!                 row. Go's `log/syslog` has this line too but only behind a
//!                 socket: see `send_unix`.
//!   send_unix     One RFC 3164 message over a unix datagram socket, one syscall
//!                 each, with a thread of the same process draining it.
//!                 Ours `UnixEmitter.sendBsd` (`sendto`, a retry sleep on a full
//!                 queue); ref Go `log/syslog` `Dial("unixgram")` + `Info` (`write`,
//!                 through the netpoller, one more byte: its LF); alt Rust
//!                 `syslog::unix_custom` + `Logger::info` (`send` on a connected
//!                 socket, blocks on a full queue, the line built in a new String).
//!   parse_5424    RFC 5424, no SD, every field read and the timestamp converted.
//!                 Ours `parse`, no allocation; ref Go go-syslog v4.6.0
//!                 `rfc5424.NewParser().Parse`, strict mode (a message object, the
//!                 strings copied); alt Rust `syslog_rfc5424` 0.10.0 (the same).
//!   parse_5424_sd With two SD elements, values unescaped: ours into a stack
//!                 buffer, one by one; theirs into their maps.
//!   parse_bad     64 damaged lines all three refuse: a bad PRI, a bad date, an
//!                 unclosed SD. Count = refused.
//!   parse_3164    `<PRI>Mmm dd hh:mm:ss host tag[pid]: msg`. Ours `parseBsd`; ref
//!                 go-syslog `rfc3164`; alt Rust `syslog_loose` 0.23.0.
//!   parse_loose   INFO: the `parse_5424_sd` corpus against `syslog_loose` (nom),
//!                 the lenient parser Vector uses, on its RFC 5424 path.
//!
//! Count = the sum over messages of the field lengths read and the timestamp's
//! seconds, so a side that skipped work would not match (encoder rows: messages).
//! Ratios are ours/theirs by wall time, best of rounds, sides alternating.

const std = @import("std");
const bench = @import("testkit").bench;
const syslog = @import("syslog");
const linux = std.os.linux;

const ref_card = "Go `log/syslog` 1.26 + go-syslog v4.6.0";
const fast_card = "Rust `syslog` 7.0.0, `syslog_rfc5424` 0.10.0, `syslog_loose` 0.23.0";
const bench_name = "bench-syslog";
const work_dir = ".zig-cache/bench-syslog";
const go_dir = "modules/syslog/tools/go_bench";
const rust_manifest = "modules/syslog/tools/rust_bench/Cargo.toml";
const rust_exe = "modules/syslog/tools/rust_bench/target/release/rust_bench";
const N = 64;

const Op = enum { fmt_5424, fmt_5424_sd, fmt_3164, send_unix, parse_5424, parse_5424_sd, parse_bad, parse_3164 };

const host = "web-1.example.org";
const app = "api-gateway";
const pid = "4242";

const Ctx = struct {
    op: Op = .fmt_5424,
    texts: [N][]const u8 = undefined,
    msgids: [N][]const u8 = undefined,
    event_ids: [N][]const u8 = undefined,
    min: [N][]const u8 = undefined,
    sd: [N][]const u8 = undefined,
    bad: [N][]const u8 = undefined,
    bsd: [N][]const u8 = undefined,
    emitter: *syslog.UnixEmitter = undefined,
};

fn sdOf(c: *const Ctx, i: usize, params: *[3]syslog.SdParam, els: *[1]syslog.SdElement) []const syslog.SdElement {
    params.* = .{
        .{ .name = "iut", .value = "3" },
        .{ .name = "eventSource", .value = "App\"lica]tion\\x" },
        .{ .name = "eventID", .value = c.event_ids[i] },
    };
    els.* = .{.{ .id = "exampleSDID@32473", .params = params }};
    return els;
}

fn sumFields(m: *const syslog.Parsed) u64 {
    var t: u64 = 0;
    if (m.hostname) |h| t += h.len;
    if (m.app_name) |h| t += h.len;
    if (m.procid) |h| t += h.len;
    if (m.msgid) |h| t += h.len;
    t += m.msg.len;
    if (m.timestamp) |ts| t +%= @as(u64, @bitCast(@divFloor(ts.unix_us, 1_000_000)));
    var buf: [1024]u8 = undefined;
    var els = m.elements();
    while (els.next()) |el| {
        t += el.id.len;
        var ps = el.params();
        while (ps.next()) |p| {
            t += p.name.len;
            const v = p.value(&buf) catch @panic("bench-syslog: value");
            t += v.len;
        }
    }
    return t;
}

fn once(c: *Ctx) u64 {
    var t: u64 = 0;
    var buf: [2048]u8 = undefined;
    switch (c.op) {
        .fmt_5424, .fmt_5424_sd => for (c.texts, 0..) |text, i| {
            var params: [3]syslog.SdParam = undefined;
            var els: [1]syslog.SdElement = undefined;
            const m: syslog.Message = .{
                .facility = .user,
                .severity = .info,
                .timestamp = syslog.nowTimestamp(),
                .hostname = host,
                .app_name = app,
                .procid = pid,
                .msgid = c.msgids[i],
                .structured_data = if (c.op == .fmt_5424_sd) sdOf(c, i, &params, &els) else &.{},
                .msg = text,
            };
            const line = syslog.bufPrint(&m, &buf) catch @panic("bench-syslog: fmt");
            std.mem.doNotOptimizeAway(line.ptr);
            t += 1;
        },
        .fmt_3164 => for (c.texts) |text| {
            const m: syslog.bsd.Message = .{
                .facility = .user,
                .severity = .info,
                .timestamp = syslog.nowTimestamp(),
                .hostname = host,
                .tag = app,
                .pid = pid,
                .msg = text,
            };
            const line = syslog.bsd.bufPrint(&m, &buf) catch @panic("bench-syslog: fmt");
            std.mem.doNotOptimizeAway(line.ptr);
            t += 1;
        },
        .send_unix => for (c.texts) |text| {
            const m: syslog.bsd.Message = .{
                .facility = .user,
                .severity = .info,
                .timestamp = syslog.nowTimestamp(),
                .tag = app,
                .pid = pid,
                .msg = text,
            };
            c.emitter.sendBsd(&m) catch @panic("bench-syslog: send");
            t += 1;
        },
        .parse_5424 => for (c.min) |l| {
            const m = syslog.parse(l) catch @panic("bench-syslog: parse");
            t +%= sumFields(&m);
        },
        .parse_5424_sd => for (c.sd) |l| {
            const m = syslog.parse(l) catch @panic("bench-syslog: parse");
            t +%= sumFields(&m);
        },
        .parse_bad => for (c.bad) |l| {
            if (syslog.parse(l)) |_| @panic("bench-syslog: accepted") else |_| t += 1;
        },
        .parse_3164 => for (c.bsd) |l| {
            const m = syslog.parseBsd(l);
            if (m.hostname) |h| t += h.len;
            if (m.tag) |h| t += h.len;
            if (m.pid) |h| t += h.len;
            t += m.msg.len;
        },
    }
    return t;
}

// ── the corpus ───────────────────────────────────────────────────────────────

const words = [_][]const u8{ "served", "request", "upstream", "timeout", "retry", "connection", "closed", "by", "peer", "cache", "miss", "200", "503", "after", "ms", "client", "shard", "rebalance", "queue", "depth" };

fn makeText(arena: std.mem.Allocator, r: std.Random) ![]const u8 {
    const want = r.intRangeAtMost(usize, 60, 140);
    var out: std.ArrayList(u8) = .empty;
    while (out.items.len < want) {
        if (out.items.len > 0) try out.append(arena, ' ');
        try out.appendSlice(arena, words[r.uintLessThan(usize, words.len)]);
    }
    return out.items;
}

fn writeLines(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, file: []const u8, lines: *const [N][]const u8) !void {
    var out: std.ArrayList(u8) = .empty;
    var total: usize = 0;
    for (lines) |m| {
        try out.appendSlice(arena, &.{ @truncate(m.len >> 8), @truncate(m.len) });
        try out.appendSlice(arena, m);
        total += m.len;
    }
    try dir.writeFile(io, .{ .sub_path = file, .data = out.items });
    std.debug.print("{s}: {s}: {d} lines, {d} bytes ({d} avg)\n", .{ bench_name, file, N, total, total / N });
}

fn setup(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, c: *Ctx) !void {
    var prng = std.Random.DefaultPrng.init(0x5159_106c);
    const r = prng.random();
    const stamp: syslog.Timestamp = .{ .unix_ms = 1783600496123, .offset_minutes = 60 };
    for (0..N) |i| {
        c.texts[i] = try makeText(arena, r);
        c.msgids[i] = try arena.print("{d}", .{1000 + i});
        c.event_ids[i] = try arena.print("{d}", .{5000 + i});
        var buf: [2048]u8 = undefined;
        const m: syslog.Message = .{ .facility = .local3, .severity = .warning, .timestamp = stamp, .hostname = host, .app_name = app, .procid = pid, .msgid = c.msgids[i], .msg = c.texts[i] };
        c.min[i] = try arena.dupe(u8, try syslog.bufPrint(&m, &buf));

        const params = [_]syslog.SdParam{
            .{ .name = "iut", .value = "3" },
            .{ .name = "eventSource", .value = "App\"lica]tion\\x" },
            .{ .name = "eventID", .value = c.event_ids[i] },
        };
        const params2 = [_]syslog.SdParam{.{ .name = "class", .value = "high" }};
        const els = [_]syslog.SdElement{ .{ .id = "exampleSDID@32473", .params = &params }, .{ .id = "examplePriority@32473", .params = &params2 } };
        var with = m;
        with.structured_data = &els;
        c.sd[i] = try arena.dupe(u8, try syslog.bufPrint(&with, &buf));

        // Three kinds of damage, each an error for every side.
        c.bad[i] = switch (i % 3) {
            0 => try arena.print("<{d}>{s}", .{ 200 + i, c.min[i][std.mem.findScalar(u8, c.min[i], '>').? + 1 ..] }),
            1 => try std.mem.replaceOwned(u8, arena, c.min[i], "2026-07-09", "2026-13-09"),
            else => try arena.dupe(u8, c.sd[i][0 .. std.mem.findScalar(u8, c.sd[i], ']').? - 1]),
        };

        const b: syslog.bsd.Message = .{ .facility = .local3, .severity = .warning, .timestamp = stamp, .hostname = host, .tag = app, .pid = pid, .msg = c.texts[i] };
        c.bsd[i] = try arena.dupe(u8, try syslog.bsd.bufPrint(&b, &buf));
        // Rust's `syslog_loose` and go-syslog read a TAG of letters, digits and `-`.
    }
    try writeLines(arena, io, dir, "texts.bin", &c.texts);
    try writeLines(arena, io, dir, "parse_5424.bin", &c.min);
    try writeLines(arena, io, dir, "parse_5424_sd.bin", &c.sd);
    try writeLines(arena, io, dir, "parse_bad.bin", &c.bad);
    try writeLines(arena, io, dir, "parse_3164.bin", &c.bsd);
}

// ── the drain of send_unix ───────────────────────────────────────────────────

fn drain(fd: linux.fd_t) void {
    var b: [4096]u8 = undefined;
    while (true) {
        const rc = linux.recvfrom(fd, &b, b.len, 0, null, null);
        if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .INTR) return;
    }
}

fn bindDrain(path: []const u8) !linux.fd_t {
    var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = @splat(0) };
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: linux.fd_t = @intCast(rc);
    if (linux.errno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un))) != .SUCCESS) return error.BindFailed;
    return fd;
}

// ── main ─────────────────────────────────────────────────────────────────────

fn cargoBuild(arena: std.mem.Allocator, io: std.Io) !void {
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    const res = try std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--offline", "--locked", "--manifest-path", rust_manifest },
    });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: cargo build failed:\n{s}\n", .{ bench_name, res.stderr });
        return error.CargoBuildFailed;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;

    var ctx: Ctx = .{};
    try setup(arena, io, dir, &ctx);

    // Relative: a work directory under a deep worktree does not fit sun_path.
    const sock = work_dir ++ "/ours.sock";
    dir.deleteFile(io, "ours.sock") catch {};
    const drain_fd = try bindDrain(sock);
    const drainer = try std.Thread.spawn(.{}, drain, .{drain_fd});
    drainer.detach();
    var emitter = try syslog.UnixEmitter.open(sock);
    defer emitter.close();
    ctx.emitter = &emitter;

    try cargoBuild(arena, io);
    const rust = try cwd.realPathFileAlloc(io, rust_exe, arena);
    const go = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });

    const W = bench.Work(Op);
    const rust_i = 0;
    const go_i = 1;
    const ws = [_]W{
        .{ .name = "fmt_5424", .op = .fmt_5424, .ref = "fmt_5424", .ref_exe = go_i, .alt = "fmt_5424", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "fmt_5424_sd", .op = .fmt_5424_sd, .ref = "fmt_5424_sd", .ref_exe = go_i, .alt = "fmt_5424_sd", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "fmt_3164", .op = .fmt_3164, .ref = "fmt_3164", .ref_exe = rust_i, .fast_only = true, .wall_only = true },
        .{ .name = "send_unix", .op = .send_unix, .ref = "send_unix", .ref_exe = go_i, .alt = "send_unix", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "parse_5424", .op = .parse_5424, .ref = "parse_5424", .ref_exe = go_i, .alt = "parse_5424", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "parse_5424_sd", .op = .parse_5424_sd, .ref = "parse_5424_sd", .ref_exe = go_i, .alt = "parse_5424_sd", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "parse_bad", .op = .parse_bad, .ref = "parse_bad", .ref_exe = go_i, .alt = "parse_bad", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "parse_3164", .op = .parse_3164, .ref = "parse_3164", .ref_exe = go_i, .alt = "parse_3164", .alt_exe = rust_i, .wall_only = true },
        .{ .name = "parse_loose", .op = .parse_5424_sd, .ref = "parse_loose", .ref_exe = rust_i, .info = true, .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{ rust, go },
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, &ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\nworst ours/ref = {d:.2} (best {d:.2})\n", .{ s.worst_ref, s.best_ref });
    if (args.len <= 1) try w.print("card: **Performance:** ref {d:.2}–{d:.2}× {s} · fastest {d:.2}× {s} (measured <today>)\n", .{ s.best_ref, s.worst_ref, ref_card, s.worst_fast orelse 0, fast_card });
    try w.flush();
    return 0;
}
