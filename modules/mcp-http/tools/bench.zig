// SPDX-License-Identifier: MIT

//! Comparative benchmark: `mcp-http` (Streamable HTTP over this repository's
//! `http.Server`, `router` and `mcp`) against the official MCP SDKs' HTTP
//! servers, the program behind the `**Performance:**` line of the maturity
//! card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-mcp-http` runs it (always
//! ReleaseFast); `zig build install-bench-mcp-http` builds it into
//! zig-out/bench/ for a run inside the bench shield. Run from the repository
//! root. Needs go 1.26 with github.com/modelcontextprotocol/go-sdk v1.8.0 in the
//! module cache (`tools/http_bench/go`, `GOPROXY=off`) and the oracle venv
//! with mcp 2.3.0 and uvicorn (`MCP_ORACLE_VENV`, default
//! ~/.local/share/zig-libs/oracle-venvs/mcp; `BENCH_PY=0` skips it).
//!
//! Subjects, each on its own 127.0.0.1 port, all stateless with JSON
//! responses over the same catalog (tool `echo` with typed input and output
//! schemas, 20 small tools):
//!   ours       `mcp-http` `Transport` (`.stream = .off`) in this process, on a
//!              threaded `http.Server`, `mcp.Server` behind a spin lock;
//!   python     the official Python SDK 2.3.0 — **the reference** —
//!              `MCPServer.streamable_http_app(stateless_http=True,
//!              json_response=True)` under uvicorn (`tools/http_bench/py_server.py`);
//!   go         the official Go SDK v1.8.0, `NewStreamableHTTPHandler` with
//!              `Stateless` and `JSONResponse` (`tools/http_bench/go`).
//! One load generator for all three, the Go program's `client` mode:
//! keep-alive connections POST session-era (2025-11-25) requests, every
//! response must be 200 with the workload's marker, ns per request by wall
//! time. Workloads × connections: `tools_call_echo` and `tools_list_20`, at 1
//! and 4 connections. Each subject is warmed, then the subjects alternate for
//! BENCH_ROUNDS rounds (default 3), each keeping its best; BENCH_N requests per
//! run (default 20000; the Python server gets a fifth of that, its rate is
//! two orders lower). Ratios are ours / theirs; the verdict is the worst row.

const std = @import("std");
const benchkit = @import("benchkit");
const mcp = @import("mcp");
const mcphttp = @import("mcp-http");
const http = @import("http");
const router = @import("router");

const bench_name = "bench-mcp-http";

const EchoIn = struct { text: []const u8 };
const EchoOut = struct { echo: []const u8 };

fn echo(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    const in = call.argsAs(EchoIn) catch return call.fail("bad arguments");
    call.writeJson(EchoOut{ .echo = in.text });
    return false;
}

fn noop(_: ?*anyopaque, call: *mcp.ToolCall) bool {
    call.write("ok");
    return false;
}

const small_schema = "{\"type\":\"object\",\"properties\":{\"a\":{\"type\":\"string\"},\"b\":{\"type\":\"integer\"}},\"required\":[\"a\"]}";

const tool_names = blk: {
    var names: [20][]const u8 = undefined;
    for (&names, 0..) |*n, i| n.* = std.fmt.comptimePrint("tool_{d:0>2}", .{i});
    break :blk names;
};
const tool_descriptions = blk: {
    var d: [20][]const u8 = undefined;
    for (&d, 0..) |*n, i| n.* = std.fmt.comptimePrint("Small tool number {d}", .{i});
    break :blk d;
};

const SpinLock = struct {
    m: std.atomic.Mutex = .unlocked,
    fn lock(ctx: ?*anyopaque) void {
        const self: *SpinLock = @ptrCast(@alignCast(ctx.?));
        while (!self.m.tryLock()) std.atomic.spinLoopHint();
    }
    fn unlock(ctx: ?*anyopaque) void {
        const self: *SpinLock = @ptrCast(@alignCast(ctx.?));
        self.m.unlock();
    }
};

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

const workloads = [_][]const u8{ "tools_call_echo", "tools_list_20" };
const conns = [_][]const u8{ "1", "4" };
const subjects = [_][]const u8{ "ours", "python", "go" };

fn envInt(env: *const std.process.Environ.Map, name: []const u8, default: usize) usize {
    const v = env.get(name) orelse return default;
    return std.fmt.parseInt(usize, v, 10) catch default;
}

/// Wait until something accepts on 127.0.0.1:`port` (a child server starting).
fn waitListening(io: std.Io, port: u16) !void {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    var tries: usize = 0;
    while (tries < 200) : (tries += 1) {
        if (addr.connect(io, .{ .mode = .stream })) |s| {
            s.close(io);
            return;
        } else |_| try io.sleep(.fromMilliseconds(50), .awake);
    }
    return error.ServerDidNotStart;
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const env = init.environ_map;
    const rounds = envInt(env, "BENCH_ROUNDS", 3);
    const n_req = envInt(env, "BENCH_N", 20000);
    const want_py = !std.mem.eql(u8, env.get("BENCH_PY") orelse "1", "0");
    const port_base: u16 = @intCast(envInt(env, "BENCH_PORT_BASE", 18740) & 0xfff0);

    // ── ours, in process ────────────────────────────────────────────────
    var server = mcp.Server.init(gpa, .{ .name = "bench", .version = "1.0.0" });
    defer server.deinit();
    try server.addTool(.{ .name = "echo", .description = "Echo the text back", .input_schema = mcp.schemaOf(EchoIn), .output_schema = mcp.schemaOf(EchoOut), .handler = echo });
    for (tool_names, tool_descriptions) |nm, d| try server.addTool(.{ .name = nm, .description = d, .input_schema = small_schema, .handler = noop });
    var spin: SpinLock = .{};
    var transport: mcphttp.Transport = .{ .gpa = gpa, .server = &server, .stream = .off, .lock = .{ .ctx = &spin, .lockFn = SpinLock.lock, .unlockFn = SpinLock.unlock } };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());
    var hs = http.Server.init(io, gpa, .{ .handler = r.handler(), .context = &r, .server_name = null, .emit_date = false, .port = port_base });
    try hs.bind();
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&hs});
    defer {
        hs.shutdown();
        thread.join();
        hs.deinit();
    }

    // ── the foreign servers ─────────────────────────────────────────────
    const cwd = try std.process.currentPathAlloc(io, arena);
    const work = try arena.print("{s}/.zig-cache/bench-mcp-http", .{cwd});
    std.Io.Dir.cwd().createDirPath(io, work) catch {};
    const go_exe = try benchkit.goBuild(arena, io, bench_name, env, .{ .exe = "go", .dir = "modules/mcp-http/tools/http_bench/go", .abs = work, .out = "http_bench" });
    const ports: [subjects.len]u16 = .{ port_base, port_base + 2, port_base + 1 };
    var go_port_buf: [8]u8 = undefined;
    var go_child = try std.process.spawn(io, .{ .argv = &.{ go_exe, "server", try std.mem.print(&go_port_buf, "{d}", .{ports[2]}) }, .stdin = .close, .stdout = .ignore });
    defer go_child.kill(io);
    try waitListening(io, ports[2]);

    var py_child: ?std.process.Child = null;
    defer if (py_child) |*c| c.kill(io);
    var py_banner: []const u8 = "skipped (BENCH_PY=0)";
    if (want_py) {
        const venv = env.get("MCP_ORACLE_VENV") orelse try arena.print("{s}/.local/share/zig-libs/oracle-venvs/mcp", .{env.get("HOME") orelse ""});
        const python = try arena.print("{s}/bin/python", .{venv});
        var py_port_buf: [8]u8 = undefined;
        py_child = try std.process.spawn(io, .{ .argv = &.{ python, "-I", "modules/mcp-http/tools/http_bench/py_server.py", try std.mem.print(&py_port_buf, "{d}", .{ports[1]}) }, .stdin = .close, .stdout = .ignore });
        try waitListening(io, ports[1]);
        py_banner = "the official MCP Python SDK 2.3.0 (uvicorn)";
    }

    // ── measure ─────────────────────────────────────────────────────────
    var best: [workloads.len][conns.len][subjects.len]f64 = @splat(@splat(@splat(std.math.inf(f64))));
    for (0..rounds + 1) |round| { // round 0 warms every subject up and is not kept
        for (workloads, 0..) |wl, wi| for (conns, 0..) |cn, ci| for (subjects, 0..) |subj, si| {
            if (si == 1 and !want_py) continue;
            const n = if (round == 0) @max(n_req / 20, 200) else if (si == 1) @max(n_req / 5, 200) else n_req;
            var url_buf: [64]u8 = undefined;
            var n_buf: [16]u8 = undefined;
            const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/mcp", .{ports[si]});
            const row = benchkit.foreignArgv(arena, io, bench_name, &.{ go_exe, "client", url, wl, cn, try std.mem.print(&n_buf, "{d}", .{n}) }, wl, null) catch |e| {
                std.debug.print("{s}: {s} {s} x{s} failed: {t}\n", .{ bench_name, subj, wl, cn, e });
                return 1;
            };
            if (round != 0) best[wi][ci][si] = @min(best[wi][ci][si], row.ns);
        };
    }

    // ── report ──────────────────────────────────────────────────────────
    var out_buf: [4096]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &out_buf);
    const w = &fw.interface;
    try w.print("{s}: python = {s}; go = the official MCP Go SDK v1.8.0; {d} rounds, best ns/request\n", .{ bench_name, py_banner, rounds });
    try w.print("{s:<16} {s:>5} {s:>10} {s:>10} {s:>10} {s:>12} {s:>10}\n", .{ "workload", "conns", "ours", "python", "go", "ours/python", "ours/go" });
    var worst_py: f64 = 0;
    var worst_go: f64 = 0;
    for (workloads, 0..) |wl, wi| for (conns, 0..) |cn, ci| {
        const b = best[wi][ci];
        const rp = b[0] / b[1];
        const rg = b[0] / b[2];
        if (want_py) worst_py = @max(worst_py, rp);
        worst_go = @max(worst_go, rg);
        try w.print("{s:<16} {s:>5} {d:>10.0} {d:>10.0} {d:>10.0} {d:>12.3} {d:>10.3}\n", .{ wl, cn, b[0], b[1], b[2], rp, rg });
    };
    if (want_py) try w.print("verdict: ref (python) worst {d:.3}x", .{worst_py}) else try w.writeAll("verdict: ref (python) not measured");
    try w.print(", go worst {d:.3}x\n", .{worst_go});
    try w.flush();
    return 0;
}
