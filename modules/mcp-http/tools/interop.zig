// SPDX-License-Identifier: MIT

//! Differential oracle for `mcp-http`: the official MCP Python SDK's
//! Streamable HTTP client (run as a black box, its source not read -- the
//! SDKs are mid-relicensing, see SPEC "Compared with") against this module
//! over a real socket.
//!
//!  - this program serves `tools/sdk_oracle/catalog.zig` through `mcp-http`
//!    (sessions, held listens) on an `http.Server` on 127.0.0.1, records every
//!    exchange the SDK makes (request method, target, MCP headers and body;
//!    response status, content type and body), and runs
//!  - `tools/sdk_oracle/drive.py PORT WORKDIR`, which drives it with the SDK's
//!    `streamable_http_client` + `ClientSession`, once per protocol era
//!    (2026-07-28 stateless with `server/discover`, and the session era with
//!    `initialize`), and checks every typed answer -- including a held
//!    `subscriptions/listen` that receives a pushed notification and ends with
//!    the graceful close, and a cancelled `tools/call`.
//!
//! Only when every check passes are the recorded exchanges written as
//! `src/sdk_oracle_vectors.zig`, which `src/sdk_oracle.zig` replays through
//! `Transport` with no Python at test time.
//!
//! THIS IS A PROGRAM, NOT A TEST (CONVENTIONS §9). Recipe:
//!
//!   V=~/.local/share/zig-libs/oracle-venvs/mcp
//!   python3 -m venv $V && $V/bin/pip install mcp==2.3.0
//!   zig build interop-mcp-http              # re-take, rewrite the transcript
//!   zig build interop-mcp-http -- --check   # re-take, compare with the committed one
//!
//! `MCP_ORACLE_VENV` overrides the venv path.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const mcp = @import("mcp");
const mcphttp = @import("mcp-http");
const catalog = @import("sdk_oracle/catalog.zig");

const script = "modules/mcp-http/tools/sdk_oracle/drive.py";
const work_dir = ".zig-cache/sdk-oracle-http";
const out_path = "modules/mcp-http/src/sdk_oracle_vectors.zig";

/// The request headers the transport reads; the rest (httpx's own) is not
/// recorded.
const recorded_headers = [_][]const u8{ "accept", "mcp-protocol-version", "mcp-method", "mcp-name", "mcp-session-id", "last-event-id" };

const Exchange = struct {
    method: []const u8,
    target: []const u8,
    headers: []const u8,
    body: []const u8,
    status: u16 = 0,
    content_type: []const u8 = "",
    minted_sid: []const u8 = "",
    response: std.ArrayList(u8) = .empty,
    done: bool = false,
};

const Recorder = struct {
    gpa: std.mem.Allocator,
    mu: std.atomic.Mutex = .unlocked,
    list: std.ArrayList(*Exchange) = .empty,

    fn lock(r: *Recorder) void {
        while (!r.mu.tryLock()) std.atomic.spinLoopHint();
    }

    fn middleware(r: *Recorder) router.Middleware {
        return .{ .state = r, .run = run };
    }

    fn observe(ctx: *anyopaque, bytes: []const u8) void {
        const ex: *Exchange = @ptrCast(@alignCast(ctx));
        ex.response.appendSlice(std.heap.page_allocator, bytes) catch {};
    }

    fn run(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const r: *Recorder = @ptrCast(@alignCast(state.?));
        const a = std.heap.page_allocator; // freed with the process
        const ex = try a.create(Exchange);
        var hb: std.Io.Writer.Allocating = .init(a);
        for (recorded_headers) |name| {
            var it = ctx.req.headerAll(name);
            while (it.next()) |v| try hb.writer.print("{s}: {s}\r\n", .{ name, v });
        }
        const body = try ctx.req.reader().allocRemaining(a, .limited(8 << 20));
        ex.* = .{
            .method = try a.dupe(u8, ctx.req.methodName()),
            .target = try a.dupe(u8, ctx.req.target),
            .headers = hb.written(),
            .body = body,
        };
        r.lock();
        try r.list.append(r.gpa, ex);
        r.mu.unlock();
        var fr: std.Io.Reader = .fixed(body);
        ctx.req.decoded = &fr;
        const tap: http.Server.ResponseWriter.BodyTap = .{ .ctx = ex, .observe = observe };
        ctx.res.body_tap = &tap;
        defer ctx.res.body_tap = null;
        try next.run(ctx);
        try ex.response.appendSlice(a, ctx.res.bufferedBody());
        ex.status = ctx.res.status;
        ex.content_type = try a.dupe(u8, ctx.res.getHeader("Content-Type") orelse "");
        ex.minted_sid = try a.dupe(u8, ctx.res.getHeader("Mcp-Session-Id") orelse "");
        ex.done = true;
    }
};

const LiveCtx = struct {
    transport: *mcphttp.Transport,
    listens: *mcphttp.Listens,
    server: *mcp.Server,

    fn touch(ctx: ?*anyopaque) usize {
        const l: *LiveCtx = @ptrCast(@alignCast(ctx.?));
        // Runs inside a tool, so under the transport lock already.
        return l.server.notifyListChanged(l.transport.pushSink(), .tools);
    }

    fn finish(ctx: ?*anyopaque) void {
        const l: *LiveCtx = @ptrCast(@alignCast(ctx.?));
        l.listens.finishAll();
    }
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

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    const gpa = da.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next();
    var check = false;
    if (args.next()) |a| {
        if (!std.mem.eql(u8, a, "--check")) {
            std.debug.print("usage: interop-mcp-http [--check]\n", .{});
            return 2;
        }
        check = true;
    }
    const env = try init.environ.createMap(arena);
    const venv = env.get("MCP_ORACLE_VENV") orelse blk: {
        const home = env.get("HOME") orelse {
            std.debug.print("interop-mcp-http: neither MCP_ORACLE_VENV nor HOME is set\n", .{});
            return 1;
        };
        break :blk try std.fmt.allocPrint(arena, "{s}/.local/share/zig-libs/oracle-venvs/mcp", .{home});
    };
    const python = try std.fmt.allocPrint(arena, "{s}/bin/python", .{venv});

    var server = mcp.Server.init(gpa, catalog.info);
    defer server.deinit();
    server.push = true;
    var sessions = mcphttp.Sessions.init(gpa);
    defer sessions.deinit();
    var listens = mcphttp.Listens.init(gpa);
    defer listens.deinit();
    var spin: SpinLock = .{};
    var transport: mcphttp.Transport = .{
        .gpa = gpa,
        .server = &server,
        .sessions = &sessions,
        .listens = &listens,
        .lock = .{ .ctx = &spin, .lockFn = SpinLock.lock, .unlockFn = SpinLock.unlock },
    };
    var live_ctx: LiveCtx = .{ .transport = &transport, .listens = &listens, .server = &server };
    var live: catalog.Live = .{ .touch = LiveCtx.touch, .finish = LiveCtx.finish, .ctx = &live_ctx };
    try catalog.register(&server, &live);

    var rec: Recorder = .{ .gpa = gpa };
    defer rec.list.deinit(gpa);
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(rec.middleware());
    try r.use(transport.middleware());

    var hs = http.Server.init(io, gpa, .{ .handler = r.handler(), .context = &r, .server_name = null, .emit_date = false });
    try hs.bind();
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&hs});
    const port = hs.boundAddress().getPort();

    std.Io.Dir.cwd().createDirPath(io, work_dir) catch {};
    var port_buf: [8]u8 = undefined;
    const port_s = try std.mem.print(&port_buf, "{d}", .{port});
    std.debug.print("interop-mcp-http: MCP Python SDK ({s}) against 127.0.0.1:{d} ...\n", .{ venv, port });
    var ok = false;
    if (std.process.spawn(io, .{ .argv = &.{ python, script, port_s, work_dir }, .stdin = .close })) |child_v| {
        var child = child_v;
        ok = switch (try child.wait(io)) {
            .exited => |code| code == 0,
            else => false,
        };
    } else |e| std.debug.print("interop-mcp-http: could not run {s} ({t}) -- the oracle needs the venv\n", .{ python, e });

    hs.shutdownGraceful(2000) catch {};
    hs.shutdown();
    thread.join();
    hs.deinit();
    if (!ok) {
        std.debug.print("interop-mcp-http: SDK oracle FAILED\n", .{});
        return 1;
    }

    const version = std.Io.Dir.cwd().readFileAlloc(io, work_dir ++ "/sdk-version", arena, .limited(64)) catch "unknown";
    var aw: std.Io.Writer.Allocating = .init(arena);
    const w = &aw.writer;
    try w.print("// SPDX-License-Identifier: MIT\n// GENERATED by modules/mcp-http/tools/interop.zig (MCP Python SDK {s}) -- do not hand-edit.\n", .{std.mem.trim(u8, version, " \n")});
    try w.writeAll("//! Every HTTP exchange the official MCP Python SDK's Streamable HTTP client made with this\n" ++
        "//! module's `Transport` (both eras), after the SDK's typed client accepted every answer and\n" ++
        "//! `tools/sdk_oracle/drive.py`'s checks passed. Replayed by `sdk_oracle.zig`.\n\n");
    try w.print("pub const sdk_version = \"{s}\";\n\n", .{std.mem.trim(u8, version, " \n")});
    try w.writeAll("pub const Exchange = struct { method: []const u8, target: []const u8, headers: []const u8, body: []const u8, status: u16, content_type: []const u8, minted_sid: []const u8, response: []const u8 };\n\n");
    try w.writeAll("pub const exchanges = [_]Exchange{\n");
    for (rec.list.items) |ex| {
        if (!ex.done) continue;
        try w.writeAll("    .{ .method = ");
        try zstr(w, ex.method);
        try w.writeAll(", .target = ");
        try zstr(w, ex.target);
        try w.writeAll(", .headers = ");
        try zstr(w, ex.headers);
        try w.writeAll(", .body = ");
        try zstr(w, ex.body);
        try w.print(", .status = {d}, .content_type = ", .{ex.status});
        try zstr(w, ex.content_type);
        try w.writeAll(", .minted_sid = ");
        try zstr(w, ex.minted_sid);
        try w.writeAll(", .response = ");
        try zstr(w, ex.response.items);
        try w.writeAll(" },\n");
    }
    try w.writeAll("};\n");
    const text = aw.written();
    if (check) {
        const old = std.Io.Dir.cwd().readFileAlloc(io, out_path, arena, .limited(16 << 20)) catch "";
        if (!transcriptEqual(old, text)) {
            std.debug.print("interop-mcp-http: {s} is stale: the SDK or the transport moved -- re-take and read the diff\n", .{out_path});
            return 1;
        }
        std.debug.print("interop-mcp-http: SDK oracle fresh\n", .{});
        return 0;
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = text });
    std.debug.print("interop-mcp-http: SDK oracle re-taken ({d} exchanges)\n", .{rec.list.items.len});
    return 0;
}

/// Session ids are random: two takes agree when they agree with every
/// 32-hex-digit run masked.
fn transcriptEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] == b[i]) continue;
        if (!std.ascii.isHex(a[i]) or !std.ascii.isHex(b[i])) return false;
    }
    return true;
}

fn zstr(w: *std.Io.Writer, bytes: []const u8) !void {
    try w.writeByte('"');
    for (bytes) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        0x20...0x21, 0x23...0x5b, 0x5d...0x7e => try w.writeByte(c),
        else => try w.print("\\x{x:0>2}", .{c}),
    };
    try w.writeByte('"');
}
