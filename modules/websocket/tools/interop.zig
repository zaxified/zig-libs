// SPDX-License-Identifier: MIT

//! Live oracle for `websocket`: two independent Go implementations --
//! github.com/coder/websocket v1.8.15 (the scope reference) and
//! github.com/gorilla/websocket v1.5.3 -- as real peers over loopback, through
//! their public APIs (`tools/go_oracle`), against this module's client and
//! server.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-websocket` runs it and
//! `zig build check-interop` compiles it. Needs `go` on PATH with the two
//! modules in the module cache (`GOPROXY=off`, pinned by `go_oracle/go.mod`
//! and `go.sum`) and loopback networking. Run from the repository root.
//!
//!   zig build interop-websocket             # judge and compare; exit 1 on any surprise
//!   zig build interop-websocket -- deflate  # only the rows whose id contains "deflate"
//!   zig build interop-websocket -- --capture  # also rewrite src/testdata/interop/
//!
//! Three families:
//!
//! - `client`: this module's client (`handshake` + `conn.Conn`) against the
//!   coder and gorilla servers. The judge is the server library's own client
//!   on the same server and scenario: both clients' results must match, and
//!   so must what the server recorded about each connection (close code it
//!   saw, messages echoed, subprotocol, permessage-deflate).
//! - `server`: the coder and gorilla clients against this module's server
//!   (`http.Server` + `handshake.respondUpgraded` + `conn.Conn`, the way qap
//!   serves it). The judge is the same Go client against its own library's
//!   server: same client line, same server record.
//! - `raw`: fixed handshake and frame bytes (valid traffic, every class of
//!   protocol violation, handshake defects) sent to all three servers; each
//!   server's reaction (101 or not, messages echoed, the close code) is
//!   compared with this module's server's. `stricter` rows (the peer accepts
//!   what RFC 6455 says to refuse, this module refuses) are the card's
//!   `**Ahead:**` rows; `differs` rows are a documented, deliberate
//!   difference (the row's `why`). Everything else must agree.
//!
//! Scenarios (client/server families; `go_oracle/main.go` has the Go side):
//! `echo` (the message suite: every length-form boundary 0..1 MiB, text and
//! binary, multi-byte UTF-8), `deflate` (the same with permessage-deflate),
//! `frag`/`frag-deflate` (a 4 KiB text message sent in fragments each way,
//! compressed or not), `sping` (the server pings, the client's automatic
//! pong is awaited), `ping` (the client pings), `close` (the client closes
//! with 4001), `servclose` (the server closes with 4002 "zl-bye"), `subproto`
//! (chat and echo offered).
//!
//! Every verdict goes to `.zig-cache/interop-websocket/verdicts.tsv`; stdout
//! gets the surprises and a summary per family.
//!
//! `--capture` also keeps every byte the Go libraries sent after the
//! handshake in the scenarios without 1 MiB of plain payload (`captured`):
//! their servers' frames to this client, their clients' masked frames to
//! this server -- compressed by their flate, fragmented their way, with
//! their pings and closes -- as `src/testdata/interop/<row id>.bin`, which
//! `src/interop_replay_test.zig` feeds back through `conn.Conn` with no peer.

const std = @import("std");
const websocket = @import("websocket");
const http = @import("http");
const handshake = websocket.handshake;
const frame = websocket.frame;
const deflate = websocket.deflate;
const Conn = websocket.conn.Conn;

const work_dir = ".zig-cache/interop-websocket";
const go_dir = "modules/websocket/tools/go_oracle";
const frag_len = 4096;
const capture_dir = "modules/websocket/src/testdata/interop";
/// The scenarios `--capture` keeps (each also names its `/path`).
const captured = [_][]const u8{ "deflate", "frag", "frag-deflate", "sping", "ping", "close", "servclose" };

fn isCaptured(scenario: []const u8) bool {
    for (captured) |c| if (std.mem.eql(u8, c, scenario)) return true;
    return false;
}

/// A reader that hands `inner`'s bytes on and keeps a copy of each
/// (`--capture`).
const Tap = struct {
    inner: *std.Io.Reader,
    gpa: std.mem.Allocator,
    log: std.ArrayList(u8) = .empty,
    reader: std.Io.Reader,

    fn init(inner: *std.Io.Reader, gpa: std.mem.Allocator, buf: []u8) Tap {
        return .{ .inner = inner, .gpa = gpa, .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buf, .seek = 0, .end = 0 } };
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const t: *Tap = @alignCast(@fieldParentPtr("reader", r));
        // What one read of `inner` brings, not a full slice: a socket
        // would wait for bytes the peer never sends.
        while (t.inner.bufferedLen() == 0) try t.inner.fillMore();
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = @min(dest.len, t.inner.bufferedLen());
        @memcpy(dest[0..n], t.inner.buffered()[0..n]);
        t.inner.toss(n);
        t.log.appendSlice(t.gpa, dest[0..n]) catch return error.ReadFailed;
        w.advance(n);
        return n;
    }

    fn save(t: *const Tap, io: std.Io, id: []const u8) void {
        var name: [128]u8 = undefined;
        const path = std.mem.print(&name, "{s}/{s}.bin", .{ capture_dir, id }) catch return;
        std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = t.log.items }) catch |err|
            std.debug.print("capture {s}: {t}\n", .{ path, err });
    }
};
/// Room for the suite's 1 MiB message in one frame, plus its header.
const max_msg = 2 << 20;

// ── shared with go_oracle/main.go ──────────────────────────────────────────

fn pattern(out: []u8, text: bool) []u8 {
    for (out, 0..) |*b, i| b.* = if (text) @intCast('a' + i % 26) else @truncate(i *% 31 +% 7);
    return out;
}

const SuiteMsg = struct { text: bool, len: usize };
const suite_lens = [_]usize{ 0, 1, 125, 126, 127, 65535, 65536, 1 << 20 };
const suite_utf8 = "žluťoučký kůň úpěl ďábelské ódy — 😀 €";
const suite_count = suite_lens.len * 2 + 1;

/// The i-th message of the suite (the Go side's `suite()`), into `buf`.
fn suiteMsg(i: usize, buf: []u8) struct { opcode: frame.Opcode, data: []const u8 } {
    if (i == suite_count - 1) return .{ .opcode = .text, .data = suite_utf8 };
    const text = i % 2 == 0;
    return .{ .opcode = if (text) .text else .binary, .data = pattern(buf[0..suite_lens[i / 2]], text) };
}

// ── the watchdog ───────────────────────────────────────────────────────────

/// A case that runs past this is a hang: the program says which and exits.
const case_limit_ms = 40_000;
var wd_started_ms: std.atomic.Value(i64) = .init(0);
var wd_case: [96]u8 = undefined;
var wd_case_len: std.atomic.Value(usize) = .init(0);

fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}

fn watchdog(io: std.Io) void {
    while (true) {
        io.sleep(.fromMilliseconds(500), .awake) catch {};
        const t = wd_started_ms.load(.acquire);
        if (t != 0 and nowMs(io) - t > case_limit_ms) {
            std.debug.print("HANG case={s}: over {d} ms\n", .{ wd_case[0..wd_case_len.load(.acquire)], case_limit_ms });
            std.process.exit(2);
        }
    }
}

fn caseStart(io: std.Io, id: []const u8) void {
    const n = @min(id.len, wd_case.len);
    @memcpy(wd_case[0..n], id[0..n]);
    wd_case_len.store(n, .release);
    wd_started_ms.store(nowMs(io), .release);
}

// ── this module's server ───────────────────────────────────────────────────

/// What the server handler recorded about the last connection. Cases run
/// one at a time, so one slot does.
const Obs = struct {
    id_buf: [96]u8 = undefined,
    id_len: usize = 0,
    line_buf: [256]u8 = undefined,
    line_len: usize = 0,
    ready: std.atomic.Value(bool) = .init(false),
    /// `--capture`: the server handler taps its connections.
    capture_io: ?std.Io = null,

    fn put(o: *Obs, id: []const u8, comptime fmt: []const u8, args: anytype) void {
        const n = @min(id.len, o.id_buf.len);
        @memcpy(o.id_buf[0..n], id[0..n]);
        o.id_len = n;
        o.line_len = (std.mem.print(&o.line_buf, fmt, args) catch @as([]const u8, "overflow")).len;
        o.ready.store(true, .release);
    }

    fn take(o: *Obs, io: std.Io, id: []const u8, arena: std.mem.Allocator) ![]const u8 {
        var waited: u32 = 0;
        while (!o.ready.load(.acquire)) : (waited += 1) {
            if (waited > 5000) return "none";
            try io.sleep(.fromMilliseconds(1), .awake);
        }
        o.ready.store(false, .release);
        if (!std.mem.eql(u8, o.id_buf[0..o.id_len], id)) return arena.print("wrong case {s}", .{o.id_buf[0..o.id_len]});
        return arena.dupe(u8, o.line_buf[0..o.line_len]);
    }
};

fn queryValue(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        if (kv.len > name.len and std.mem.startsWith(u8, kv, name) and kv[name.len] == '=') return kv[name.len + 1 ..];
    }
    return null;
}

/// The deflate state one side of a connection needs (`conn.Deflate`).
const DeflateState = struct {
    cbuf: []u8,
    window: *deflate.Window,
    compressor: *deflate.Compressor,
    out: []u8,

    fn init(gpa: std.mem.Allocator) !DeflateState {
        return .{
            .cbuf = try gpa.alloc(u8, max_msg),
            .window = try gpa.create(deflate.Window),
            .compressor = try gpa.create(deflate.Compressor),
            .out = try gpa.alloc(u8, max_msg),
        };
    }

    fn deinit(d: DeflateState, gpa: std.mem.Allocator) void {
        gpa.free(d.cbuf);
        gpa.destroy(d.window);
        gpa.destroy(d.compressor);
        gpa.free(d.out);
    }

    fn opts(d: DeflateState) websocket.conn.Deflate {
        return .{ .compressed_buf = d.cbuf, .window = d.window, .compressor = d.compressor, .out_buf = d.out };
    }
};

/// Echo until the peer closes; the record has the Go handlers' shape.
fn serverEcho(c: *Conn, msgs_in: usize, buf: []u8) []const u8 {
    var msgs = msgs_in;
    while (true) {
        const m = c.readMessage() catch |err| {
            if (err == error.Closed) {
                const code = c.peer_close.?.code orelse 1005;
                return std.mem.print(buf, "closed={d} msgs={d}", .{ code, msgs }) catch unreachable;
            }
            return std.mem.print(buf, "closed=err:{t} msgs={d}", .{ err, msgs }) catch unreachable;
        };
        msgs += 1;
        c.writeMessage(m.opcode, m.payload) catch |err| return std.mem.print(buf, "closed=err:write_{t} msgs={d}", .{ err, msgs }) catch unreachable;
    }
}

/// Send `body` as a text message in four frames -- compressed (RSV1 on the
/// first frame only, RFC 7692 §6.1) when `d` is given.
fn writeFragmented(c: *Conn, body: []const u8, d: ?DeflateState, mask: ?std.Random) !void {
    var data = body;
    var compressed = false;
    if (d) |ds| if (ds.compressor.compressMessage(body, ds.out, 1)) |z| {
        data = z;
        compressed = true;
    };
    const q = data.len / 4;
    for (0..4) |i| {
        const part = data[i * q .. if (i == 3) data.len else (i + 1) * q];
        var key: ?[4]u8 = null;
        if (mask) |r| {
            var k: [4]u8 = undefined;
            r.bytes(&k);
            key = k;
        }
        try frame.writeFrame(c.writer, .{
            .fin = i == 3,
            .opcode = if (i == 0) .text else .continuation,
            .payload = part,
            .mask_key = key,
            .compressed = compressed and i == 0,
        });
    }
    try c.writer.flush();
}

fn ourHandler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const obs: *Obs = @ptrCast(@alignCast(req.context.?));
    const id = queryValue(req.query, "case") orelse "-";
    const path = req.path;
    const deflating = std.mem.endsWith(u8, path, "deflate");
    const accept = handshake.acceptHandshake(req.head, .{ .protocols = &.{ "chat", "echo" }, .permessage_deflate = deflating }) catch |err| {
        obs.put(id, "accept:{t}", .{err});
        return rw.writeError(400, "bad websocket handshake");
    };
    const up = try handshake.respondUpgraded(req, rw, accept);

    const gpa = std.heap.page_allocator;
    const msg_buf = try gpa.alloc(u8, max_msg);
    defer gpa.free(msg_buf);
    var ds: ?DeflateState = null;
    if (accept.deflate != null) ds = try DeflateState.init(gpa);
    defer if (ds) |d| d.deinit(gpa);
    var tap_buf: [16 * 1024]u8 = undefined;
    var tap: Tap = .init(up.reader, gpa, &tap_buf);
    defer tap.log.deinit(gpa);
    const scenario = queryValue(req.query, "sc") orelse "";
    const tapping = obs.capture_io != null and isCaptured(scenario);
    defer if (tapping) tap.save(obs.capture_io.?, id);
    var c: Conn = .init(.server, if (tapping) &tap.reader else up.reader, up.writer, msg_buf, .{
        .deflate = if (ds) |d| d.opts() else null,
        .max_frame_size = max_msg,
    });
    var line: [160]u8 = undefined;
    const tail_proto = accept.protocol orelse "-";
    const tail_ext: u8 = if (accept.deflate != null) '1' else '0';

    if (std.mem.eql(u8, path, "/echo") or std.mem.eql(u8, path, "/deflate")) {
        obs.put(id, "{s} proto={s} ext={c}", .{ serverEcho(&c, 0, &line), tail_proto, tail_ext });
    } else if (std.mem.startsWith(u8, path, "/close/")) {
        const code = std.fmt.parseInt(u16, path["/close/".len..], 10) catch 1000;
        try c.close(code, "zl-bye");
        // The peer's close frame answers it.
        while (true) {
            _ = c.readMessage() catch |err| {
                if (err == error.Closed) {
                    obs.put(id, "closed=ok proto={s} ext={c}", .{ tail_proto, tail_ext });
                } else obs.put(id, "closed=err:{t} proto={s} ext={c}", .{ err, tail_proto, tail_ext });
                break;
            };
        }
    } else if (std.mem.eql(u8, path, "/frag") or std.mem.eql(u8, path, "/frag-deflate")) {
        var body: [frag_len]u8 = undefined;
        _ = pattern(&body, true);
        writeFragmented(&c, &body, ds, null) catch |err| {
            obs.put(id, "closed=err:write_{t} proto={s} ext={c}", .{ err, tail_proto, tail_ext });
            return;
        };
        const m = c.readMessage() catch |err| {
            obs.put(id, "closed=err:bad_echo_{t} proto={s} ext={c}", .{ err, tail_proto, tail_ext });
            return;
        };
        if (m.opcode != .text or !std.mem.eql(u8, m.payload, &body)) {
            obs.put(id, "closed=err:bad_echo proto={s} ext={c}", .{ tail_proto, tail_ext });
            return;
        }
        obs.put(id, "{s} proto={s} ext={c}", .{ serverEcho(&c, 1, &line), tail_proto, tail_ext });
    } else {
        obs.put(id, "no such path", .{});
    }
}

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

// ── this module's client ───────────────────────────────────────────────────

const Env = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    go_exe: []const u8,
    env_map: *std.process.Environ.Map,
    coder_port: u16,
    gorilla_port: u16,
    our_port: u16,
    obs: *Obs,
    prng: std.Random.DefaultPrng = .init(0x6455),
    capture: bool = false,
};

const Impl = enum {
    ours,
    coder,
    gorilla,

    fn port(i: Impl, env: *const Env) u16 {
        return switch (i) {
            .ours => env.our_port,
            .coder => env.coder_port,
            .gorilla => env.gorilla_port,
        };
    }
};

fn scenarioPath(scenario: []const u8) []const u8 {
    if (std.mem.eql(u8, scenario, "deflate")) return "/deflate";
    if (std.mem.eql(u8, scenario, "frag")) return "/frag";
    if (std.mem.eql(u8, scenario, "frag-deflate")) return "/frag-deflate";
    if (std.mem.eql(u8, scenario, "sping")) return "/ping";
    if (std.mem.eql(u8, scenario, "servclose")) return "/close/4002";
    return "/echo";
}

/// One scenario of this module's client against `port`; "ok …" or "err …"
/// in the Go client's format.
fn ourClient(env: *Env, port: u16, scenario: []const u8, id: []const u8) []const u8 {
    return ourClientInner(env, port, scenario, id) catch |err| env.arena.print("err {t}", .{err}) catch "err OOM";
}

fn ourClientInner(env: *Env, port: u16, scenario: []const u8, id: []const u8) ![]const u8 {
    const io = env.io;
    const arena = env.arena;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var rbuf: [16 * 1024]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var sr = s.reader(io, &rbuf);
    var sw = s.writer(io, &wbuf);

    const rnd = env.prng.random();
    const key = handshake.generateKey(rnd);
    const offer_deflate = std.mem.endsWith(u8, scenario, "deflate");
    const protocols: []const []const u8 = if (std.mem.eql(u8, scenario, "subproto")) &.{ "chat", "echo" } else &.{};
    const host = try arena.print("127.0.0.1:{d}", .{port});
    const target = try arena.print("{s}?case={s}", .{ scenarioPath(scenario), id });
    try handshake.writeRequest(&sw.interface, .{ .host = host, .target = target, .key = &key, .protocols = protocols, .permessage_deflate = offer_deflate });
    try sw.interface.flush();
    var head_buf: [4096]u8 = undefined;
    const head = try http.h1.ResponseHead.parse(try http.h1.readHead(&sr.interface, &head_buf));
    const v = try handshake.verifyResponseWith(head, &key, .{ .protocols = protocols, .permessage_deflate = offer_deflate });
    const ext: u8 = if (v.deflate != null) '1' else '0';

    var ds: ?DeflateState = null;
    if (v.deflate != null) ds = try DeflateState.init(arena);
    const msg_buf = try arena.alloc(u8, max_msg);
    var tap_buf: [16 * 1024]u8 = undefined;
    var tap: Tap = .init(&sr.interface, arena, &tap_buf);
    const tapping = env.capture and isCaptured(scenario);
    defer if (tapping) tap.save(io, id);
    var c: Conn = .init(.client, if (tapping) &tap.reader else &sr.interface, &sw.interface, msg_buf, .{
        .mask_random = rnd,
        .deflate = if (ds) |d| d.opts() else null,
        .max_frame_size = max_msg,
    });

    if (std.mem.eql(u8, scenario, "echo") or std.mem.eql(u8, scenario, "deflate")) {
        const buf = try arena.alloc(u8, 1 << 20);
        for (0..suite_count) |i| {
            const m = suiteMsg(i, buf);
            try c.writeMessage(m.opcode, m.data);
            const r = c.readMessage() catch |err| return arena.print("err read {d}: {t}", .{ i, err });
            if (r.opcode != m.opcode or !std.mem.eql(u8, r.payload, m.data))
                return arena.print("err echo {d} differs (len {d}, want {d})", .{ i, r.payload.len, m.data.len });
        }
        try closeNormally(&c, 1000, "");
        return arena.print("ok msgs={d} ext={c}", .{ suite_count, ext });
    }
    if (std.mem.startsWith(u8, scenario, "frag")) {
        var body: [frag_len]u8 = undefined;
        _ = pattern(&body, true);
        // The server's fragmented message first, then ours back.
        const r = c.readMessage() catch |err| return arena.print("err read: {t}", .{err});
        if (r.opcode != .text or !std.mem.eql(u8, r.payload, &body)) return "err server message differs";
        try writeFragmented(&c, &body, ds, rnd);
        try closeNormally(&c, 1000, "");
        return arena.print("ok msgs=1 ext={c}", .{ext});
    }
    if (std.mem.eql(u8, scenario, "sping")) {
        // `readMessage` answers the ping by itself; the server then says so.
        const r = c.readMessage() catch |err| return arena.print("err read: {t}", .{err});
        // The payload borrows the reader's buffer until the next read.
        const said = try arena.dupe(u8, r.payload);
        if (!std.mem.startsWith(u8, said, "ping-ok")) return arena.print("err server says {s}", .{said});
        try closeNormally(&c, 1000, "");
        return arena.print("ok {s} ext={c}", .{ said, ext });
    }
    if (std.mem.eql(u8, scenario, "close")) {
        try closeNormally(&c, 4001, "zl-client-bye");
        return arena.print("ok closed ext={c}", .{ext});
    }
    if (std.mem.eql(u8, scenario, "servclose")) {
        while (true) {
            _ = c.readMessage() catch |err| {
                if (err != error.Closed) return arena.print("err read: {t}", .{err});
                const pc = c.peer_close.?;
                return arena.print("ok code={d} reason={s} ext={c}", .{ pc.code orelse 1005, pc.reason, ext });
            };
        }
    }
    if (std.mem.eql(u8, scenario, "subproto")) {
        try closeNormally(&c, 1000, "");
        return arena.print("ok proto={s} ext={c}", .{ v.protocol orelse "-", ext });
    }
    return "err unknown scenario";
}

/// Close with `code` and wait for the echo, which must carry the same code.
fn closeNormally(c: *Conn, code: u16, reason: []const u8) !void {
    try c.close(code, reason);
    while (true) {
        _ = c.readMessage() catch |err| {
            if (err != error.Closed) return err;
            if (c.peer_close.?.code != code) return error.CloseEchoDiffers;
            return;
        };
    }
}

fn goClient(env: *Env, lib: Impl, port: u16, scenario: []const u8, id: []const u8) []const u8 {
    const url = env.arena.print("ws://127.0.0.1:{d}{s}?case={s}&sc={s}", .{ port, scenarioPath(scenario), id, scenario }) catch return "err OOM";
    const r = std.process.run(env.arena, env.io, .{
        .argv = &.{ env.go_exe, "client", @tagName(lib), url, scenario },
        .environ_map = env.env_map,
        .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    }) catch |err| return env.arena.print("err go client: {t}", .{err}) catch "err OOM";
    return std.mem.trim(u8, r.stdout, " \n");
}

/// The server's record of case `id`.
fn report(env: *Env, server: Impl, id: []const u8) []const u8 {
    if (server == .ours) return env.obs.take(env.io, id, env.arena) catch "none";
    return goReport(env, server.port(env), id) catch |err| env.arena.print("report: {t}", .{err}) catch "none";
}

fn goReport(env: *Env, port: u16, id: []const u8) ![]const u8 {
    const io = env.io;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var rbuf: [4096]u8 = undefined;
    var wbuf: [512]u8 = undefined;
    var sr = s.reader(io, &rbuf);
    var sw = s.writer(io, &wbuf);
    try sw.interface.print("GET /report?case={s} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", .{id});
    try sw.interface.flush();
    var head_buf: [2048]u8 = undefined;
    _ = try http.h1.readHead(&sr.interface, &head_buf);
    const body = try sr.interface.allocRemaining(env.arena, .limited(4096));
    return std.mem.trim(u8, body, " \r\n");
}

// ── raw cases ──────────────────────────────────────────────────────────────

const Expect = enum { agree, stricter, differs };

const Hs = enum { normal, deflate, dup_key, version8, origin_evil, key15, http10, no_connection, key_not_b64, dup_version, upgrade_list };

const RawCase = struct {
    id: []const u8,
    hs: Hs = .normal,
    /// The frames after the handshake; a close 1000 follows unless the
    /// last of them is a close.
    frames: []const []const u8 = &.{},
    /// Messages a server that accepts everything echoes.
    echoes: usize = 0,
    coder: Expect = .agree,
    gorilla: Expect = .agree,
    why: []const u8 = "",
};

const mask_key = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };

const Form = enum { min, f16, f64 };

/// A client frame: `b0` (FIN/RSV/opcode), masked unless `masked` is false,
/// the length in `form` (non-minimal when the payload is shorter).
fn rawFrame(arena: std.mem.Allocator, b0: u8, payload: []const u8, form: Form, masked: bool) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.append(arena, b0);
    const m: u8 = if (masked) 0x80 else 0;
    switch (form) {
        .min => if (payload.len < 126) {
            try out.append(arena, m | @as(u8, @intCast(payload.len)));
        } else if (payload.len <= 0xffff) {
            try out.append(arena, m | 126);
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(payload.len))));
        } else {
            try out.append(arena, m | 127);
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u64, payload.len)));
        },
        .f16 => {
            try out.append(arena, m | 126);
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(payload.len))));
        },
        .f64 => {
            try out.append(arena, m | 127);
            try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u64, payload.len)));
        },
    }
    if (masked) try out.appendSlice(arena, &mask_key);
    const start = out.items.len;
    try out.appendSlice(arena, payload);
    if (masked) frame.applyMask(out.items[start..], mask_key);
    return out.items;
}

fn f(arena: std.mem.Allocator, b0: u8, payload: []const u8) []const u8 {
    return rawFrame(arena, b0, payload, .min, true) catch @panic("OOM");
}

fn closeBody(arena: std.mem.Allocator, code: u16, reason: []const u8) []const u8 {
    const b = arena.alloc(u8, 2 + reason.len) catch @panic("OOM");
    std.mem.writeInt(u16, b[0..2], code, .big);
    @memcpy(b[2..], reason);
    return b;
}

fn rawCases(arena: std.mem.Allocator) ![]const RawCase {
    var out: std.ArrayList(RawCase) = .empty;
    const a = arena;
    try out.appendSlice(a, &.{
        .{ .id = "valid-text", .frames = try a.dupe([]const u8, &.{f(a, 0x81, "Hello")}), .echoes = 1 },
        .{ .id = "valid-binary-64k", .frames = try a.dupe([]const u8, &.{f(a, 0x82, &@as([65536]u8, @splat(0x5a)))}), .echoes = 1 },
        .{ .id = "valid-fragmented-ping-between", .frames = try a.dupe([]const u8, &.{ f(a, 0x01, "Hel"), f(a, 0x89, "p"), f(a, 0x80, "lo") }), .echoes = 1 },
        .{ .id = "valid-empty-text", .frames = try a.dupe([]const u8, &.{f(a, 0x81, "")}), .echoes = 1 },
        .{ .id = "valid-utf8-split-across-fragments", .frames = try a.dupe([]const u8, &.{ f(a, 0x01, "\xc5"), f(a, 0x80, "\xbe") }), .echoes = 1 },
        .{ .id = "valid-unsolicited-pong", .frames = try a.dupe([]const u8, &.{ f(a, 0x8a, "x"), f(a, 0x81, "ok") }), .echoes = 1 },
        // RFC 6455 §8.1: invalid UTF-8 text MUST fail the connection (1007).
        .{ .id = "utf8-invalid-surrogate", .frames = try a.dupe([]const u8, &.{f(a, 0x81, "\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5\xed\xa0\x80edited")}), .echoes = 1, .coder = .stricter, .gorilla = .stricter, .why = "RFC 6455 §8.1: invalid UTF-8 in a text message MUST fail the connection (1007); the peer echoes it" },
        .{ .id = "utf8-overlong", .frames = try a.dupe([]const u8, &.{f(a, 0x81, "\xc0\xaf")}), .echoes = 1, .coder = .stricter, .gorilla = .stricter, .why = "RFC 6455 §8.1 (overlong form is not UTF-8, RFC 3629 §3)" },
        .{ .id = "utf8-invalid-across-fragments", .frames = try a.dupe([]const u8, &.{ f(a, 0x01, "ok\xce"), f(a, 0x80, "\xff") }), .echoes = 1, .coder = .stricter, .gorilla = .stricter, .why = "RFC 6455 §8.1, a fragmented message" },
        // RFC 6455 §5.2: "the minimal number of bytes MUST be used".
        .{ .id = "length-nonminimal-16", .frames = try a.dupe([]const u8, &.{try rawFrame(a, 0x81, "Hello", .f16, true)}), .echoes = 1, .coder = .stricter, .gorilla = .stricter, .why = "RFC 6455 §5.2: the minimal length encoding MUST be used; the peer reads a 16-bit length of 5" },
        .{ .id = "length-nonminimal-64", .frames = try a.dupe([]const u8, &.{try rawFrame(a, 0x81, "Hello", .f64, true)}), .echoes = 1, .coder = .stricter, .gorilla = .stricter, .why = "RFC 6455 §5.2, the 64-bit form" },
        // Protocol violations every implementation must refuse.
        .{ .id = "unmasked-client-frame", .frames = try a.dupe([]const u8, &.{try rawFrame(a, 0x81, "Hello", .min, false)}), .echoes = 1 },
        .{ .id = "rsv1-without-extension", .frames = try a.dupe([]const u8, &.{f(a, 0xc1, "Hello")}), .echoes = 1 },
        .{ .id = "rsv2", .frames = try a.dupe([]const u8, &.{f(a, 0xa1, "Hello")}), .echoes = 1 },
        .{ .id = "rsv3", .frames = try a.dupe([]const u8, &.{f(a, 0x91, "Hello")}), .echoes = 1 },
        .{ .id = "opcode-3-reserved", .frames = try a.dupe([]const u8, &.{f(a, 0x83, "Hello")}), .echoes = 1 },
        .{ .id = "opcode-b-reserved-control", .frames = try a.dupe([]const u8, &.{f(a, 0x8b, "")}), .echoes = 0 },
        .{ .id = "ping-fragmented", .frames = try a.dupe([]const u8, &.{f(a, 0x09, "p")}), .echoes = 0 },
        .{ .id = "ping-126-bytes", .frames = try a.dupe([]const u8, &.{f(a, 0x89, &@as([126]u8, @splat('p')))}), .echoes = 0 },
        .{ .id = "continuation-orphan", .frames = try a.dupe([]const u8, &.{f(a, 0x80, "lo")}), .echoes = 1 },
        .{ .id = "text-inside-fragmented-message", .frames = try a.dupe([]const u8, &.{ f(a, 0x01, "Hel"), f(a, 0x81, "x"), f(a, 0x80, "lo") }), .echoes = 2 },
        .{ .id = "data-after-close", .frames = try a.dupe([]const u8, &.{ f(a, 0x88, closeBody(a, 1000, "")), f(a, 0x81, "late") }), .echoes = 0 },
        // Close frames (§5.5.1, §7.4).
        .{ .id = "close-1000", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1000, "bye"))}) },
        .{ .id = "close-empty", .frames = try a.dupe([]const u8, &.{f(a, 0x88, "")}) },
        .{ .id = "close-4001", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 4001, ""))}) },
        .{ .id = "close-1012", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1012, ""))}) },
        .{ .id = "close-1013", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1013, ""))}) },
        .{ .id = "close-1014", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1014, ""))}), .gorilla = .differs, .why = "1014 Bad Gateway is assigned in the IANA registry RFC 6455 §11.7 makes authoritative; gorilla v1.5.3 predates it" },
        .{ .id = "close-999", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 999, ""))}) },
        .{ .id = "close-1004", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1004, ""))}) },
        .{ .id = "close-1005", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1005, ""))}) },
        .{ .id = "close-1006", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1006, ""))}) },
        .{ .id = "close-1015", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1015, ""))}) },
        .{ .id = "close-2999", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 2999, ""))}) },
        .{ .id = "close-5000", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 5000, ""))}) },
        .{ .id = "close-1-byte-body", .frames = try a.dupe([]const u8, &.{f(a, 0x88, "\x03")}), .gorilla = .stricter, .why = "RFC 6455 §5.5.1: a body, if present, starts with a 2-byte code; gorilla reads one byte as a close without a code" },
        .{ .id = "close-reason-invalid-utf8", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1000, "\xff\xfe"))}), .coder = .stricter, .why = "RFC 6455 §5.5.1: the close reason is UTF-8 (§8.1 applies); coder accepts it" },
        .{ .id = "close-reason-123-bytes", .frames = try a.dupe([]const u8, &.{f(a, 0x88, closeBody(a, 1000, &@as([123]u8, @splat('r'))))}) },
        // permessage-deflate negotiated (no context takeover).
        .{ .id = "deflate-rfc7692-hello", .hs = .deflate, .frames = try a.dupe([]const u8, &.{f(a, 0xc1, "\xf2\x48\xcd\xc9\xc9\x07\x00")}), .echoes = 1 },
        .{ .id = "deflate-two-fragments", .hs = .deflate, .frames = try a.dupe([]const u8, &.{ f(a, 0x41, "\xf2\x48\xcd"), f(a, 0x80, "\xc9\xc9\x07\x00") }), .echoes = 1 },
        .{ .id = "deflate-rsv1-on-continuation", .hs = .deflate, .frames = try a.dupe([]const u8, &.{ f(a, 0x01, "Hel"), f(a, 0xc0, "lo") }), .echoes = 1, .gorilla = .stricter, .why = "RFC 7692 §6.1: RSV1 on a non-first fragment MUST fail the connection; gorilla ignores it" },
        .{ .id = "deflate-rsv1-on-ping", .hs = .deflate, .frames = try a.dupe([]const u8, &.{f(a, 0xc9, "")}), .echoes = 0, .gorilla = .stricter, .why = "RFC 7692 §6.1: RSV1 on a control frame MUST fail the connection; gorilla ignores it" },
        .{ .id = "deflate-uncompressed-message", .hs = .deflate, .frames = try a.dupe([]const u8, &.{f(a, 0x81, "plain")}), .echoes = 1 },
        // Opening handshake (§4.2.1).
        .{ .id = "hs-version-8", .hs = .version8 },
        .{ .id = "hs-cross-origin", .hs = .origin_evil },
        .{ .id = "hs-http-1.0", .hs = .http10, .gorilla = .stricter, .why = "RFC 6455 §4.1/§4.2.1: the request MUST be HTTP/1.1 or higher; gorilla upgrades an HTTP/1.0 request" },
        .{ .id = "hs-no-connection-upgrade", .hs = .no_connection },
        .{ .id = "hs-key-15-bytes", .hs = .key15 },
        .{ .id = "hs-key-not-base64", .hs = .key_not_b64 },
        .{ .id = "hs-duplicate-key", .hs = .dup_key, .gorilla = .stricter, .why = "RFC 6455 §11.3.1: Sec-WebSocket-Key MUST NOT appear more than once in a request; gorilla answers the first one" },
        .{ .id = "hs-duplicate-version", .hs = .dup_version, .coder = .stricter, .gorilla = .stricter, .why = "RFC 6455 §11.3.5: Sec-WebSocket-Version MUST NOT appear more than once in a request" },
        .{ .id = "hs-upgrade-token-list", .hs = .upgrade_list, .frames = try a.dupe([]const u8, &.{f(a, 0x81, "Hello")}), .echoes = 1 },
    });
    return out.items;
}

fn rawRequest(arena: std.mem.Allocator, hs: Hs, port: u16, id: []const u8) ![]const u8 {
    const key = "dGhlIHNhbXBsZSBub25jZQ==";
    var w: std.Io.Writer.Allocating = .init(arena);
    const o = &w.writer;
    try o.print("GET /{s}?case={s} HTTP/1.{c}\r\n", .{ if (hs == .deflate) "deflate" else "echo", id, @as(u8, if (hs == .http10) '0' else '1') });
    try o.print("Host: 127.0.0.1:{d}\r\n", .{port});
    try o.writeAll(if (hs == .upgrade_list) "Upgrade: foo, websocket\r\n" else "Upgrade: websocket\r\n");
    try o.writeAll(if (hs == .no_connection) "Connection: keep-alive\r\n" else "Connection: Upgrade\r\n");
    try o.writeAll(switch (hs) {
        .key15 => "Sec-WebSocket-Key: AAECAwQFBgcICQoLDA0O\r\n",
        .key_not_b64 => "Sec-WebSocket-Key: !!!!!!!!!!!!!!!!!!!!!!==\r\n",
        else => "Sec-WebSocket-Key: " ++ key ++ "\r\n",
    });
    if (hs == .dup_key) try o.writeAll("Sec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA==\r\n");
    try o.writeAll(if (hs == .version8) "Sec-WebSocket-Version: 8\r\n" else "Sec-WebSocket-Version: 13\r\n");
    if (hs == .dup_version) try o.writeAll("Sec-WebSocket-Version: 13\r\n");
    if (hs == .origin_evil) try o.writeAll("Origin: http://evil.example\r\n");
    if (hs == .deflate) try o.writeAll("Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n");
    try o.writeAll("\r\n");
    return w.written();
}

/// The verdict a server gave a raw case: `status=<n>` when the handshake
/// was refused, else `echo=<n> close=<code|none|eof>`.
const RawVerdict = struct {
    text: []const u8,
    accepted: bool,
};

fn runRaw(env: *Env, c: *const RawCase, server: Impl) RawVerdict {
    const text = runRawInner(env, c, server) catch |err| env.arena.print("err:{t}", .{err}) catch "err";
    return .{ .text = text, .accepted = rawAccepted(c, text) };
}

/// Accepted = the handshake succeeded, every message came back, and the
/// connection ended with a close that is not a protocol-error answer.
fn rawAccepted(c: *const RawCase, text: []const u8) bool {
    if (!std.mem.startsWith(u8, text, "echo=")) return false;
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    const echoes = std.fmt.parseInt(usize, it.next().?["echo=".len..], 10) catch return false;
    const close = (it.next() orelse return false)["close=".len..];
    if (echoes != c.echoes) return false;
    for ([_][]const u8{ "1002", "1003", "1007", "1008", "1009", "1010", "1011", "eof" }) |bad| if (std.mem.eql(u8, close, bad)) return false;
    return true;
}

fn runRawInner(env: *Env, c: *const RawCase, server: Impl) ![]const u8 {
    const io = env.io;
    const arena = env.arena;
    const port = server.port(env);
    const id = try arena.print("raw-{s}@{t}", .{ c.id, server });
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    const rbuf = try arena.alloc(u8, 1 << 18);
    var wbuf: [1024]u8 = undefined;
    var sr = s.reader(io, rbuf);
    var sw = s.writer(io, &wbuf);
    try sw.interface.writeAll(try rawRequest(arena, c.hs, port, id));
    try sw.interface.flush();
    var head_buf: [4096]u8 = undefined;
    const head = try http.h1.ResponseHead.parse(try http.h1.readHead(&sr.interface, &head_buf));
    // Drain the server's record of a refused handshake (ours keeps it).
    if (head.status != 101) {
        if (server == .ours) _ = report(env, .ours, id);
        return arena.print("status={d}", .{head.status});
    }
    for (c.frames) |fr| try sw.interface.writeAll(fr);
    const ends_with_close = c.frames.len > 0 and c.frames[c.frames.len - 1][0] & 0x0f == 0x8;
    if (!ends_with_close) try sw.interface.writeAll(f(arena, 0x88, closeBody(arena, 1000, "")));
    sw.interface.flush() catch {};

    var echoes: usize = 0;
    const r = &sr.interface;
    const close: []const u8 = while (true) {
        const buf = r.buffered();
        const res = frame.parseFrameWith(@constCast(buf), .client, 1 << 17, .{ .allow_rsv1 = true }) catch |err| break try arena.print("bad-frame:{t}", .{err});
        switch (res) {
            .need_more => {
                r.fillMore() catch break "eof";
                continue;
            },
            .frame => |fr| {
                r.toss(fr.consumed);
                switch (fr.opcode) {
                    .text, .binary => echoes += 1,
                    .close => {
                        if (fr.payload.len < 2) break "none";
                        break try arena.print("{d}", .{std.mem.readInt(u16, fr.payload[0..2], .big)});
                    },
                    else => {},
                }
            },
        }
    };
    if (server == .ours) _ = report(env, .ours, id);
    return arena.print("echo={d} close={s}", .{ echoes, close });
}

// ── main ───────────────────────────────────────────────────────────────────

const Tally = struct { cases: usize = 0, surprises: usize = 0, stricter: usize = 0, differs: usize = 0 };

const Out = struct {
    w: *std.Io.Writer,
    tsv: *std.Io.Writer,
    families: std.StringArrayHashMapUnmanaged(Tally) = .empty,
    total: Tally = .{},
    arena: std.mem.Allocator,

    fn row(o: *Out, id: []const u8, family: []const u8, expect: Expect, peer: []const u8, ours: []const u8, surprise: ?[]const u8, why: []const u8) !void {
        const fam = try o.families.getOrPut(o.arena, family);
        if (!fam.found_existing) fam.value_ptr.* = .{};
        inline for (.{ fam.value_ptr, &o.total }) |t| {
            t.cases += 1;
            if (surprise != null) t.surprises += 1;
            if (surprise == null and expect == .stricter) t.stricter += 1;
            if (surprise == null and expect == .differs) t.differs += 1;
        }
        try o.tsv.print("{s}\t{s}\t{t}\t{s}\t{s}\t{s}\t{s}\n", .{ id, family, expect, peer, ours, if (surprise == null) "as expected" else "SURPRISE", surprise orelse why });
        if (surprise) |s| try o.w.print("SURPRISE {s} ({t}): {s}\n", .{ id, expect, s });
    }
};

fn matches(filters: []const [:0]const u8, id: []const u8) bool {
    if (filters.len == 0) return true;
    for (filters) |x| if (std.mem.find(u8, id, x) != null) return true;
    return false;
}

const client_scenarios = [_][]const u8{ "echo", "deflate", "frag", "frag-deflate", "sping", "close", "servclose", "subproto" };
const server_scenarios = [_][]const u8{ "echo", "deflate", "frag", "frag-deflate", "ping", "close", "servclose", "subproto" };

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    var capture = false;
    var filter_list: std.ArrayList([:0]const u8) = .empty;
    for (args[1..]) |a| {
        if (std.mem.eql(u8, a, "--capture")) capture = true else try filter_list.append(arena, a);
    }
    const filters = filter_list.items;
    if (capture and filters.len != 0) {
        std.debug.print("interop-websocket: --capture rewrites every capture: run it without filters\n", .{});
        return 1;
    }
    if (capture) try cwd.createDirPath(io, capture_dir);

    var env_map = try init.environ_map.clone(arena);
    try env_map.put("GOTOOLCHAIN", "local");
    try env_map.put("GOPROXY", "off");
    try env_map.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_oracle", .{abs});
    const build = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env_map,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("interop-websocket: could not run go ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("interop-websocket: go build failed:\n{s}\n", .{build.stderr});
        return 1;
    }

    var server = try std.process.spawn(io, .{
        .argv = &.{ exe, "serve" },
        .environ_map = &env_map,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    defer server.kill(io);
    var go_version: []const u8 = "?";
    var coder_port: u16 = 0;
    var gorilla_port: u16 = 0;
    {
        var buf: [256]u8 = undefined;
        var r = server.stdout.?.reader(io, &buf);
        const line = (try r.interface.takeDelimiter('\n')) orelse {
            std.debug.print("interop-websocket: the Go oracle exited before it was ready\n", .{});
            return 1;
        };
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, it.next() orelse "", "READY")) return error.BadOracleBanner;
        go_version = try arena.dupe(u8, it.next() orelse "?");
        while (it.next()) |kv| {
            if (std.mem.startsWith(u8, kv, "coder=")) coder_port = try std.fmt.parseInt(u16, kv[6..], 10);
            if (std.mem.startsWith(u8, kv, "gorilla=")) gorilla_port = try std.fmt.parseInt(u16, kv[8..], 10);
        }
    }

    var obs: Obs = .{ .capture_io = if (capture) io else null };
    // http.Server's default 16 KiB read buffer: `Conn` reads a payload
    // that does not fit it straight into `message_buf` (the suite sends
    // 1 MiB in one frame).
    var ours = http.Server.init(io, init.gpa, .{
        .handler = ourHandler,
        .context = &obs,
    });
    defer ours.deinit();
    try ours.bind();
    const ours_thread = try std.Thread.spawn(.{}, serveWrap, .{&ours});
    defer ours_thread.join();
    defer ours.shutdown();
    const wd = try std.Thread.spawn(.{}, watchdog, .{io});
    wd.detach();

    var env: Env = .{
        .io = io,
        .arena = arena,
        .go_exe = exe,
        .env_map = &env_map,
        .coder_port = coder_port,
        .gorilla_port = gorilla_port,
        .our_port = ours.boundAddress().getPort(),
        .obs = &obs,
        .capture = capture,
    };

    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    var tsv: std.Io.Writer.Allocating = .init(arena);
    try tsv.writer.writeAll("id\tfamily\texpect\tpeer\tours\tverdict\tdetail\n");
    var o: Out = .{ .w = &stdout.interface, .tsv = &tsv.writer, .arena = arena };

    // client: this module's client vs the Go servers; the judge is the
    // server library's own client.
    for ([_]Impl{ .coder, .gorilla }) |srv| for (client_scenarios) |sc| {
        const id = try arena.print("client-{s}@{t}", .{ sc, srv });
        if (!matches(filters, id)) continue;
        caseStart(io, id);
        const ref_id = try arena.print("{s}-ref", .{id});
        const go_line = goClient(&env, srv, srv.port(&env), sc, ref_id);
        const go_rep = report(&env, srv, ref_id);
        const our_line = ourClient(&env, srv.port(&env), sc, id);
        const our_rep = report(&env, srv, id);
        const surprise: ?[]const u8 = if (!std.mem.startsWith(u8, go_line, "ok"))
            try arena.print("the Go client fails: {s}", .{go_line})
        else if (!std.mem.eql(u8, go_line, our_line))
            try arena.print("Go client: {s} | ours: {s}", .{ go_line, our_line })
        else if (!std.mem.eql(u8, go_rep, our_rep))
            try arena.print("server saw Go: {s} | ours: {s}", .{ go_rep, our_rep })
        else
            null;
        try o.row(id, "client", .agree, go_line, our_line, surprise, our_rep);
    };

    // server: the Go clients vs this module's server; the judge is the same
    // client against its own library's server.
    for ([_]Impl{ .coder, .gorilla }) |cli| for (server_scenarios) |sc| {
        const id = try arena.print("server-{s}@{t}", .{ sc, cli });
        if (!matches(filters, id)) continue;
        caseStart(io, id);
        const ref_id = try arena.print("{s}-ref", .{id});
        const go_line = goClient(&env, cli, cli.port(&env), sc, ref_id);
        const go_rep = report(&env, cli, ref_id);
        const our_line = goClient(&env, cli, env.our_port, sc, id);
        const our_rep = report(&env, .ours, id);
        const surprise: ?[]const u8 = if (!std.mem.startsWith(u8, go_line, "ok"))
            try arena.print("the Go pair fails: {s}", .{go_line})
        else if (!std.mem.eql(u8, go_line, our_line))
            try arena.print("Go client vs its server: {s} | vs ours: {s}", .{ go_line, our_line })
        else if (!std.mem.eql(u8, go_rep, our_rep))
            try arena.print("Go server saw: {s} | ours saw: {s}", .{ go_rep, our_rep })
        else
            null;
        try o.row(id, "server", .agree, go_line, our_line, surprise, our_rep);
    };

    // raw: the same bytes to all three servers.
    for (try rawCases(arena)) |*c| {
        if (!matches(filters, try arena.print("raw-{s}", .{c.id}))) continue;
        caseStart(io, c.id);
        const v_ours = runRaw(&env, c, .ours);
        for ([_]Impl{ .coder, .gorilla }) |peer| {
            const id = try arena.print("raw-{s}@{t}", .{ c.id, peer });
            const expect = if (peer == .coder) c.coder else c.gorilla;
            const v = runRaw(&env, c, peer);
            const surprise: ?[]const u8 = switch (expect) {
                .agree => if (v.accepted != v_ours.accepted)
                    try arena.print("{t}: {s} | ours: {s}", .{ peer, v.text, v_ours.text })
                else
                    null,
                .stricter => if (!v.accepted)
                    try arena.print("{t} refuses it now ({s}): the lead is gone", .{ peer, v.text })
                else if (v_ours.accepted)
                    try arena.print("ours accepts it ({s})", .{v_ours.text})
                else
                    null,
                .differs => if (v.accepted == v_ours.accepted)
                    try arena.print("{t} and ours agree now ({s}): update the row", .{ peer, v.text })
                else
                    null,
            };
            try o.row(id, "raw", expect, v.text, v_ours.text, surprise, c.why);
        }
    }
    wd_started_ms.store(0, .release);
    try dir.writeFile(io, .{ .sub_path = "verdicts.tsv", .data = tsv.written() });

    const w = &stdout.interface;
    try w.print("\nGo {s}: coder/websocket v1.8.15, gorilla/websocket v1.5.3; {d} rows\n", .{ go_version, o.total.cases });
    try w.print("{s:<8} {s:>6} {s:>9} {s:>9} {s:>8}\n", .{ "family", "rows", "surprises", "stricter", "differs" });
    for (o.families.keys(), o.families.values()) |k, v| try w.print("{s:<8} {d:>6} {d:>9} {d:>9} {d:>8}\n", .{ k, v.cases, v.surprises, v.stricter, v.differs });
    try w.print("{s:<8} {d:>6} {d:>9} {d:>9} {d:>8}\n", .{ "total", o.total.cases, o.total.surprises, o.total.stricter, o.total.differs });
    try w.print("verdicts: {s}/verdicts.tsv\n", .{work_dir});
    try w.flush();
    return if (o.total.surprises == 0) 0 else 1;
}
