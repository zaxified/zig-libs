// SPDX-License-Identifier: MIT

//! karlseguin/websocket.zig (MIT, pinned in `tools/README.md`) as a live peer of
//! `interop.zig`: its SERVER and its CLIENT, speaking the scenarios of
//! `go_oracle/main.go` so the third column of `zig build interop-websocket` can
//! judge this module against them. Two modes:
//!
//!   ks_peer serve <port> <report-port>
//!   ks_peer client <ws-url> <scenario>
//!
//! `serve` listens on `<port>` (WebSocket) and `<report-port>` (plain HTTP:
//! `GET /report?case=<id>` returns the record of that case, as the Go oracle's
//! `/report` does), prints `READY ks=<port> report=<report-port>` and serves until
//! killed. `client` runs one scenario and prints `ok <detail>` or `err <detail>`.
//!
//! What the library cannot do, so the scenarios treat it the way the library
//! allows (and `interop.zig` documents per row): it never compresses what it
//! writes (its `compression` option is disabled in the Zig 0.17 branch, the client
//! refuses it), it negotiates no subprotocol by itself (the handler answers
//! `Sec-WebSocket-Protocol`), it writes every message as one frame (fragments are
//! hand-framed through `writeFramed` / `Stream.writeAll`), and `Client.close`
//! shuts the socket without waiting for the peer's close (the client here sends
//! the close frame with `writeFrame` and reads the echo itself).
//!
//! The library is not a dependency of zig-libs: `tools/ks_build.sh` clones it
//! outside the repository and builds this file against it.

const std = @import("std");
const ws = @import("websocket");

const frag_len = 4096;
const max_msg = 2 << 20;

// ── shared with go_oracle/main.go and interop.zig ──────────────────────────

fn pattern(out: []u8, text: bool) []u8 {
    for (out, 0..) |*b, i| b.* = if (text) @intCast('a' + i % 26) else @truncate(i *% 31 +% 7);
    return out;
}

const suite_lens = [_]usize{ 0, 1, 125, 126, 127, 65535, 65536, 1 << 20 };
const suite_utf8 = "žluťoučký kůň úpěl ďábelské ódy — 😀 €";
const suite_count = suite_lens.len * 2 + 1;

/// The i-th message of the suite, into `buf` (the Go side's `suite()`).
fn suiteMsg(i: usize, buf: []u8) struct { text: bool, data: []u8 } {
    if (i == suite_count - 1) {
        @memcpy(buf[0..suite_utf8.len], suite_utf8);
        return .{ .text = true, .data = buf[0..suite_utf8.len] };
    }
    const text = i % 2 == 0;
    return .{ .text = text, .data = pattern(buf[0..suite_lens[i / 2]], text) };
}

// ── the records `GET /report` returns ──────────────────────────────────────

const Rec = struct {
    id: [96]u8 = undefined,
    id_len: usize = 0,
    line: [256]u8 = undefined,
    line_len: usize = 0,
};

var recs: [1024]Rec = @splat(.{});
var rec_n: usize = 0;
var rec_lock: std.atomic.Mutex = .unlocked;

fn lockRecs() void {
    while (!rec_lock.tryLock()) std.atomic.spinLoopHint();
}

fn put(id: []const u8, comptime fmt: []const u8, args: anytype) void {
    lockRecs();
    defer rec_lock.unlock();
    if (rec_n >= recs.len) return;
    const r = &recs[rec_n];
    const n = @min(id.len, r.id.len);
    @memcpy(r.id[0..n], id[0..n]);
    r.id_len = n;
    r.line_len = if (std.fmt.bufPrint(&r.line, fmt, args)) |s| s.len else |_| 0;
    rec_n += 1;
}

fn lookup(id: []const u8, out: []u8) ?[]const u8 {
    lockRecs();
    defer rec_lock.unlock();
    for (recs[0..rec_n]) |*r| {
        if (std.mem.eql(u8, r.id[0..r.id_len], id)) {
            @memcpy(out[0..r.line_len], r.line[0..r.line_len]);
            return out[0..r.line_len];
        }
    }
    return null;
}

// ── the server ─────────────────────────────────────────────────────────────

fn queryValue(query: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        if (kv.len > name.len and std.mem.startsWith(u8, kv, name) and kv[name.len] == '=') return kv[name.len + 1 ..];
    }
    return null;
}

const Kind = enum { echo, ping, close, frag, other };

const Handler = struct {
    conn: *ws.Conn,
    kind: Kind,
    id_buf: [96]u8 = undefined,
    id_len: usize = 0,
    close_code: ?u16 = null,
    close_arg: u16 = 1000,
    msgs: usize = 0,
    bad: bool = false,
    proto: []const u8 = "-",
    ext: u8 = '0',
    ponged: bool = false,

    pub fn init(h: *ws.Handshake, conn: *ws.Conn, _: void) !Handler {
        const q = std.mem.indexOfScalar(u8, h.url, '?');
        const path = if (q) |i| h.url[0..i] else h.url;
        const query = if (q) |i| h.url[i + 1 ..] else "";
        var self: Handler = .{ .conn = conn, .kind = .other };
        const id = queryValue(query, "case") orelse "-";
        self.id_len = @min(id.len, self.id_buf.len);
        @memcpy(self.id_buf[0..self.id_len], id[0..self.id_len]);
        if (std.mem.eql(u8, path, "/echo") or std.mem.eql(u8, path, "/deflate")) self.kind = .echo;
        if (std.mem.eql(u8, path, "/ping")) self.kind = .ping;
        if (std.mem.eql(u8, path, "/frag") or std.mem.eql(u8, path, "/frag-deflate")) self.kind = .frag;
        if (std.mem.startsWith(u8, path, "/close/")) {
            self.kind = .close;
            self.close_arg = std.fmt.parseInt(u16, path["/close/".len..], 10) catch 1000;
        }
        // The library never accepts the offer (its compression is disabled in the Zig 0.17 branch):
        // the 101 carries no extension, whatever the client offered.
        self.ext = '0';
        // The library selects no subprotocol: the first offered one of ours
        // (the order the client gave), as coder does.
        if (h.headers.get("sec-websocket-protocol")) |offer| {
            var it = std.mem.tokenizeAny(u8, offer, ", ");
            while (it.next()) |p| {
                if (std.mem.eql(u8, p, "chat")) {
                    h.res_headers.add("sec-websocket-protocol", "chat");
                    self.proto = "chat";
                    break;
                }
                if (std.mem.eql(u8, p, "echo")) {
                    h.res_headers.add("sec-websocket-protocol", "echo");
                    self.proto = "echo";
                    break;
                }
            }
        }
        return self;
    }

    pub fn afterInit(self: *Handler) !void {
        switch (self.kind) {
            .ping => {
                var p = "zl-ping".*;
                try self.conn.writePing(&p);
            },
            .close => try self.conn.close(.{ .code = self.close_arg, .reason = "zl-bye" }),
            .frag => {
                // Four text fragments of 1024 bytes, unmasked (server frames).
                var body: [frag_len]u8 = undefined;
                _ = pattern(&body, true);
                for (0..4) |i| {
                    var fr: [4 + 1024]u8 = undefined;
                    fr[0] = (if (i == 3) @as(u8, 0x80) else 0) | (if (i == 0) @as(u8, 1) else 0);
                    fr[1] = 126;
                    std.mem.writeInt(u16, fr[2..4], 1024, .big);
                    @memcpy(fr[4..], body[i * 1024 ..][0..1024]);
                    try self.conn.writeFramed(&fr);
                }
            },
            else => {},
        }
    }

    pub fn clientMessage(self: *Handler, data: []u8, tpe: ws.MessageTextType) !void {
        self.msgs += 1;
        switch (self.kind) {
            .frag => if (self.msgs == 1) {
                var body: [frag_len]u8 = undefined;
                _ = pattern(&body, true);
                if (tpe != .text or !std.mem.eql(u8, data, &body)) {
                    self.bad = true;
                    return error.BadEcho;
                }
            },
            else => {},
        }
        switch (tpe) {
            .text => try self.conn.writeText(data),
            .binary => try self.conn.writeBin(data),
        }
    }

    pub fn clientPong(self: *Handler, data: []u8) !void {
        if (self.kind != .ping or self.ponged) return;
        self.ponged = true;
        var buf: [64]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, "ping-ok:{s}", .{data}) catch "ping-err";
        try self.conn.writeText(s);
    }

    /// The peer's close frame: record its code and answer with the same one.
    pub fn clientClose(self: *Handler, data: []u8) !void {
        self.close_code = if (data.len >= 2) std.mem.readInt(u16, data[0..2], .big) else 1005;
        if (data.len >= 2) try self.conn.close(.{ .code = self.close_code.? }) else try self.conn.close(.{});
    }

    pub fn close(self: *Handler) void {
        const id = self.id_buf[0..self.id_len];
        if (self.bad) {
            put(id, "closed=err:bad_echo proto={s} ext={c}", .{ self.proto, self.ext });
        } else if (self.kind == .close) {
            put(id, "closed=ok proto={s} ext={c}", .{ self.proto, self.ext });
        } else if (self.close_code) |c| {
            put(id, "closed={d} msgs={d} proto={s} ext={c}", .{ c, self.msgs, self.proto, self.ext });
        } else {
            put(id, "closed=err:eof msgs={d} proto={s} ext={c}", .{ self.msgs, self.proto, self.ext });
        }
    }
};

const ReportCtx = struct { io: std.Io, port: u16 };

/// A one-request-per-connection HTTP listener: `GET /report?case=<id>` answers
/// the record (waiting up to 5 s for it), as the Go oracle does.
fn reportLoop(ctx: ReportCtx) void {
    const io = ctx.io;
    var l = std.Io.net.IpAddress.listen(&.{ .ip4 = .loopback(ctx.port) }, io, .{ .reuse_address = true }) catch return;
    while (true) {
        const s = l.accept(io) catch return;
        defer s.close(io);
        var rbuf: [2048]u8 = undefined;
        var wbuf: [512]u8 = undefined;
        var sr = s.reader(io, &rbuf);
        var sw = s.writer(io, &wbuf);
        const line = (sr.interface.takeDelimiter('\n') catch continue) orelse continue;
        const q = std.mem.indexOf(u8, line, "case=") orelse continue;
        const rest = line[q + 5 ..];
        const end = std.mem.indexOfAny(u8, rest, " &\r") orelse rest.len;
        const id = rest[0..end];
        var out: [256]u8 = undefined;
        var got: []const u8 = "none";
        var waited: u32 = 0;
        while (waited < 5000) : (waited += 5) {
            if (lookup(id, &out)) |r| {
                got = r;
                break;
            }
            io.sleep(.fromMilliseconds(5), .awake) catch {};
        }
        sw.interface.print("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}\n", .{ got.len + 1, got }) catch continue;
        sw.interface.flush() catch {};
    }
}

fn serveMain(init: std.process.Init, port: u16, report_port: u16) !void {
    const t = try std.Thread.spawn(.{}, reportLoop, .{ReportCtx{ .io = init.io, .port = report_port }});
    t.detach();
    var server = try ws.Server(Handler).init(init.io, init.gpa, .{
        .port = port,
        .address = "127.0.0.1",
        .max_message_size = max_msg,
        .buffers = .{ .small_size = 4096, .large_size = max_msg },
        .handshake = .{ .timeout = 3, .max_size = 2048, .max_headers = 8 },
    });
    var out: [96]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(init.io, &out);
    try w.interface.print("READY ks={d} report={d}\n", .{ port, report_port });
    try w.interface.flush();
    try server.listen({});
}

// ── the client ─────────────────────────────────────────────────────────────

fn clientMain(init: std.process.Init, url: []const u8, scenario: []const u8, out: *std.Io.Writer) !void {
    const gpa = init.gpa;
    const prefix = "ws://127.0.0.1:";
    if (!std.mem.startsWith(u8, url, prefix)) return error.BadUrl;
    const rest = url[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return error.BadUrl;
    const port = try std.fmt.parseInt(u16, rest[0..slash], 10);
    const target = rest[slash..];

    var client = try ws.Client.init(init.io, gpa, .{ .port = port, .host = "127.0.0.1", .max_size = max_msg });
    defer client.deinit();
    var hdr: std.Io.Writer.Allocating = .init(gpa);
    defer hdr.deinit();
    try hdr.writer.print("Host: 127.0.0.1:{d}", .{port});
    // An offer the client never uses: the library cannot compress, which RFC
    // 7692 allows (the server may compress, the client may send plain).
    if (std.mem.endsWith(u8, scenario, "deflate")) try hdr.writer.writeAll("\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover");
    if (std.mem.eql(u8, scenario, "subproto")) try hdr.writer.writeAll("\r\nSec-WebSocket-Protocol: chat, echo");
    try client.handshake(target, .{ .timeout_ms = 5000, .headers = hdr.written() });
    try client.readTimeout(20_000);

    if (std.mem.eql(u8, scenario, "echo") or std.mem.eql(u8, scenario, "deflate")) {
        const buf = try gpa.alloc(u8, 1 << 20);
        defer gpa.free(buf);
        for (0..suite_count) |i| {
            const m = suiteMsg(i, buf);
            const want = try gpa.dupe(u8, m.data);
            defer gpa.free(want);
            if (m.text) try client.writeText(m.data) else try client.writeBin(m.data);
            const r = (try client.read()) orelse return out.print("err read {d}: timeout\n", .{i});
            defer client.done(r);
            const same_type = (r.type == .text and m.text) or (r.type == .binary and !m.text);
            if (!same_type or !std.mem.eql(u8, r.data, want))
                return out.print("err echo {d} differs (len {d}, want {d})\n", .{ i, r.data.len, want.len });
        }
        if (try closeAndWait(&client, 1000, "")) |e| return out.print("err {s}\n", .{e});
        return out.print("ok msgs={d}\n", .{suite_count});
    }
    if (std.mem.startsWith(u8, scenario, "frag")) {
        var body: [frag_len]u8 = undefined;
        _ = pattern(&body, true);
        // The server's fragmented message first (the library reassembles it),
        // then ours back, in four masked frames written by hand.
        const r = (try client.read()) orelse return out.print("err read: timeout\n", .{});
        if (r.type != .text or !std.mem.eql(u8, r.data, &body)) {
            client.done(r);
            return out.print("err server message differs\n", .{});
        }
        client.done(r);
        const mk = [4]u8{ 0x37, 0xfa, 0x21, 0x3d };
        for (0..4) |i| {
            var fr: [8 + 1024]u8 = undefined;
            fr[0] = (if (i == 3) @as(u8, 0x80) else 0) | (if (i == 0) @as(u8, 1) else 0);
            fr[1] = 0x80 | 126;
            std.mem.writeInt(u16, fr[2..4], 1024, .big);
            @memcpy(fr[4..8], &mk);
            for (0..1024) |j| fr[8 + j] = body[i * 1024 + j] ^ mk[j % 4];
            try client.stream.writeAll(&fr);
        }
        if (try closeAndWait(&client, 1000, "")) |e| return out.print("err {s}\n", .{e});
        return out.print("ok msgs=1\n", .{});
    }
    if (std.mem.eql(u8, scenario, "ping")) {
        var p = "zl-ping".*;
        try client.writePing(&p);
        while (true) {
            const r = (try client.read()) orelse return out.print("err no pong\n", .{});
            defer client.done(r);
            if (r.type == .pong) {
                if (!std.mem.eql(u8, r.data, "zl-ping")) return out.print("err pong payload {s}\n", .{r.data});
                break;
            }
        }
        if (try closeAndWait(&client, 1000, "")) |e| return out.print("err {s}\n", .{e});
        return out.print("ok pong\n", .{});
    }
    if (std.mem.eql(u8, scenario, "sping")) {
        // A manual read loop: the library answers no ping for the caller here.
        while (true) {
            const r = (try client.read()) orelse return out.print("err read: timeout\n", .{});
            defer client.done(r);
            switch (r.type) {
                .ping => {
                    const copy = try gpa.dupe(u8, r.data);
                    defer gpa.free(copy);
                    try client.writePong(copy);
                },
                .text => {
                    if (!std.mem.startsWith(u8, r.data, "ping-ok")) return out.print("err server says {s}\n", .{r.data});
                    const said = try gpa.dupe(u8, r.data);
                    defer gpa.free(said);
                    if (try closeAndWait(&client, 1000, "")) |e| return out.print("err {s}\n", .{e});
                    return out.print("ok {s}\n", .{said});
                },
                else => {},
            }
        }
    }
    if (std.mem.eql(u8, scenario, "close")) {
        if (try closeAndWait(&client, 4001, "zl-client-bye")) |e| return out.print("err {s}\n", .{e});
        return out.print("ok closed\n", .{});
    }
    if (std.mem.eql(u8, scenario, "servclose")) {
        while (true) {
            const r = (try client.read()) orelse return out.print("err read: timeout\n", .{});
            defer client.done(r);
            if (r.type == .close) {
                if (r.data.len < 2) return out.print("ok code=1005 reason=\n", .{});
                // Answer it (the library's `close` would only shut the socket).
                const echo = try gpa.dupe(u8, r.data);
                defer gpa.free(echo);
                client.writeFrame(.close, echo) catch {};
                return out.print("ok code={d} reason={s}\n", .{ std.mem.readInt(u16, r.data[0..2], .big), r.data[2..] });
            }
        }
    }
    if (std.mem.eql(u8, scenario, "subproto")) {
        if (try closeAndWait(&client, 1000, "")) |e| return out.print("err {s}\n", .{e});
        return out.print("ok\n", .{});
    }
    return out.print("err unknown scenario {s}\n", .{scenario});
}

/// Send a close frame (the library's own `close` would also shut the socket)
/// and read until the peer's close arrives, which must carry the same code.
/// Null when it did.
fn closeAndWait(client: *ws.Client, code: u16, reason: []const u8) !?[]const u8 {
    var buf: [125]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], code, .big);
    @memcpy(buf[2..][0..reason.len], reason);
    try client.writeFrame(.close, buf[0 .. 2 + reason.len]);
    while (true) {
        const r = (try client.read()) orelse return "close echo: timeout";
        defer client.done(r);
        if (r.type == .close) {
            if (r.data.len < 2 or std.mem.readInt(u16, r.data[0..2], .big) != code) return "close echo differs";
            return null;
        }
    }
}

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const mode = args.next() orelse return usage();
    if (std.mem.eql(u8, mode, "serve")) {
        const port = try std.fmt.parseInt(u16, args.next() orelse return usage(), 10);
        const rport = try std.fmt.parseInt(u16, args.next() orelse return usage(), 10);
        return serveMain(init, port, rport);
    }
    if (std.mem.eql(u8, mode, "client")) {
        const url = args.next() orelse return usage();
        const scenario = args.next() orelse return usage();
        var obuf: [1024]u8 = undefined;
        var w = std.Io.File.stdout().writerStreaming(init.io, &obuf);
        clientMain(init, url, scenario, &w.interface) catch |err| w.interface.print("err {t}\n", .{err}) catch {};
        try w.interface.flush();
        return;
    }
    return usage();
}

fn usage() error{Usage} {
    std.debug.print("usage: ks_peer serve <port> <report-port> | ks_peer client <ws-url> <scenario>\n", .{});
    return error.Usage;
}
