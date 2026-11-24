// SPDX-License-Identifier: MIT

//! Replay of the official MCP Python SDK's Streamable HTTP exchanges
//! (`sdk_oracle_vectors.zig`, taken by `tools/interop.zig`): every request the
//! SDK sent, in order, goes through this module's `Transport` (sessions
//! configured, over `sdk_oracle_catalog.zig`) and must get the status, the
//! content type and the body the live run gave it, byte for byte. The SDK's
//! typed client accepted those answers, so this pins the transport's wire to
//! what a real client of both eras understands.
//!
//! Not replayed: the exchanges that depend on the live run (a held
//! `subscriptions/listen`, the tools that reach the transport or wait for a
//! cancellation; `sdk_oracle_catalog.live_only`) -- the live run checked them.
//! Session ids are random: a request naming the live run's session names the
//! replay's.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const mcp = @import("mcp");
const root = @import("root.zig");
const catalog = @import("sdk_oracle_catalog.zig");
const vectors = @import("sdk_oracle_vectors.zig");
const testing = std.testing;

fn headerOf(block: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, block, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

fn liveOnly(ex: vectors.Exchange) bool {
    if (std.mem.eql(u8, headerOf(ex.headers, "mcp-method") orelse "", "subscriptions/listen")) return true;
    const name = headerOf(ex.headers, "mcp-name") orelse return false;
    for (catalog.live_only) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

const Answer = struct { status: u16, content_type: []const u8, sid: []const u8, body: []const u8 };

/// Status, content type, session id and the de-chunked body of one response.
fn parse(raw: []const u8, body_out: []u8) !Answer {
    const head_end = std.mem.find(u8, raw, "\r\n\r\n") orelse return error.NoHead;
    const head = raw[0..head_end];
    const status = try std.fmt.parseInt(u16, head[9..12], 10);
    var rest = raw[head_end + 4 ..];
    var n: usize = 0;
    if (std.ascii.eqlIgnoreCase(headerOf(head, "transfer-encoding") orelse "", "chunked")) {
        while (true) {
            const eol = std.mem.find(u8, rest, "\r\n") orelse return error.BadChunk;
            const size = try std.fmt.parseInt(usize, rest[0..eol], 16);
            rest = rest[eol + 2 ..];
            if (size == 0) break;
            @memcpy(body_out[n..][0..size], rest[0..size]);
            n += size;
            rest = rest[size + 2 ..];
        }
    } else {
        @memcpy(body_out[0..rest.len], rest);
        n = rest.len;
    }
    return .{
        .status = status,
        .content_type = headerOf(head, "content-type") orelse "",
        .sid = headerOf(head, "mcp-session-id") orelse "",
        .body = body_out[0..n],
    };
}

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [4096]u8 = undefined;
    var request_body_buf: [4096]u8 = undefined;
    var response_body_buf: [8192]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

test "sdk oracle: the official Python SDK's Streamable HTTP exchanges replay byte for byte" {
    const gpa = testing.allocator;
    var server = mcp.Server.init(gpa, catalog.info);
    defer server.deinit();
    server.push = true;
    try catalog.register(&server, null);
    var sessions = root.Sessions.init(gpa);
    defer sessions.deinit();
    var transport: root.Transport = .{ .gpa = gpa, .server = &server, .sessions = &sessions };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(transport.middleware());

    var live_sid: []const u8 = "";
    var replay_sid_buf: [64]u8 = undefined;
    var replay_sid: []const u8 = "";
    var replayed: usize = 0;
    for (vectors.exchanges, 0..) |ex, i| {
        if (liveOnly(ex)) continue;
        var headers: std.Io.Writer.Allocating = .init(gpa);
        defer headers.deinit();
        var it = std.mem.splitSequence(u8, ex.headers, "\r\n");
        while (it.next()) |line| {
            if (line.len == 0) continue;
            if (std.ascii.startsWithIgnoreCase(line, "mcp-session-id:") and live_sid.len != 0 and
                std.mem.eql(u8, std.mem.trim(u8, line["mcp-session-id:".len..], " "), live_sid))
            {
                try headers.writer.print("Mcp-Session-Id: {s}\r\n", .{replay_sid});
            } else try headers.writer.print("{s}\r\n", .{line});
        }
        const wire = try std.fmt.allocPrint(gpa, "{s} {s} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\n{s}Content-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
            ex.method, ex.target, headers.written(), ex.body.len, ex.body,
        });
        defer gpa.free(wire);
        const out_buf = try gpa.alloc(u8, 64 * 1024);
        defer gpa.free(out_buf);
        const body_buf = try gpa.alloc(u8, 64 * 1024);
        defer gpa.free(body_buf);
        const got = try parse(runWire(&r, wire, out_buf), body_buf);
        if (ex.minted_sid.len != 0) {
            live_sid = ex.minted_sid;
            @memcpy(replay_sid_buf[0..got.sid.len], got.sid);
            replay_sid = replay_sid_buf[0..got.sid.len];
        }
        errdefer std.debug.print("exchange {d} ({s} {s}): got {d} {s}\n{s}\nwant {d} {s}\n{s}\n", .{
            i, ex.method, ex.body, got.status, got.content_type, got.body, ex.status, ex.content_type, ex.response,
        });
        try testing.expectEqual(ex.status, got.status);
        try testing.expectEqualStrings(ex.content_type, got.content_type);
        try testing.expectEqualStrings(ex.response, got.body);
        replayed += 1;
    }
    // Both eras, most of the exchanges: a transcript that lost them would
    // otherwise pass by replaying nothing.
    try testing.expect(replayed >= 20);
}
