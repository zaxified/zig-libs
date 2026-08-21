// SPDX-License-Identifier: MIT

//! What a server built on `http` does with the module: parse a real
//! HTTP/1.1 request head with the pure wire codec (`h1.RequestHead.parse`,
//! no socket involved), then run the same bytes through the full
//! socket-free serving loop (`Server.serveStream`) with a small routing
//! handler, capturing the response on an in-memory buffer instead of a
//! real connection — exactly the pattern the module's own offline tests
//! use, and the shape a request router built on top of `http` would drive.
//! A second, deliberately malformed head shows the codec failing closed
//! with a nameable error instead of misparsing.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const http = @import("http");

fn handler(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    if (std.mem.eql(u8, req.path, "/hello")) {
        try rw.setHeader("Content-Type", "text/plain");
        var buf: [128]u8 = undefined;
        const body = try std.fmt.bufPrint(&buf, "hello, {s} {s} query={s}\n", .{ req.method.token(), req.path, req.query });
        try rw.writeAll(body);
    } else {
        rw.setStatus(404);
        try rw.writeAll("not found\n");
    }
}

pub fn main() !void {
    // ── pure codec layer: parse a request head with no socket at all ──────
    const good_head = "GET /hello?name=Ada HTTP/1.1\r\nHost: example.com\r\n";
    const parsed = try http.h1.RequestHead.parse(good_head);
    std.debug.print("parsed head: method={s} target={s} host={?s}\n", .{ parsed.method, parsed.target, parsed.host });

    // A header line with no colon is not valid HTTP/1.1 and must fail by a
    // nameable error, not silently drop the field or misparse the block.
    const bad_head = "GET /hello HTTP/1.1\r\nBadHeaderLineNoColon\r\n";
    _ = http.h1.RequestHead.parse(bad_head) catch |err| switch (err) {
        error.MalformedHead => std.debug.print("malformed head correctly rejected\n", .{}),
        error.UnsupportedVersion => return err,
    };

    // ── full request/response cycle, socket-free ──────────────────────────
    const wire_request = "GET /hello?name=Ada HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    var in: std.Io.Reader = .fixed(wire_request);
    var out_buf: [4096]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);

    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;

    http.Server.serveStream(.{
        .handler = handler,
        .server_name = "example/1.0",
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });

    const response = out.buffered();
    std.debug.print("--- response ({d} bytes) ---\n{s}\n", .{ response.len, response });

    // A 404 path through the exact same loop, to show the handler's other
    // branch and the response writer's status line reaching the wire.
    const missing_request = "GET /missing HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    var in2: std.Io.Reader = .fixed(missing_request);
    var out2_buf: [4096]u8 = undefined;
    var out2: std.Io.Writer = .fixed(&out2_buf);
    http.Server.serveStream(.{
        .handler = handler,
        .server_name = "example/1.0",
    }, &in2, &out2, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    std.debug.print("--- 404 status line ---\n{s}\n", .{out2.buffered()[0..std.mem.indexOf(u8, out2.buffered(), "\r\n").?]});
}
