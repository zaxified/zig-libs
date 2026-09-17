// SPDX-License-Identifier: MIT

//! Differential probe for `oracle_handshake.py` (`CONVENTIONS.md` §9): drives
//! this module's PUBLIC handshake API — `handshake.verifyResponse` (client
//! side) and `handshake.acceptHandshake` (server side) — over the same fixed
//! case table `oracle_handshake.py` feeds to python-websockets 15.0.1's
//! `ClientProtocol`/`ServerProtocol`, and prints one verdict line per case.
//! The Python side runs the real foreign implementation and compares.
//!
//! Builds against `handshake.zig`'s public functions only — no module source
//! is copied here, just literal RFC 6455 wire bytes matching the Python
//! oracle's own case table 1:1 (same key, same accept value, same headers).

const std = @import("std");
const websocket = @import("websocket");
const http = @import("http");
const h1 = http.h1;
const handshake = websocket.handshake;

// RFC 6455 §1.3 worked example nonce/accept pair — same as the Python oracle.
const KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const ACC = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

const Case = struct {
    name: []const u8,
    raw: []const u8,
};

// ── client side: verifyResponse over a 101 response ────────────────────────
const client_cases = [_]Case{
    .{ .name = "baseline 101", .raw = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: " ++ ACC ++ "\r\n" ++
        "\r\n" },
    .{ .name = "+ Sec-WebSocket-Extensions: permessage-deflate", .raw = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: " ++ ACC ++ "\r\n" ++
        "Sec-WebSocket-Extensions: permessage-deflate\r\n" ++
        "\r\n" },
    .{ .name = "+ Sec-WebSocket-Extensions: x-made-up", .raw = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: " ++ ACC ++ "\r\n" ++
        "Sec-WebSocket-Extensions: x-made-up\r\n" ++
        "\r\n" },
    .{ .name = "+ Sec-WebSocket-Protocol: chat (never offered)", .raw = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: " ++ ACC ++ "\r\n" ++
        "Sec-WebSocket-Protocol: chat\r\n" ++
        "\r\n" },
    .{ .name = "Accept x2 (right then wrong)", .raw = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: " ++ ACC ++ "\r\n" ++
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n" ++
        "\r\n" },
    .{ .name = "Upgrade x2 (websocket then h2c)", .raw = "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Upgrade: h2c\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: " ++ ACC ++ "\r\n" ++
        "\r\n" },
};

// ── server side: acceptHandshake over a GET upgrade request ────────────────
const server_cases = [_]Case{
    .{ .name = "baseline GET upgrade", .raw = "GET / HTTP/1.1\r\n" ++
        "Host: h\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: " ++ KEY ++ "\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n" },
    .{ .name = "Sec-WebSocket-Key x2", .raw = "GET / HTTP/1.1\r\n" ++
        "Host: h\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: " ++ KEY ++ "\r\n" ++
        "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "\r\n" },
    .{ .name = "Sec-WebSocket-Version: 13, 8", .raw = "GET / HTTP/1.1\r\n" ++
        "Host: h\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: " ++ KEY ++ "\r\n" ++
        "Sec-WebSocket-Version: 13, 8\r\n" ++
        "\r\n" },
    .{ .name = "Origin: https://evil.example", .raw = "GET / HTTP/1.1\r\n" ++
        "Host: h\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: " ++ KEY ++ "\r\n" ++
        "Sec-WebSocket-Version: 13\r\n" ++
        "Origin: https://evil.example\r\n" ++
        "\r\n" },
};

pub fn main() !void {
    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buf);
    const w = &stdout_writer.interface;

    for (client_cases) |c| {
        const head = h1.ResponseHead.parse(c.raw) catch |err| {
            try w.print("client\t{s}\tREJECT\tParse:{s}\n", .{ c.name, @errorName(err) });
            continue;
        };
        // Same offered-protocol set the Python `ClientProtocol` uses: none.
        if (handshake.verifyResponse(head, KEY, &.{})) |_| {
            try w.print("client\t{s}\tACCEPT\t-\n", .{c.name});
        } else |err| {
            try w.print("client\t{s}\tREJECT\t{s}\n", .{ c.name, @errorName(err) });
        }
    }

    for (server_cases) |c| {
        const head = h1.RequestHead.parse(c.raw) catch |err| {
            try w.print("server\t{s}\tREJECT\tParse:{s}\n", .{ c.name, @errorName(err) });
            continue;
        };
        // Same server config the Python `ServerProtocol()` default uses: no
        // subprotocols configured.
        if (handshake.acceptHandshake(head, .{})) |_| {
            try w.print("server\t{s}\tACCEPT\t-\n", .{c.name});
        } else |err| {
            try w.print("server\t{s}\tREJECT\t{s}\n", .{ c.name, @errorName(err) });
        }
    }

    try w.flush();
}
