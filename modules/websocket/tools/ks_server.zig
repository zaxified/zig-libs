// SPDX-License-Identifier: MIT

//! One peer of the frozen-corpus oracle (`oracle_ks.py`): karlseguin/websocket.zig's SERVER
//! (MIT, pinned in `tools/README.md`), reading every message and answering none, the way the
//! Go servers of `oracle_go_main.go` do. Prints `READY <port>` and serves until killed.
//!
//!   ks_server <port>
//!
//! The library is not a dependency of zig-libs: clone it outside the repository and compile
//! this file against it as `tools/README.md` shows.

const std = @import("std");
const ws = @import("websocket");

const Handler = struct {
    conn: *ws.Conn,

    pub fn init(_: *ws.Handshake, conn: *ws.Conn, _: void) !Handler {
        return .{ .conn = conn };
    }

    pub fn clientMessage(_: *Handler, _: []const u8) !void {}
};

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const port: u16 = if (args.next()) |a| try std.fmt.parseInt(u16, a, 10) else 9224;

    var server = try ws.Server(Handler).init(init.io, init.gpa, .{
        .port = port,
        .address = "127.0.0.1",
        .max_message_size = 1 << 21, // as the Go oracles' SetReadLimit
        .handshake = .{ .timeout = 3, .max_size = 1024, .max_headers = 0 },
    });
    var out: [64]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(init.io, &out);
    try w.interface.print("READY {d}\n", .{port});
    try w.interface.flush();
    try server.listen({});
}
