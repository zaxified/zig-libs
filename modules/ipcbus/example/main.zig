// SPDX-License-Identifier: MIT

//! What a same-host control-plane owner does with `ipcbus`: bind a
//! `Server` on a unix socket, accept one client connection, dispatch the
//! request through application logic, and reply — then show the framing
//! layer correctly refusing an oversized announced frame instead of
//! reading it into an unbounded buffer.
//!
//! ipcbus is "one connection per request" with no internal concurrency, so
//! this example drives client and server from a single thread: a unix
//! stream `connect()` succeeds and queues in the kernel backlog as soon as
//! the peer is listening, even before `acceptOne` is called, so writing the
//! client's request before accepting it does not deadlock.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const ipcbus = @import("ipcbus");
const framing = @import("framing");
const linux = std.os.linux;

/// All application command handling lives in the caller, never in
/// `ipcbus` — this dispatch just uppercases the request into a
/// caller-owned scratch buffer.
fn dispatch(ctx: *[64]u8, req: []const u8, gpa: std.mem.Allocator) anyerror![]const u8 {
    _ = gpa;
    if (req.len > ctx.len) return error.RequestTooLarge;
    for (req, 0..) |c, i| ctx[i] = std.ascii.toUpper(c);
    return ctx[0..req.len];
}

pub fn main() !void {
    // Only `Server.handleOne`'s request-side scratch allocates
    // (`framing.readFrameAlloc`); everything else here is fixed buffers.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const path: [:0]const u8 = "/tmp/zig-libs-example-ipcbus.sock";
    var server = try ipcbus.Server.listen(path);
    defer server.deinit();

    // ── a normal request/reply round trip ───────────────────────────────
    const client_fd = try ipcbus.connectUnix(path);
    defer _ = linux.close(client_fd);

    var cw_buf: [256]u8 = undefined;
    var cw = ipcbus.FdWriter.init(client_fd, &cw_buf);
    try framing.writeFrame(&cw.interface, "hello ipcbus", .{});
    try cw.interface.flush();

    const conn_fd = try server.acceptOne(); // already queued; does not block
    var reply_scratch: [64]u8 = undefined;
    try ipcbus.Server.handleOne(conn_fd, &reply_scratch, dispatch, gpa, .{});

    var cr_buf: [256]u8 = undefined;
    var cr = ipcbus.FdReader.init(client_fd, &cr_buf);
    var reply_buf: [64]u8 = undefined;
    const reply = try framing.readFrame(&cr.interface, &reply_buf, .{});
    std.debug.print("reply: {s}\n", .{reply});

    // ── a second connection, whose announced frame length exceeds the
    //    server's cap — must be rejected by name, never over-read ───────
    const client_fd2 = try ipcbus.connectUnix(path);
    defer _ = linux.close(client_fd2);

    var cw2_buf: [256]u8 = undefined;
    var cw2 = ipcbus.FdWriter.init(client_fd2, &cw2_buf);
    try framing.writeFrame(&cw2.interface, "x" ** 50, .{}); // fine under the default 1 MiB cap
    try cw2.interface.flush();

    const conn_fd2 = try server.acceptOne();
    defer _ = linux.close(conn_fd2);
    var sr_buf: [256]u8 = undefined;
    var sr = ipcbus.FdReader.init(conn_fd2, &sr_buf);
    var small_buf: [8]u8 = undefined;
    _ = framing.readFrame(&sr.interface, &small_buf, .{ .max_frame = 10 }) catch |err| switch (err) {
        error.FrameTooLarge => {
            std.debug.print("oversize frame correctly rejected\n", .{});
            return;
        },
        else => return err,
    };
    return error.ExpectedFrameTooLarge;
}
