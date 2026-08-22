// SPDX-License-Identifier: MIT

//! What a monitoring agent does with `icmp`: build/parse the wire codec by
//! hand for one round trip, then drive the `Pinger` scheduler — the layer a
//! real caller actually reaches for — against a target, handling both of
//! its input-validation and privilege errors by name.

const std = @import("std");
const icmp = @import("icmp");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── the wire codec, standalone ──────────────────────────────────────
    // Build an echo request the way a hand-rolled prober would, then decode
    // the reply a peer would send back — round-tripping through the same
    // RFC 1071 checksum the kernel checks on the way in.
    var req: [icmp.echo.echo_header_len]u8 = undefined;
    // The writer reports a short buffer rather than asserting, so a consumer
    // has to acknowledge it. `&req` is an array pointer of exactly the header
    // length, so the branch is unreachable here -- but it is nameable, which
    // an assert compiled out of ReleaseFast never was.
    icmp.echo.writeEchoRequest(.v4, &req, 0xbeef, 1) catch |err| switch (err) {
        error.BufferTooSmall => unreachable,
    };

    // Simulate the peer's answer: same packet, type flipped to echo_reply,
    // checksum recomputed (the only two octets that legitimately change).
    var reply = req;
    reply[0] = icmp.echo.v4.echo_reply;
    reply[2] = 0;
    reply[3] = 0;
    std.mem.writeInt(u16, reply[2..4], icmp.echo.checksum(&reply), .big);

    switch (icmp.echo.parseV4(&reply, false)) {
        .echo_reply => |r| std.debug.print("parsed echo_reply: ident=0x{x} seq={d}\n", .{ r.ident, r.seq }),
        .icmp_error, .ignored => std.debug.print("unexpected: reply not recognised as echo_reply\n", .{}),
    }

    // ── the scheduler, as a real caller drives it ───────────────────────
    var pinger = try icmp.Pinger.init(gpa, .{
        .mode = .count,
        .count = 1,
        .timeout_ns = 200 * std.time.ns_per_ms,
    });
    defer pinger.deinit();

    // A malformed target: the parse error must be nameable from outside so
    // a caller can reject bad config before ever opening a socket.
    if (pinger.addTarget("not-an-ip-address")) |_| {
        std.debug.print("unexpected: bad address accepted\n", .{});
    } else |err| switch (err) {
        error.InvalidAddress => std.debug.print("addTarget(\"not-an-ip-address\"): InvalidAddress (expected)\n", .{}),
        error.OutOfMemory => return err,
    }

    const id = try pinger.addTarget("127.0.0.1");

    // `run()` needs an unprivileged DGRAM ping socket (ping_group_range) or
    // CAP_NET_RAW; a locked-down sandbox has neither, and that has to be a
    // nameable outcome rather than a crash.
    if (pinger.run()) |_| {
        const st = pinger.stats(id);
        std.debug.print("127.0.0.1: sent={d} recv={d} alive={}\n", .{ st.sent, st.recv, st.alive() });
    } else |err| switch (err) {
        error.PermissionDenied => std.debug.print("run(): PermissionDenied (no ping_group_range / CAP_NET_RAW here)\n", .{}),
        else => return err,
    }
}
