// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: it drives the module's real `query` -- socket, receive loop,
// deadline and all -- against `stub.py` on loopback. The unit tests reach
// `processReply`/`validateReply` directly and deliberately skip the socket;
// this is the only thing that exercises the path a caller actually takes, and
// it does so without touching a public NTP server.
//
// It also measures ELAPSED time, which is how the "the timeout bounds the whole
// run, not one receive step" claim is checked: `wrongport` must end at the
// deadline, and `flood_then_correct` must succeed quickly despite 2000 decoy
// datagrams arriving first.
//
// WHAT IT NEEDS: the live module and a running `stub.py`. `run_scenarios.sh`
// wires the two together.
//
//   client <ip> <port> <timeout_ms>
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseSafe --dep sntp \
//       -Mmain=client.zig -Msntp=../src/root.zig \
//       --cache-dir <scratch>/zc-client -femit-bin=<scratch>/client

const std = @import("std");
const sntp = @import("sntp");

pub fn main(init: std.process.Init.Minimal) !u8 {
    var it = init.args.iterate();
    _ = it.next();
    const ip = it.next() orelse return usage();
    const port = try std.fmt.parseInt(u16, it.next() orelse return usage(), 10);
    const tmo = try std.fmt.parseInt(u32, it.next() orelse return usage(), 10);

    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    var threaded: std.Io.Threaded = .init(da.allocator(), .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse(ip, port);
    var kiss: sntp.KissOfDeath = undefined;

    var t0: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &t0);
    const res = sntp.query(io, addr, .{ .timeout_ms = tmo }, &kiss);
    var t1: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &t1);
    const elapsed_ms = (@as(i64, t1.sec - t0.sec) * 1000) + @divTrunc(@as(i64, t1.nsec - t0.nsec), 1_000_000);

    if (res) |r| {
        const off_s = @as(f64, @floatFromInt(r.offset_ns)) / 1e9;
        std.debug.print("ACCEPTED elapsed={d}ms stratum={d} leap={t} offset_ns={d} ({d:.3} s = {d:.2} days) delay_ns={d}\n", .{
            elapsed_ms, r.reply.stratum, r.reply.leap, r.offset_ns, off_s, off_s / 86400.0, r.roundtrip_ns,
        });
    } else |e| {
        std.debug.print("REJECTED elapsed={d}ms err={t}", .{ elapsed_ms, e });
        if (e == error.KissOfDeath) std.debug.print(" kiss={t} raw={s}", .{ kiss.code, kiss.raw });
        std.debug.print("\n", .{});
    }
    return 0;
}

fn usage() u8 {
    std.debug.print("usage: client <ip> <port> <timeout_ms>\n", .{});
    return 2;
}
