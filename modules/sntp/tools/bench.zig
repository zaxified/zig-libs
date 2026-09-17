// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: two measurements, neither of which any test makes.
//
//   1. Per-reply codec cost (decode, decode+verify+offset+delay, encode).
//      `SPEC.md` and `README.md` state NO performance numbers for this module
//      (checked), so there is nothing to re-derive -- but there is also nothing
//      to notice a regression, and this is the instrument that would.
//   2. Allocation count on the whole `query` path. The audit's anchor was
//      "allocs during call = 0, live delta = 0 B, peak live = 0 B". No test
//      asserts it: the codec's zero-allocation property is provable from the
//      signatures (no `Allocator` parameter anywhere), but `query` takes an
//      `std.Io` and runs a socket, so only running it can show the count.
//
// ⚠ The counting allocator wraps the allocator handed to `std.Io.Threaded`, not
// a `DebugAllocator` used as a meter -- the debug allocator is the child here,
// so its own bookkeeping is not counted as the module's allocations.
//
// ⚠ State the optimize mode when quoting any number from this. A bare
// `zig build-exe` is a Debug build.
//
//   bench <iters>                 # codec only
//   bench <iters> <ip> <port>     # plus the query path against stub.py
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep sntp \
//       -Mmain=bench.zig -Msntp=../src/root.zig \
//       --cache-dir <scratch>/zc-bench -femit-bin=<scratch>/bench

const std = @import("std");
const sntp = @import("sntp");

var sink: u64 = 0;

fn nowNs() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + ts.nsec;
}

/// Counting allocator: peak LIVE bytes, not a cumulative total -- a cumulative
/// counter cannot see simultaneity, and a bound is about the high-water mark.
const Counting = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,
    allocs: usize = 0,
    frees: usize = 0,

    fn allocator(self: *Counting) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, a, ra) orelse return null;
        self.live += len;
        self.allocs += 1;
        if (self.live > self.peak) self.peak = self.live;
        return p;
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(buf, a, new_len, ra)) return false;
        self.live = self.live - buf.len + new_len;
        if (self.live > self.peak) self.peak = self.live;
        return true;
    }
    fn remap(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(buf, a, new_len, ra) orelse return null;
        self.live = self.live - buf.len + new_len;
        self.allocs += 1;
        if (self.live > self.peak) self.peak = self.live;
        return p;
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *Counting = @ptrCast(@alignCast(ctx));
        self.child.rawFree(buf, a, ra);
        self.live -= buf.len;
        self.frees += 1;
    }
};

pub fn main(init: std.process.Init.Minimal) !u8 {
    var it = init.args.iterate();
    _ = it.next();
    const iters: usize = if (it.next()) |a| try std.fmt.parseInt(usize, a, 10) else 5_000_000;

    // A realistic stratum-1 reply: the frozen time.google.com golden bytes.
    const golden = [_]u8{
        0x24, 0x01, 0x00, 0xec, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x07, 0x47, 0x4f, 0x4f, 0x47,
        0xee, 0x18, 0x7a, 0x1c, 0xf6, 0x98, 0x9f, 0x83,
        0xee, 0x18, 0x7a, 0x1c, 0xef, 0x6b, 0x28, 0x00,
        0xee, 0x18, 0x7a, 0x1c, 0xf6, 0x98, 0x9f, 0x84,
        0xee, 0x18, 0x7a, 0x1c, 0xf6, 0x98, 0x9f, 0x86,
    };
    const t1: sntp.Timestamp = .{ .seconds = 3_994_581_532, .fraction = 0xEF6B2800 };
    const t4: sntp.Timestamp = .{ .seconds = 3_994_581_532, .fraction = 0xF9AC1000 };

    for (0..10_000) |_| {
        const r = try sntp.decodeResponse(&golden, null);
        sink +%= r.transmit.fraction;
    }

    var t0 = nowNs();
    for (0..iters) |_| {
        var b = golden;
        std.mem.doNotOptimizeAway(&b);
        const r = sntp.decodeResponse(&b, null) catch unreachable;
        sink +%= r.transmit.fraction +% r.stratum;
    }
    const d_decode = nowNs() - t0;

    t0 = nowNs();
    for (0..iters) |_| {
        var b = golden;
        std.mem.doNotOptimizeAway(&b);
        const r = sntp.decodeResponse(&b, null) catch unreachable;
        sntp.verifyOriginate(r, t1) catch unreachable;
        const s: sntp.Sample = .{ .originate = r.originate, .receive = r.receive, .transmit = r.transmit, .destination = t4 };
        sink +%= @bitCast(@as(i64, @truncate(s.offsetNanos())));
        sink +%= @bitCast(@as(i64, @truncate(s.roundtripDelayNanos())));
    }
    const d_full = nowNs() - t0;

    t0 = nowNs();
    for (0..iters) |_| {
        var out: [sntp.packet_len]u8 = undefined;
        sntp.encodeRequest(&out, t1);
        std.mem.doNotOptimizeAway(&out);
        sink +%= out[47];
    }
    const d_encode = nowNs() - t0;

    std.debug.print("iters={d}\n", .{iters});
    std.debug.print("  decodeResponse            : {d:.2} ns/op\n", .{@as(f64, @floatFromInt(d_decode)) / @as(f64, @floatFromInt(iters))});
    std.debug.print("  decode+verify+offset+delay: {d:.2} ns/op\n", .{@as(f64, @floatFromInt(d_full)) / @as(f64, @floatFromInt(iters))});
    std.debug.print("  encodeRequest             : {d:.2} ns/op\n", .{@as(f64, @floatFromInt(d_encode)) / @as(f64, @floatFromInt(iters))});
    std.debug.print("  sink={d}\n", .{sink});

    // ── allocations on the query path (needs stub.py listening) ─────────────
    if (it.next()) |ip| {
        const port = try std.fmt.parseInt(u16, it.next() orelse return 2, 10);
        var da: std.heap.DebugAllocator(.{}) = .init;
        defer _ = da.deinit();
        var c: Counting = .{ .child = da.allocator() };
        var threaded: std.Io.Threaded = .init(c.allocator(), .{});
        defer threaded.deinit();
        const io = threaded.io();
        const before_allocs = c.allocs;
        const before_live = c.live;
        const before_peak = c.peak;
        const addr = try std.Io.net.IpAddress.parse(ip, port);
        const r = sntp.query(io, addr, .{ .timeout_ms = 2000 }, null);
        std.debug.print("  query: allocs during call = {d}, live delta = {d} B, peak live = {d} B (was {d} B)\n", .{
            c.allocs - before_allocs,
            @as(isize, @intCast(c.live)) - @as(isize, @intCast(before_live)),
            c.peak,
            before_peak,
        });
        if (r) |ok| std.debug.print("  query ok, offset_ns={d}\n", .{ok.offset_ns}) else |e| std.debug.print("  query err={t}\n", .{e});
    }
    return 0;
}
