// SPDX-License-Identifier: MIT
//
// `uci`: parse cost + peak-live-bytes probe.
//
// Two questions:
//  1. Is `Parser.addOption`'s scan over the section's existing options
//     quadratic in the number of options in ONE section?
//  2. How many bytes of arena does a byte of input buy — measured as PEAK
//     LIVE bytes, not a cumulative counter, since the arena never releases.
//
// ⚠ This is the only way to re-derive the numbers `root.zig`'s `max_total_items`
// doc comment asserts (22x–41.5x amplification, "a 16 MiB file could legally
// cost 371+ MB of RSS"). No test pins peak memory: `total item cap: boundary is
// exact` pins the item COUNT, which is the guard, not the consequence it was
// chosen for. A number nobody can re-derive is a number, not evidence.
//
// The audit kept three further copies of this file (`perf_cap`, `perf_cap2`,
// `perf_quad`) that differed from it in exactly one thing: the size/mode table,
// edited in place. They are one instrument with arguments, and that is what
// this is — the sweep is now argv, so measuring a different range does not
// fork the source again.
//
// Build:
//   zig build-exe -O ReleaseFast --dep uci -Mmain=perf_probe.zig \
//       -Muci=../src/root.zig --cache-dir <scratch>/zc-perf
// Run:
//   ./perf_probe                                  # the default sweep
//   ./perf_probe 250000 500000 1000000            # other sizes
//   ./perf_probe --mode=distinct_key 256000       # one shape only
//
// ⚠ ReleaseFast, not Debug: a bare `zig build-exe` is a Debug build and the
// timings are then a measurement of the debug allocator.

const std = @import("std");
const uci = @import("uci");

/// Allocator wrapper tracking PEAK LIVE bytes (a cumulative total cannot see
/// simultaneity — what matters for a DoS bound is the high-water mark).
const PeakAlloc = struct {
    child: std.mem.Allocator,
    live: usize = 0,
    peak: usize = 0,

    fn allocator(self: *PeakAlloc) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *PeakAlloc = @ptrCast(@alignCast(ctx));
        const p = self.child.rawAlloc(len, a, ra) orelse return null;
        self.live += len;
        if (self.live > self.peak) self.peak = self.live;
        return p;
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const self: *PeakAlloc = @ptrCast(@alignCast(ctx));
        if (!self.child.rawResize(buf, a, new_len, ra)) return false;
        self.live = self.live - buf.len + new_len;
        if (self.live > self.peak) self.peak = self.live;
        return true;
    }
    fn remap(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const self: *PeakAlloc = @ptrCast(@alignCast(ctx));
        const p = self.child.rawRemap(buf, a, new_len, ra) orelse return null;
        self.live = self.live - buf.len + new_len;
        if (self.live > self.peak) self.peak = self.live;
        return p;
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const self: *PeakAlloc = @ptrCast(@alignCast(ctx));
        self.child.rawFree(buf, a, ra);
        self.live -= buf.len;
    }
};

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = std.os.linux.write(1, s.ptr, s.len);
}

const Mode = enum { same_key, distinct_key, one_per_section };

fn build(gpa: std.mem.Allocator, mode: Mode, n: usize) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    if (mode != .one_per_section) try b.appendSlice(gpa, "config t\n");
    for (0..n) |i| {
        switch (mode) {
            // Every line a DIFFERENT key: the scan never short-circuits.
            .distinct_key => {
                var lb: [64]u8 = undefined;
                try b.appendSlice(gpa, try std.fmt.bufPrint(&lb, "\toption k{d} v\n", .{i}));
            },
            // Every line the SAME key: the scan hits on the first entry.
            .same_key => try b.appendSlice(gpa, "\toption k v\n"),
            // Control: one option per section — the per-section option list
            // never grows, so any quadratic term must vanish.
            .one_per_section => {
                var lb: [64]u8 = undefined;
                try b.appendSlice(gpa, try std.fmt.bufPrint(&lb, "config t{d}\n\toption k v\n", .{i}));
            },
        }
    }
    return b.toOwnedSlice(gpa);
}

const default_modes = [_]Mode{ .distinct_key, .same_key, .one_per_section };
const default_sizes = [_]usize{ 1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 64_000, 128_000 };

pub fn main(init: std.process.Init) !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const base = dbg.allocator();

    // ⚠ 0.16 removed `argsAlloc`; the runtime hands us a `process.Args`.
    // Same pattern as `scripts/tz-gen/src/main.zig`.
    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, base);
    defer it.deinit();
    _ = it.next(); // exe name

    var modes: std.ArrayList(Mode) = .empty;
    defer modes.deinit(base);
    var sizes: std.ArrayList(usize) = .empty;
    defer sizes.deinit(base);

    while (it.next()) |a| {
        if (std.mem.startsWith(u8, a, "--mode=")) {
            var mit = std.mem.splitScalar(u8, a["--mode=".len..], ',');
            while (mit.next()) |m| {
                const tag = std.meta.stringToEnum(Mode, m) orelse {
                    out("unknown mode: {s}\n", .{m});
                    return error.BadArgument;
                };
                try modes.append(base, tag);
            }
        } else {
            const n = std.fmt.parseInt(usize, a, 10) catch {
                out("not a size: {s}\n", .{a});
                return error.BadArgument;
            };
            try sizes.append(base, n);
        }
    }

    const use_modes: []const Mode = if (modes.items.len > 0) modes.items else &default_modes;
    const use_sizes: []const usize = if (sizes.items.len > 0) sizes.items else &default_sizes;

    out("mode,options,bytes_in,ms,peak_live_bytes,bytes_per_input_byte\n", .{});

    for (use_modes) |mode| {
        for (use_sizes) |n| {
            const text = try build(base, mode, n);
            defer base.free(text);

            var pa: PeakAlloc = .{ .child = base };
            const gpa = pa.allocator();

            const t0 = nowNs();
            // ⚠ A rejection is a RESULT, not a crash: past `max_total_items`
            // the parser is supposed to refuse, and that boundary is exactly
            // what a large sweep is for. Report it in the row.
            var pkg = uci.parse(gpa, text) catch |e| {
                out("{s},{d},{d},-,-,{s}\n", .{ @tagName(mode), n, text.len, @errorName(e) });
                continue;
            };
            const t1 = nowNs();
            const peak = pa.peak;
            pkg.deinit(gpa);

            const ms = @as(f64, @floatFromInt(t1 - t0)) / 1_000_000.0;
            const ratio = @as(f64, @floatFromInt(peak)) / @as(f64, @floatFromInt(text.len));
            out("{s},{d},{d},{d:.3},{d},{d:.2}\n", .{ @tagName(mode), n, text.len, ms, peak, ratio });
        }
    }
}
