// SPDX-License-Identifier: MIT

//! bench — request-build timings. Off by default; opt in with `TC_BENCH`:
//!
//!   TC_BENCH=1 scripts/modtest tc -Doptimize=ReleaseFast -Dcpu=native
//!
//! ## Why this file exists
//!
//! Written 2026-09-15 to price the F10 fix: `qdisc.appendHtbClassOptions`
//! called `ratespec.calcRateTable` twice per request (once for `rate`, once
//! for `ceil`), and the A1 audit measured that single 256-entry loop at
//! ~98-100% of the whole request's cost. When `ceil`'s clamped rate and
//! cell_log override match `rate`'s -- the common case, since `tc class add
//! ... rate X ceil X` is a frequent invocation and the goldens capture it --
//! the second call is now skipped and its table copied from the first
//! instead. This reports the min wall time of `buildClassSet` for that exact
//! htb rate==ceil shape, so the saving is a number, not a guess.
//!
//! ⛔ A B-side (rate != ceil, no reuse) is reported alongside so a reader can
//! see the fix costs nothing on the path it does not apply to.

const std = @import("std");
const root = @import("root.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "bench (opt-in via TC_BENCH)" {
    if (@import("builtin").target.os.tag == .windows or
        std.testing.environ.getPosix("TC_BENCH") == null) return error.SkipZigTest;

    // Arena, not std.testing.allocator: the DebugAllocator std.testing hands
    // out costs ~5us PER ALLOCATION (measured elsewhere in this campaign,
    // see feedback_measurement_traps), and buildClassSet makes several
    // (ArrayList growth, toOwnedSlice) -- swamping the few-microsecond effect
    // this bench exists to see. Reset (not deinit) between reps to reuse the
    // backing pages without carrying std.testing's alloc-tracking overhead.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const gpa = arena_state.allocator();
    const ps = root.ratespec.golden_psched;

    const S = struct {
        var sink: usize = 0;

        fn buildOne(alloc: std.mem.Allocator, rate: u64, ceil: u64) void {
            const req = root.message.buildClassSet(
                alloc,
                1,
                .add,
                .{ .ifindex = 1, .handle = root.Handle.init(1, 0x40), .parent = root.Handle.init(1, 0) },
                .{ .htb = .{
                    .rate = rate,
                    .ceil = ceil,
                    .prio = 3,
                    .quantum = 3000,
                    .burst = 15 * 1024,
                    .mtu = 1500,
                } },
                ps,
            ) catch @panic("buildClassSet failed");
            sink +%= req.len;
        }
    };

    const reps = 2000;
    var eq: u64 = std.math.maxInt(u64);
    var i: usize = 0;
    while (i < reps) : (i += 1) {
        _ = arena_state.reset(.retain_capacity);
        const t0 = nowNs();
        S.buildOne(gpa, 5_000_000 / 8, 5_000_000 / 8); // rate 5mbit ceil 5mbit (F10's reuse path)
        const dt = nowNs() - t0;
        if (dt < eq) eq = dt;
    }
    var ne: u64 = std.math.maxInt(u64);
    i = 0;
    while (i < reps) : (i += 1) {
        _ = arena_state.reset(.retain_capacity);
        const t0 = nowNs();
        S.buildOne(gpa, 125_000, 250_000); // rate 1mbit ceil 2mbit (no reuse -- both computed)
        const dt = nowNs() - t0;
        if (dt < ne) ne = dt;
    }

    std.debug.print(
        \\
        \\tc buildClassSet htb (min of {d} runs, ns/op)
        \\  rate == ceil (F10 reuse path) {d:>10}
        \\  rate != ceil (no reuse)       {d:>10}
        \\  sink={d}
        \\
    , .{ reps, eq, ne, S.sink });
}
