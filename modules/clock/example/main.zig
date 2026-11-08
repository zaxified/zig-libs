// SPDX-License-Identifier: MIT

//! What a consumer of `clock` does: a small time-dependent type takes a
//! `clock.Clock` with the production default, a test-style driver hands it a
//! `ManualClock` and moves time by hand, and the real OS reads are used for a
//! timing measurement and a Unix timestamp. Checks only what the module
//! documents (monotonic order, units, saturation), not specific clock values.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const clock = @import("clock");

/// A check that survives every optimize mode (the examples are RUN in the
/// lane's mode; a debug-only assert would vanish in ReleaseFast).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

/// The consumer: an idle timeout that expires `limit_ns` after the last touch.
const IdleTimer = struct {
    clock: clock.Clock = .monotonic,
    limit_ns: u64,
    last: u64 = 0,

    fn touch(self: *IdleTimer) void {
        self.last = self.clock.now();
    }

    fn expired(self: *const IdleTimer) bool {
        return self.clock.since(self.last) >= self.limit_ns;
    }
};

pub fn main() !void {
    // 1. Driven by a manual clock: no sleeping, exact control.
    var manual = clock.ManualClock.init(1_000);
    var t: IdleTimer = .{ .clock = manual.clock(), .limit_ns = 5 * std.time.ns_per_s };
    t.touch();
    manual.advance(4 * std.time.ns_per_s);
    must(!t.expired(), @src());
    manual.advance(1 * std.time.ns_per_s);
    must(t.expired(), @src());
    // A clock set back never yields a huge "elapsed": `since` saturates at 0.
    manual.set(0);
    must(!t.expired(), @src());

    // 2. The production default reads the OS monotonic clock.
    var real: IdleTimer = .{ .limit_ns = std.time.ns_per_s };
    real.touch();
    must(!real.expired(), @src());

    // 3. Timing a piece of work and stamping it with wall-clock time.
    const t0 = clock.monotonicNs();
    var acc: u64 = 0;
    for (0..10_000) |i| acc +%= i *% 2654435761;
    std.mem.doNotOptimizeAway(acc);
    const took = clock.elapsedNs(t0, clock.monotonicNs());
    must(took < 10 * std.time.ns_per_s, @src());
    const unix_s = clock.realtimeS();
    must(unix_s > 1_577_836_800, @src()); // after 2020-01-01
    must(@divFloor(clock.realtimeMs(), std.time.ms_per_s) >= unix_s, @src());

    // 4. A wall clock under test control, before the epoch.
    var wall = clock.ManualWallClock.init(-1);
    must(wall.clock().nowS() == -1, @src());

    std.debug.print("clock example: ok (work took {d} ns, unix {d})\n", .{ took, unix_s });
}
