// SPDX-License-Identifier: MIT

//! simio — a deterministic `std.Io` for simulation testing.
//!
//! Code written against `std.Io` runs unchanged on simulated hosts: every task
//! is a fiber on one OS thread, time is virtual, and every choice the
//! simulator makes is drawn from one seed, so a run is a pure function of that
//! seed and replays exactly. The network, the file system and fault injection
//! build on `netsim` (see SPEC.md for the milestones; this is M1, the
//! scheduler: tasks, groups, cancelation, futex, clocks, sleep, randomness).
//!
//! ```zig
//! var sim: simio.Sim = undefined;
//! sim.init(gpa, .{ .seed = 7 });
//! defer sim.deinit();
//! const host = try sim.addHost(.{});
//! try host.spawn(myServerMain, .{ host.io() });
//! const r = sim.run();          // .quiescent / .deadlock / .step_limit
//! ```

const std = @import("std");
const sched = @import("sched.zig");

pub const meta = .{
    .doc = "Deterministic std.Io for simulation testing — fibers on one thread, virtual time, seeded scheduling; real std.Io code runs unchanged (network/FS on netsim in progress)",
    .platform_note = "linux (x86_64, aarch64, riscv64: std.Io.fiber)",
    .targets = .{.linux64},
    .platform = .linux,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "tokio-rs/turmoil, madsim, FoundationDB simulation",
    .deps = .{"netsim"},
};

pub const Sim = sched.Sim;
pub const Host = sched.Host;
pub const Options = sched.Options;
pub const HostOptions = sched.HostOptions;
pub const Outcome = sched.Outcome;
pub const RunResult = sched.RunResult;

test {
    _ = @import("stack.zig");
    _ = @import("sched.zig");
    _ = @import("vtable.zig");
    _ = @import("tests.zig");
}
