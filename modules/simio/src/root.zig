// SPDX-License-Identifier: MIT

//! simio — a deterministic `std.Io` for simulation testing.
//!
//! Code written against `std.Io` runs unchanged on simulated hosts: every task
//! is a fiber on one OS thread, time is virtual, and every choice the
//! simulator makes is drawn from one seed, so a run is a pure function of that
//! seed and replays exactly. The network, the file system and fault injection
//! build on `netsim` (see SPEC.md for the milestones; M1 is the scheduler —
//! tasks, groups, cancelation, futex, clocks, sleep, randomness — and M2 the
//! network: streams, datagrams and ICMP echo over routed, faulty links).
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
    .doc = "Deterministic std.Io for simulation testing — real std.Io code runs unchanged on fibers in virtual time, over simulated streams, datagrams and ICMP on routed faulty links, a crash-consistent disk, host crashes and a shrinking fault search",
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
pub const LinkConfig = @import("net.zig").LinkConfig;
pub const NetOptions = @import("net.zig").NetOptions;
pub const FsOptions = @import("fs.zig").FsOptions;
pub const Fault = sched.Fault;

const search = @import("search.zig");
pub const Case = search.Case;
pub const FaultConfig = search.FaultConfig;
pub const CaseResult = search.CaseResult;
pub const Violation = search.Violation;
pub const Generated = search.Generated;
pub const Failing = search.Failing;
pub const Trace = search.Trace;
pub const TraceEvent = search.TraceEvent;
pub const DiskFault = search.DiskFault;
pub const ShrinkResult = search.ShrinkResult;
pub const run = search.run;
pub const replay = search.replay;
pub const findFailing = search.findFailing;
pub const shrink = search.shrink;
pub const checkDeterminism = search.checkDeterminism;

test {
    _ = @import("stack.zig");
    _ = @import("sched.zig");
    _ = @import("vtable.zig");
    _ = @import("net.zig");
    _ = @import("fs.zig");
    _ = @import("tests.zig");
    _ = @import("net_tests.zig");
    _ = @import("search.zig");
    _ = @import("fault_tests.zig");
    _ = @import("fs_tests.zig");
    _ = @import("pilots/sntp.zig");
    _ = @import("pilots/dns.zig");
    _ = @import("pilots/mqtt.zig");
    _ = @import("pilots/ssh.zig");
    _ = @import("pilots/kv.zig");
}
