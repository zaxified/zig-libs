//! tcplan — compile a hierarchical traffic-shaping topology (site → AP →
//! subscriber, each with committed/ceil rates) into a deterministic, ordered
//! plan of `tc` operations (mq root → per-CPU HTB class trees → CAKE leaves +
//! filters), honouring the cpumap→MQ→per-CPU-HTB alignment invariant. Pure:
//! it produces the plan; the caller executes it via `tc` + `netlink`.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "LibreQoS network.json + ShapedDevices → tc HTB/CAKE plan",
    .deps = .{"tc"},
};

test "smoke" {
    try std.testing.expect(true);
}
