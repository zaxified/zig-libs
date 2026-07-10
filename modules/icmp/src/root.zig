// SPDX-License-Identifier: MIT
//! icmp — ICMP echo (ping) engine: wire codec, unprivileged/raw sockets and
//! a paced multi-target prober.
//!
//! Derived from fping (schweikert/fping) — see NOTICE for the required
//! attribution. Three layers:
//!
//!  * `echo` — pure ICMPv4/v6 echo + timestamp codec with the RFC 1071
//!    internet checksum; bounds-checked parsing that never panics.
//!  * `Socket` — non-blocking Linux ICMP sockets: unprivileged SOCK_DGRAM
//!    first (net.ipv4.ping_group_range), SOCK_RAW fallback (CAP_NET_RAW);
//!    sendmmsg/recvmmsg batching, kernel receive timestamps, TTL/TOS.
//!  * `Pinger` — fping's main_loop as a library: global send pacing,
//!    in-flight cap, per-subnet spacing, retries with timeout backoff, and
//!    reply correlation via the sibling `seqmap` module.
//!
//! Linux-only by design (errno-encoded `std.os.linux` raw syscalls, no
//! libc). Addresses come from and go to the sibling `netaddr` module.
//!
//! Basic usage:
//!
//! ```zig
//! const icmp = @import("icmp");
//!
//! var pinger = try icmp.Pinger.init(allocator, .{
//!     .mode = .count,
//!     .count = 3,
//!     .interval_ns = 5 * std.time.ns_per_ms,
//! });
//! defer pinger.deinit();
//!
//! const id = try pinger.addTarget("192.0.2.1");
//! try pinger.run();
//! const st = pinger.stats(id); // sent/recv/min/avg/max RTT, loss
//! ```

const std = @import("std");

pub const meta = .{
    .platform = .linux, // raw syscalls (ICMP sockets), no portable fallback
    .role = .client,
    .concurrency = .single_owner, // one thread/loop owns a Pinger (stop() is signal-safe)
    .model_after = "fping (schweikert/fping)",
    .deps = .{ "seqmap", "netaddr" },
};

// ── public API ──────────────────────────────────────────────────────────────

/// Pure ICMP echo/timestamp wire codec (build/parse + internet checksum).
pub const echo = @import("echo.zig");

/// Non-blocking ICMP socket (unprivileged DGRAM with RAW fallback).
pub const Socket = @import("Socket.zig");

const pinger = @import("pinger.zig");

pub const Pinger = pinger.Pinger;
pub const Config = pinger.Config;
pub const Mode = pinger.Mode;
pub const Stats = pinger.Stats;
pub const ReplyInfo = pinger.ReplyInfo;
pub const Addr = pinger.Addr;
pub const Outcome = pinger.Outcome;
pub const ResultFn = pinger.ResultFn;
pub const TargetId = pinger.TargetId;
pub const RunError = pinger.RunError;
/// CLOCK_MONOTONIC now, in ns — the clock all engine timestamps use.
pub const monoNow = pinger.monoNow;

test {
    std.testing.refAllDecls(@This());
}
