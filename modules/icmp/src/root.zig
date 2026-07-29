// SPDX-License-Identifier: MIT
//! icmp — ICMP echo (ping) engine: wire codec, unprivileged/raw sockets and
//! a paced multi-target prober.
//!
//! Clean-room from RFC 792 / RFC 4443 / RFC 1071 and ip(7)/ipv6(7); the
//! prober's scheduling design references fping (schweikert/fping) — see
//! NOTICE §2 for the provenance record. Three layers:
//!
//!  * `echo` — pure ICMPv4/v6 echo + timestamp codec with the RFC 1071
//!    internet checksum; bounds-checked parsing that never panics.
//!  * `Socket` — non-blocking Linux ICMP sockets: unprivileged SOCK_DGRAM
//!    first (net.ipv4.ping_group_range), SOCK_RAW fallback (CAP_NET_RAW);
//!    sendmmsg/recvmmsg batching, kernel receive timestamps, TTL/TOS.
//!  * `Pinger` — a paced multi-target scheduler as a library, following
//!    fping's main-loop design: global send pacing,
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
    .model_after = "RFC 792/4443/1071 (codec) + ip(7)/ipv6(7) (sockets); scheduler design ref: fping (schweikert/fping), behavior only",
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
