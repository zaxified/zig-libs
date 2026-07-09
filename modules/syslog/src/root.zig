// SPDX-License-Identifier: MIT
//! syslog — RFC 5424 syslog message formatter + emitter (UDP / TCP with
//! RFC 6587 octet framing), plus a legacy RFC 3164 (BSD) encoder.
//!
//! Pure codec at the core: build a `Message`, call `.format(writer)` (or
//! `{f}`) to get the exact wire line — correct RFC 3339 millisecond
//! timestamps, real structured-data escaping, per-field RFC 5424 length
//! limits. Timestamps are *injected* (`Timestamp{ .unix_ms }`) so formatting
//! is deterministic and testable with no clock; `nowTimestamp` is the live
//! helper for real use. The `std.Io.net` emitters only touch the network when
//! a caller constructs one.
//!
//!   const syslog = @import("syslog");
//!   var buf: [1024]u8 = undefined;
//!   const line = try syslog.bufPrint(&.{
//!       .facility = .local0, .severity = .info,
//!       .timestamp = syslog.nowTimestamp(),
//!       .hostname = "web-1", .app_name = "api", .msgid = "REQ",
//!       .msg = "served /health 200",
//!   }, &buf);

const std = @import("std");

pub const meta = .{
    .status = .gap,
    .platform = .any,
    .role = .both,
    .concurrency = .reentrant,
    .model_after = "RFC 5424 (+ RFC 6587 framing); design after joelreymont/pz",
    .deps = .{},
};

const message = @import("message.zig");
const bsd_mod = @import("bsd.zig");
const transport = @import("transport.zig");

// ── RFC 5424 core (default surface) ─────────────────────────────────────────

pub const Facility = message.Facility;
pub const Severity = message.Severity;
pub const priority = message.priority;

pub const Timestamp = message.Timestamp;
pub const CalendarTime = message.CalendarTime;
pub const decompose = message.decompose;
pub const writeRfc3339 = message.writeRfc3339;

pub const SdParam = message.SdParam;
pub const SdElement = message.SdElement;
pub const Message = message.Message;
pub const bufPrint = message.bufPrint;

pub const max_hostname = message.max_hostname;
pub const max_app_name = message.max_app_name;
pub const max_procid = message.max_procid;
pub const max_msgid = message.max_msgid;

// ── RFC 3164 (BSD) legacy encoder ───────────────────────────────────────────

pub const bsd = struct {
    pub const Message = bsd_mod.Message;
    pub const bufPrint = bsd_mod.bufPrint;
    pub const max_tag = bsd_mod.max_tag;
};

// ── transport: UDP / TCP emitters + framing helpers ─────────────────────────

pub const UdpEmitter = transport.UdpEmitter;
pub const TcpEmitter = transport.TcpEmitter;
pub const buildDatagram = transport.buildDatagram;
pub const writeOctetCounted = transport.writeOctetCounted;
pub const Options = transport.Options;
pub const default_udp_limit = transport.default_udp_limit;

// ── live clock helper ───────────────────────────────────────────────────────

/// Current wall-clock instant as a `Timestamp` (UTC, `Z`). Uses the posix
/// `clock_gettime(REALTIME)` syscall form (no libc) — `std.time.timestamp`
/// was removed in 0.16. Returns epoch 0 if the clock read fails. Pass
/// `offset_minutes` afterwards if you want a local-offset display.
pub fn nowTimestamp() Timestamp {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS)
        return .{ .unix_ms = 0 };
    const ms = @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
    return .{ .unix_ms = ms };
}

// ── dark-tests aggregator (pull sibling files into the test binary) ─────────

test {
    _ = @import("message.zig");
    _ = @import("bsd.zig");
    _ = @import("transport.zig");
}

test "meta is well-formed" {
    try std.testing.expectEqual(.gap, meta.status);
    try std.testing.expectEqual(.any, meta.platform);
    try std.testing.expectEqual(.both, meta.role);
    try std.testing.expectEqual(.reentrant, meta.concurrency);
}

test "re-exported surface round-trips through bufPrint" {
    const msg = Message{
        .facility = .local0,
        .severity = .info,
        .timestamp = .{ .unix_ms = 1783600496000 },
        .hostname = "web-1",
        .app_name = "api",
        .msgid = "REQ",
        .msg = "ok",
    };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "<134>1 2026-07-09T12:34:56.000Z web-1 api - REQ - ok",
        try bufPrint(&msg, &buf),
    );
}

test "nowTimestamp returns a plausible post-2020 instant" {
    const now = nowTimestamp();
    // 2020-01-01T00:00:00Z in ms; guards against a zeroed/failed clock read.
    try std.testing.expect(now.unix_ms > 1_577_836_800_000);
}
