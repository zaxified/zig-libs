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
    .platform = .any,
    // `.client`, not `.both`: this module FORMATS and SENDS syslog messages
    // and has no receiver — there is no parser and no listener in its public
    // surface (`Message`/`bufPrint`/`UdpEmitter`/`TcpEmitter`/`bsd`). It was
    // classified `.both`, which reads as "also a syslog server" and would put
    // it on the wrong side of any client/server survey.
    .role = .client,
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
    try std.testing.expectEqual(.any, meta.platform);
    try std.testing.expectEqual(.client, meta.role); // sends only; no receiver
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

// External anchor (2026-08-01): a real rsyslogd, both transports.
//
// This exact message was sent for real — via this module's own `UdpEmitter`
// and `TcpEmitter`, not hand-crafted bytes — to a real `rsyslogd 8.2512.0`
// listening on UDP and TCP (RFC 6587 octet-counted) in a throwaway
// unprivileged namespace, and rsyslogd's own independent RFC 5424 parser
// re-rendered every field back correctly on BOTH transports:
//
//   RCVD facility=local3 severity=warning pri=156
//     timereported=[2026-07-09T13:34:56.123+01:00] hostname=[probe-host]
//     appname=[live-probe] procid=[4242] msgid=[ORACLE]
//     structured-data=[[exampleSDID@32473 iut="3" eventSource="Application"
//     eventID="1011"]]
//     msg=[live rsyslogd oracle probe: quotes " backslash \ bracket ] end]
//     protocol=imudp
//   (byte-identical second line, protocol=imtcp)
//
// `timereported` is rsyslogd's own parse of our RFC 3339 TIMESTAMP field
// (distinct from `timegenerated`, the local receipt clock) — so the
// +01:00-shifted, millisecond-precision instant, the PRI arithmetic
// (local3*8+warning = 19*8+4 = 156), the SD element/param syntax (validating
// our escaping didn't corrupt real SD grammar), and the free-text MSG
// containing raw `"`, `\`, `]` bytes all round-tripped through an independent,
// non-`libc`, non-zig-libs parser. This is the frozen wire line that produced
// that result — a true external anchor (see SPEC.md for the full
// investigation, the AppArmor workaround needed to run rsyslogd unprivileged,
// and why this is pinned as a literal rather than re-run live).
test "external anchor: message live-verified by a real rsyslogd (UDP + TCP octet-counted)" {
    const msg = Message{
        .facility = .local3,
        .severity = .warning,
        .timestamp = .{ .unix_ms = 1783600496123, .offset_minutes = 60 },
        .hostname = "probe-host",
        .app_name = "live-probe",
        .procid = "4242",
        .msgid = "ORACLE",
        .structured_data = &.{.{
            .id = "exampleSDID@32473",
            .params = &.{
                .{ .name = "iut", .value = "3" },
                .{ .name = "eventSource", .value = "Application" },
                .{ .name = "eventID", .value = "1011" },
            },
        }},
        .msg = "live rsyslogd oracle probe: quotes \" backslash \\ bracket ] end",
    };
    var buf: [512]u8 = undefined;
    try std.testing.expectEqualStrings(
        "<156>1 2026-07-09T13:34:56.123+01:00 probe-host live-probe 4242 ORACLE " ++
            "[exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] " ++
            "live rsyslogd oracle probe: quotes \" backslash \\ bracket ] end",
        try bufPrint(&msg, &buf),
    );

    // The same bytes, RFC 6587 octet-counted — the exact frame `TcpEmitter`
    // put on the wire to rsyslogd's `imtcp` listener.
    const wire = try bufPrint(&msg, &buf);
    var framed_buf: [600]u8 = undefined;
    var w: std.Io.Writer = .fixed(&framed_buf);
    try writeOctetCounted(&w, wire);
    try std.testing.expectEqualStrings("202 ", w.buffered()[0..4]);
    try std.testing.expectEqual(@as(usize, 202), wire.len);
}
