// SPDX-License-Identifier: MIT

//! What a service-reachability consumer does with `probe`: connect-probe a
//! real listener and a real closed port on loopback, then drive the same
//! engine (`probeTcp`/`probeTarget`/`probeMany`) through its public
//! `Connector` seam for the two outcomes this sandboxed, privilege-free,
//! internet-free environment cannot reliably produce live.
//!
//! ⚠ WHAT RAN LIVE VS. WHAT DID NOT, AND WHY:
//!
//!  - **LIVE, for real, over loopback**: `probe.PosixConnector` (the
//!    recommended live connector — no CAP_NET_RAW, no CAP_ANY needed, it is
//!    a plain `SOCK_STREAM` connect) against a real listening socket this
//!    example opens itself (`.up`, with a real measured RTT) and a real
//!    closed port (a socket bound to get an ephemeral port from the kernel,
//!    then closed immediately, so nothing answers — `.refused`, the genuine
//!    kernel RST/ECONNREFUSED path). Both run through `probe.probeMany`,
//!    the real fan-out/aggregation code, not a hand-simulated result.
//!  - **NOT live, by public-seam fixture**: `.timeout`, `.canceled` and a
//!    connector-level `.error` outcome. Reproducing these for real without
//!    root would need either a firewall rule that silently drops SYNs (root
//!    to install), or driving `LiveConnector` through a genuine `std.Io`
//!    cancellation mid-connect (real, but adds cancellation-registry
//!    plumbing disproportionate to what it would additionally prove here —
//!    `probeTcp`'s handling of a `ConnectOutcome` is a straight-through
//!    `Status` copy, see `root.zig`, so the interesting logic is the
//!    copy/aggregation, not how the connector produced the value). Both are
//!    exercised instead by scripting `probe.Connector` — the SAME public
//!    seam `PosixConnector`/`LiveConnector` implement, not a private test
//!    helper — so `probeTcp`/`probeMany`'s real classification and
//!    aggregation code still runs, just fed a controlled outcome. `.canceled`
//!    specifically can never come from `PosixConnector` at all — its live
//!    path's own doc comment marks that arm `unreachable` (raw syscalls sit
//!    outside `std.Io`'s cancellation registry) — so a fixture is the only
//!    way this example can show that value exists and classifies correctly.
//!
//! No privilege is needed anywhere in this module — TCP connect scanning
//! never has been (unlike the raw-socket `traceroute`/`icmp`/`rawsock`
//! family). Every negative case below is asserted by name, never a blanket
//! catch.

const std = @import("std");
const probe = @import("probe");
const linux = std.os.linux;

// ── loopback plumbing this example needs, that the module itself has no
//    reason to publish (probe never opens a listener — it only connects) ──

/// Bind+listen on `127.0.0.1:0` and report the kernel-assigned port. No
/// `accept()` loop is needed: a completed TCP handshake (what makes a
/// connect attempt classify `.up`) only needs the listening socket's own
/// backlog, not an application-level accept.
fn openLoopbackListener() !struct { fd: i32, port: u16 } {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    errdefer _ = linux.close(fd);

    var sa: linux.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.BindFailed;

    var bound: linux.sockaddr.in = undefined;
    var blen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &blen)) != .SUCCESS)
        return error.GetsocknameFailed;

    if (linux.errno(linux.listen(fd, 4)) != .SUCCESS) return error.ListenFailed;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, bound.port) };
}

/// An ephemeral loopback port nothing is listening on: bind a throwaway
/// socket to port 0 (the kernel hands back a free port), then close it
/// again without ever calling `listen`. The very next connect to that port
/// gets a real kernel RST — `ECONNREFUSED`, `probe`'s `.refused`.
fn pickClosedPort() !u16 {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    var sa: linux.sockaddr.in = .{ .port = 0, .addr = @bitCast([4]u8{ 127, 0, 0, 1 }) };
    if (linux.errno(linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in))) != .SUCCESS)
        return error.BindFailed;

    var bound: linux.sockaddr.in = undefined;
    var blen: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    if (linux.errno(linux.getsockname(fd, @ptrCast(&bound), &blen)) != .SUCCESS)
        return error.GetsocknameFailed;
    return std.mem.bigToNative(u16, bound.port);
}

// ── fixture connector: the module's own public `Connector` seam ───────────

/// Scripts one `ConnectOutcome` per host string. Implements `probe.Connector`
/// exactly the way `PosixConnector`/`LiveConnector` do — same public
/// interface, no reach into anything private.
const ScriptedConnector = struct {
    fn connector(self: *ScriptedConnector) probe.Connector {
        return .{ .ctx = self, .connectFn = connectImpl };
    }

    fn connectImpl(_: *anyopaque, target: probe.Target, _: u64) probe.ConnectOutcome {
        if (std.mem.eql(u8, target.host, "timeout.example")) return .{ .status = .timeout };
        if (std.mem.eql(u8, target.host, "canceled.example")) return .{ .status = .canceled };
        if (std.mem.eql(u8, target.host, "error.example"))
            return .{ .status = .@"error", .err_name = "SimulatedFailure" };
        if (std.mem.eql(u8, target.host, "up.example")) return .{ .status = .up, .rtt_ns = 42 };
        return .{ .status = .@"error" };
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── 1. LIVE: a real listener and a real closed port, over PosixConnector ──

    const listener = try openLoopbackListener();
    defer _ = linux.close(listener.fd);
    const closed_port = try pickClosedPort();

    var pc: probe.PosixConnector = .{ .resolve = .literal_only };
    const live_targets = [_]probe.Target{
        .{ .host = "127.0.0.1", .port = listener.port },
        .{ .host = "127.0.0.1", .port = closed_port },
    };
    const live_results = try probe.probeMany(gpa, &live_targets, .{
        .connector = pc.connector(),
        .count = 2, // a second round per target, not just one sample
        .timeout_ms = 500,
    });
    defer probe.freeResults(gpa, live_results);

    for (live_results[0].samples) |s| {
        if (s.kind != .up) return error.ExpectedUp;
        if (s.rtt_ns == null) return error.MissingRtt;
    }
    if (!live_results[0].reachable()) return error.ExpectedReachable;
    for (live_results[1].samples) |s| {
        if (s.kind != .refused) return error.ExpectedRefused;
    }
    if (live_results[1].reachable()) return error.ExpectedUnreachable;
    std.debug.print(
        "live over loopback: 127.0.0.1:{d} up x2 (last rtt={?}ns), 127.0.0.1:{d} refused x2\n",
        .{ listener.port, live_results[0].samples[1].rtt_ns, closed_port },
    );

    // ── 2. FIXTURE: outcomes this environment cannot produce live ─────────

    var sc: ScriptedConnector = .{};
    const fixture_targets = [_]probe.Target{
        .{ .host = "up.example", .port = 1 },
        .{ .host = "timeout.example", .port = 1 },
        .{ .host = "canceled.example", .port = 1 },
        .{ .host = "error.example", .port = 1 },
    };
    const fixture_results = try probe.probeMany(gpa, &fixture_targets, .{
        .connector = sc.connector(),
        .count = 1,
    });
    defer probe.freeResults(gpa, fixture_results);

    if (fixture_results[0].samples[0].kind != .up) return error.WrongKindUp;
    if (fixture_results[1].samples[0].kind != .timeout) return error.WrongKindTimeout;
    if (fixture_results[2].samples[0].kind != .canceled) return error.WrongKindCanceled;
    if (fixture_results[3].samples[0].kind != .@"error") return error.WrongKindError;
    if (!std.mem.eql(u8, fixture_results[3].samples[0].err_name orelse "", "SimulatedFailure"))
        return error.MissingErrName;
    std.debug.print("fixture (public Connector seam): up/timeout/canceled/error all classified correctly\n", .{});

    // `app_check` downgrades a completed connect to `.error` when the
    // application-level check fails — exercised directly via `probeTcp`,
    // the single-attempt layer `probeMany` is built on.
    const RejectCheck = struct {
        fn reject(_: *anyopaque, _: probe.Target) bool {
            return false;
        }
    };
    var reject_ctx: u8 = 0;
    const app_checked = probe.probeTcp(.{ .host = "up.example", .port = 1 }, .{
        .connector = sc.connector(),
        .app_check = .{ .ctx = &reject_ctx, .checkFn = RejectCheck.reject },
    });
    if (app_checked.kind != .@"error") return error.AppCheckShouldDowngrade;
    std.debug.print("app_check: a rejected post-connect check downgrades .up to .error\n", .{});

    // ── 3. a real allocating failure path: probeTarget returns early ──────

    // probeTarget's ONLY allocation is `samples = try gpa.alloc(Result,
    // count)`, before any connect attempt runs (root.zig). A 4-byte backing
    // buffer is far too small for even one `Result`, so this proves the
    // OutOfMemory return is clean and happens before any network attempt —
    // and that this example's own backing allocation is freed regardless.
    const backing = try gpa.alloc(u8, 4);
    defer gpa.free(backing);
    var fba = std.heap.FixedBufferAllocator.init(backing);
    if (probe.probeTarget(fba.allocator(), .{ .host = "up.example", .port = 1 }, .{
        .connector = sc.connector(),
        .count = 4,
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.OutOfMemory => std.debug.print(
            "probeTarget with a 4-byte allocator: OutOfMemory (expected), before any connect was attempted\n",
            .{},
        ),
    }

    // ── 4. named negative cases outside the connector layer ───────────────

    if (probe.Target.parse("host-no-port")) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidHostPort => std.debug.print("Target.parse(\"host-no-port\"): InvalidHostPort (expected)\n", .{}),
    }

    if (probe.probeMany(gpa, &live_targets, .{
        .connector = pc.connector(),
        .max_targets = 1, // the live_targets list above has 2
    })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.TooManyTargets => std.debug.print("probeMany with max_targets=1 over 2 targets: TooManyTargets (expected)\n", .{}),
        error.OutOfMemory => return err,
    }

    std.debug.print("OK: all probe example checks passed\n", .{});
}
