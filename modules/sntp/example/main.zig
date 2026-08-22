// SPDX-License-Identifier: MIT

//! `sntp-demo` -- something in the spirit of `ntpdate` used for a *query*,
//! never for setting the clock: ask one or more NTP servers what time it is
//! and print the clock offset and round-trip delay in a form a person can
//! read. This tool NEVER sets the system clock -- `sntp` is a query-only
//! codec + client, and `settimeofday`/`clock_settime` are simply never
//! called anywhere in this file. Say it once more where a reader will
//! actually see it: `usage_text` and `banner_text` below repeat it.
//!
//! What a real consumer of the module does, in order: `sntp.query()` opens
//! a UDP socket, sends a client-mode request with T1 stamped from the local
//! clock, and validates the reply before trusting *anything* in it --
//! version, server mode, stratum (the RFC 4330 §5 / RFC 5905 §7.3 discard
//! rules), and a set Transmit Timestamp. Then -- inside `query()` itself,
//! not something a caller has to remember to call separately -- it runs the
//! RFC 4330 §5 origin-timestamp anti-spoof check (`verifyOriginate`): a
//! genuine reply must echo back the 64-bit T1 the client actually sent, so a
//! blind off-path attacker who never observed T1 cannot forge an accepted
//! reply. Only after all of that does `query` hand back an offset/delay a
//! caller can act on.
//!
//! Commit `f1d4dd9` is what this demo exists to show off: the typed
//! Kiss-o'-Death code (`KissOfDeath.code`/`.raw`) with the RFC 5905 §7.4
//! obligations it carries (RATE = back off, DENY/RSTR = stop asking this
//! server ever again), and the rest of the RFC 4330 §5 discard-rule family
//! (bad stratum, an unset Transmit Timestamp). All of it is exercised below
//! both live, against real public servers, and canned -- deliberately
//! hand-built rejects, because provoking a real Kiss-o'-Death would mean
//! abusing a public server's rate limit, which this demo will not do (see
//! the discard-rule section below for exactly which path is which).
//!
//! **Known bound, printed honestly below too:** this module's timestamp
//! arithmetic is only correct inside NTP era 0, which ends 2036-02-07 --
//! SPEC.md and README.md both document this; a tool that prints a
//! time-related number should say so, not silently assume the reader knows.
//!
//! **No DNS:** `sntp`'s `build.zig` line carries no deps beyond std (no
//! `dns` module), so this demo -- built the same way an outside consumer
//! would build it -- accepts IPv4/IPv6 **literal** addresses only, never
//! hostnames. The two default servers below are pinned literals for
//! well-known public stratum-1 services, the same ones this module's own
//! README documents and (for time.google.com) the one its golden test's
//! frozen reply was captured from.
//!
//! Built against the PUBLISHED module (`@import("sntp")`) only.

const std = @import("std");
const sntp = @import("sntp");

const Allocator = std.mem.Allocator;

const usage_text =
    \\sntp-demo -- query one or more NTP servers over SNTP (RFC 4330) and
    \\print the clock offset and round-trip delay. Read-only: this tool
    \\NEVER sets the system clock.
    \\
    \\usage:
    \\  sntp-demo [-t timeout_ms] [-p port] [server_ip ...]
    \\  sntp-demo -h | --help
    \\
    \\  server_ip     literal IPv4 or IPv6 address (this module has no DNS
    \\                dependency, so hostnames are not accepted). If none
    \\                are given, queries two well-known public servers by
    \\                their pinned literal IPs (see this module's README.md).
    \\  -t <ms>       receive timeout per server, in milliseconds (default 3000)
    \\  -p <port>     NTP port to use for every server (default 123)
    \\  -h, --help    this text
    \\
;

const banner_text =
    \\sntp-demo: SNTP (RFC 4330) time query -- read-only. This tool NEVER
    \\calls settimeofday/clock_settime; it only reports what a server said.
    \\Known bound: NTP era 0 ends 2036-02-07T06:28:16 UTC -- this module's
    \\timestamp arithmetic (and every offset/delay below) is correct only
    \\inside that era; see SPEC.md / README.md.
    \\
;

const NamedServer = struct { name: []const u8, ip: []const u8 };

/// Pinned literal IPs, not hostnames -- see the "No DNS" note above.
/// `time.google.com` is the same server the module's own golden test froze
/// a real reply from (src/root.zig, "golden: real SNTP reply captured from
/// time.google.com"); `time.cloudflare.com`'s address is the one already
/// documented in this module's own README.md example.
const default_servers = [_]NamedServer{
    .{ .name = "time.google.com", .ip = "216.239.35.4" },
    .{ .name = "time.cloudflare.com", .ip = "162.159.200.1" },
};

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes this example a leak
    // detector for the module's ownership contract, same as the sibling
    // examples in this repo.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next(); // argv[0]

    var opts = parseArgs(gpa, &args) catch |err| switch (err) {
        error.BadUsage => {
            std.debug.print("{s}", .{usage_text});
            return 1;
        },
        else => return err,
    };
    defer opts.deinit(gpa);

    if (opts.help) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("{s}", .{banner_text});

    runDiscardDemos();

    var ok: usize = 0;
    var attempted: usize = 0;
    if (opts.servers.items.len == 0) {
        std.debug.print("\n-- no server given; querying the built-in defaults --\n", .{});
        for (default_servers) |s| {
            attempted += 1;
            if (try runQuery(io, s.name, s.ip, opts.port, opts.timeout_ms)) ok += 1;
        }
    } else {
        std.debug.print("\n-- live queries --\n", .{});
        for (opts.servers.items) |s| {
            attempted += 1;
            if (try runQuery(io, s, s, opts.port, opts.timeout_ms)) ok += 1;
        }
    }

    std.debug.print("\n{d} of {d} server(s) answered with a usable, validated reply\n", .{ ok, attempted });
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// argument parsing
// ─────────────────────────────────────────────────────────────────────────────

const Options = struct {
    /// Borrowed from argv (stable for the process lifetime) -- not duped.
    servers: std.ArrayList([]const u8) = .empty,
    timeout_ms: u32 = 3000,
    port: u16 = sntp.ntp_port,
    help: bool = false,

    fn deinit(self: *Options, gpa: Allocator) void {
        self.servers.deinit(gpa);
    }
};

fn parseArgs(gpa: Allocator, args: *std.process.Args.Iterator) !Options {
    var opts: Options = .{};
    errdefer opts.deinit(gpa);

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            opts.help = true;
        } else if (std.mem.eql(u8, arg, "-t")) {
            const v = args.next() orelse return error.BadUsage;
            opts.timeout_ms = std.fmt.parseInt(u32, v, 10) catch return error.BadUsage;
        } else if (std.mem.eql(u8, arg, "-p")) {
            const v = args.next() orelse return error.BadUsage;
            opts.port = std.fmt.parseInt(u16, v, 10) catch return error.BadUsage;
        } else if (arg.len > 1 and arg[0] == '-') {
            std.debug.print("sntp-demo: unknown option '{s}'\n", .{arg});
            return error.BadUsage;
        } else {
            try opts.servers.append(gpa, arg);
        }
    }
    return opts;
}

// ─────────────────────────────────────────────────────────────────────────────
// live query
// ─────────────────────────────────────────────────────────────────────────────

/// Query one server; print what happened; return whether the reply was
/// fully validated and usable. Never propagates a raw network error --
/// "no route", "unreachable", a timeout, and a protocol-level discard are
/// all reported by name and treated as a normal (if unwelcome) outcome, not
/// a crash.
fn runQuery(io: std.Io, label: []const u8, host: []const u8, port: u16, timeout_ms: u32) !bool {
    const addr = std.Io.net.IpAddress.parse(host, port) catch |err| {
        std.debug.print(
            "{s} ({s}): not a literal IPv4/IPv6 address ({t}) -- this module has no DNS resolver, so hostnames aren't accepted; pass an IP\n",
            .{ label, host, err },
        );
        return false;
    };

    var kiss: sntp.KissOfDeath = undefined;
    const result = sntp.query(io, addr, .{ .timeout_ms = timeout_ms }, &kiss) catch |err| {
        std.debug.print("{s} ({s}:{d}): ", .{ label, host, port });
        printQueryError(err, kiss);
        return false;
    };

    const offset_ms = @as(f64, @floatFromInt(result.offset_ns)) / 1_000_000.0;
    const delay_ms = @as(f64, @floatFromInt(result.roundtrip_ns)) / 1_000_000.0;
    const direction: []const u8 = if (offset_ms >= 0) "ahead of" else "behind";
    std.debug.print(
        "{s} ({s}:{d}): stratum={d} leap={s}  offset={d:.3} ms (server clock {s} ours)  round-trip delay={d:.3} ms\n",
        .{ label, host, port, result.reply.stratum, @tagName(result.reply.leap), offset_ms, direction, delay_ms },
    );
    return true;
}

/// The extra `QueryError` cases beyond `DecodeError` (network-level, plus
/// the anti-spoof check `query` itself runs after decoding); everything
/// else falls through to `printDecodeError`, shared with the canned demo
/// below so both paths describe the same rejection the same way.
fn printQueryError(err: sntp.QueryError, kiss: sntp.KissOfDeath) void {
    switch (err) {
        error.Timeout => std.debug.print("timed out waiting for a reply\n", .{}),
        error.Canceled => std.debug.print("query canceled\n", .{}),
        error.NetworkFailed => std.debug.print("no network access (socket bind/send/receive failed)\n", .{}),
        error.OriginateMismatch => std.debug.print(
            "discarded -- origin-timestamp anti-spoof check failed (reply did not echo the T1 we sent, RFC 4330 Sec 5): a spoofed or badly broken reply\n",
            .{},
        ),
        else => |e| printDecodeError(e, kiss),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RFC 4330 §5 / RFC 5905 §7.3-7.4 discard-rule demo -- canned, no network
// ─────────────────────────────────────────────────────────────────────────────
//
// Real Kiss-o'-Death replies are rare in the wild by design (a well-behaved
// client should almost never see one), and provoking one on purpose against
// a public server means deliberately abusing its rate limit -- not
// something this demo will do. So this section hand-builds the four reject
// shapes `decodeResponse` exists to catch and runs them through the exact
// same decode path a real reply takes, entirely offline.

fn runDiscardDemos() void {
    std.debug.print(
        "\n-- RFC 4330 Sec 5 / RFC 5905 Sec 7.3-7.4 discard-rule demo (canned packets, no network) --\n",
        .{},
    );
    demoDiscard("Kiss-o'-Death RATE", .{ .version = 4, .mode = .server, .stratum = 0, .reference_id = .{ 'R', 'A', 'T', 'E' } });
    demoDiscard("Kiss-o'-Death DENY", .{ .version = 4, .mode = .server, .stratum = 0, .reference_id = .{ 'D', 'E', 'N', 'Y' } });
    demoDiscard("stratum 16 (unsynchronized)", .{ .version = 4, .mode = .server, .stratum = 16, .transmit = .{ .seconds = 1 } });
    demoDiscard("unset Transmit Timestamp", .{ .version = 4, .mode = .server, .stratum = 2 });
}

fn demoDiscard(label: []const u8, pkt: sntp.Packet) void {
    const bytes = pkt.encode();
    var kiss: sntp.KissOfDeath = undefined;
    if (sntp.decodeResponse(&bytes, &kiss)) |_| {
        std.debug.print("[canned] {s}: UNEXPECTED -- decoded without error (this would be a module bug)\n", .{label});
    } else |err| {
        std.debug.print("[canned] {s}: ", .{label});
        printDecodeError(err, kiss);
    }
}

/// One rejection reason per `DecodeError` case, in the reader's terms --
/// what the server said (for Kiss-o'-Death) or which RFC 4330/5905 sanity
/// check the reply failed, not just the bare error name.
fn printDecodeError(err: sntp.DecodeError, kiss: sntp.KissOfDeath) void {
    switch (err) {
        error.KissOfDeath => std.debug.print(
            "Kiss-o'-Death -- server says {s} (\"{s}\"): {s}\n",
            .{ @tagName(kiss.code), kiss.raw, kissObligation(kiss.code) },
        ),
        error.UnsynchronizedStratum => std.debug.print(
            "discarded -- stratum >= 16 (unsynchronized/reserved, RFC 5905 Sec 7.3 Fig. 11): not a valid, synchronized time source\n",
            .{},
        ),
        error.TransmitTimestampUnset => std.debug.print(
            "discarded -- Transmit Timestamp is unset (RFC 4330 Sec 5 sanity check 4): the server hasn't set its own clock yet\n",
            .{},
        ),
        error.InvalidVersion => std.debug.print(
            "discarded -- reply has VN=0 (RFC 4330 Sec 5 sanity check 4, per Errata 2263)\n",
            .{},
        ),
        error.NotServerMode => std.debug.print("discarded -- reply is not in server mode\n", .{}),
        error.InvalidLength => std.debug.print("discarded -- reply was not exactly 48 bytes\n", .{}),
    }
}

/// What RFC 5905 §7.4 actually obliges a client to do for each code -- only
/// RATE, DENY and RSTR carry a defined MUST; everything else is diagnostic.
fn kissObligation(code: sntp.KissCode) []const u8 {
    return switch (code) {
        .rate => "MUST back off -- increase the polling interval to this server",
        .deny => "MUST stop -- demobilize this association and never poll this server again",
        .rstr => "MUST stop -- demobilize this association; access denied by local policy",
        else => "no mandatory client action defined by RFC 5905 Sec 7.4 for this code; treat as diagnostic",
    };
}
