// SPDX-License-Identifier: MIT

//! REAL-INTERNET checks for `dns`: recursive UDP and TCP against whatever
//! resolver `/etc/resolv.conf` names, a reverse PTR against 8.8.8.8, and the
//! three DoH shapes against `dns.google` and `cloudflare-dns.com`.
//!
//! ## Why this is a PROGRAM and not seven tests
//!
//! Until 2026-09-09 these were seven `test "live: …"` in `src/Resolver.zig`,
//! each ending `catch |err| return skipLive(err)`, and `skipLive` printed
//! `live dns test skipped: <error>` with `std.debug.print` — which is stderr.
//!
//! The gate driver treats ANY stderr on an exit-0 step as a failure
//! (`scripts/test-lib.sh`, "OK-but-stderr -> treated as FAIL"), and that rule
//! is right: it exists because four checkers reported success while
//! complaining, and because `check-uapi` sat unwired for months with its
//! summary on the wrong stream. So a slow DNS server — not a bug, not even a
//! change to this module — turned `test-dns` red, and with it the run across
//! 217 modules.
//!
//! ⭐ THE SKIP WAS NOT THE DEFECT EITHER. Silencing the print would have left
//! the real problem: seven tests that pass or vanish depending on the network,
//! inside the lane whose whole purpose is to be reproducible. A skip that
//! nobody sees is worse than one that shouts — it is a test that reports
//! success for a run in which it did nothing.
//!
//! The repository had already decided this shape twice, and this is the third
//! module to follow it: `dtls` moved its wolfSSL peer to `tools/interop.zig`
//! on 2026-09-06, and `dns` itself moved the hostile-loopback anchor there on
//! 2026-09-07 (audit F20). The rule from `Module.live`'s own doc comment: the
//! anchor's VALUE replays hermetically in the lane that runs everywhere; the
//! anchor's TAKING is a program.
//!
//! ## What is and is not lost
//!
//! What these seven prove cannot be replayed: that the wire format this module
//! encodes is accepted by resolvers nobody here controls, and that the DoH
//! path really carries the `http` dependency end to end. `test-dns` covers the
//! parsing and the hostile cases hermetically; only this reaches strangers.
//!
//! So it is kept, and kept runnable — `zig build live-dns` — rather than
//! deleted. What changes is that nothing runs it on a schedule, and that is
//! the honest state: it was never really running before either. It reported
//! either a pass or a skip, and the skip is what a red gate was made of.
//!
//! `zig build check-interop` COMPILES this with no network anywhere, so it
//! cannot rot unnoticed — the same rot guard every `tools/interop.zig` gets.

const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");

const Check = struct {
    name: []const u8,
    /// What a failure here would mean — printed with the failure, because
    /// "live: DoH GET failed" on its own does not say whether the module or
    /// the internet is the suspect.
    why: []const u8,
    run: *const fn (std.Io, std.mem.Allocator) anyerror!void,
};

const checks = [_]Check{
    .{
        .name = "udp",
        .why = "recursive A lookup over UDP against the system resolver",
        .run = udpA,
    },
    .{
        .name = "tcp",
        .why = "the same lookup over TCP, which uses the 2-byte length prefix",
        .run = tcpA,
    },
    .{
        .name = "lookup-ip",
        .why = "lookupIp merges the A and AAAA answers into one list",
        .run = lookupIp,
    },
    .{
        .name = "reverse",
        .why = "reverse PTR of 8.8.8.8 resolves to a dns.google name",
        .run = reversePtr,
    },
    .{
        .name = "doh-post",
        .why = "DoH POST to dns.google — the one check that exercises the http dep",
        .run = dohPost,
    },
    .{
        .name = "doh-get",
        .why = "DoH GET to cloudflare-dns.com — base64url in the query string",
        .run = dohGet,
    },
    .{
        .name = "doh-json",
        .why = "DoH-JSON to dns.google/resolve — a different response shape entirely",
        .run = dohJson,
    },
};

fn udpA(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{ .timeout_ms = 3000 });
    defer r.deinit();

    var msg = try r.resolve("example.com", .a);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return error.UnexpectedRcode;
    for (msg.answers) |rec| {
        if (rec.data == .a) return;
    }
    return error.NoARecord;
}

fn tcpA(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{ .transport = .tcp, .timeout_ms = 4000 });
    defer r.deinit();

    var msg = try r.resolve("example.com", .a);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return error.UnexpectedRcode;
    if (msg.answers.len == 0) return error.NoAnswers;
}

fn lookupIp(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{ .timeout_ms = 3000 });
    defer r.deinit();

    const ips = try r.lookupIp("example.com");
    defer gpa.free(ips);
    if (ips.len == 0) return error.NoAddresses;
}

fn reversePtr(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{ .timeout_ms = 3000 });
    defer r.deinit();

    const names = try r.reverse(netaddr.parseIp("8.8.8.8").?);
    defer r.freeNames(names);
    if (names.len == 0) return error.NoPtrRecords;
    if (std.mem.indexOf(u8, names[0], "dns.google") == null) return error.UnexpectedPtrName;
}

fn dohPost(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{
        .doh_url = "https://dns.google/dns-query",
        .timeout_ms = 8000,
    });
    defer r.deinit();

    var msg = try r.query("example.com", .a);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return error.UnexpectedRcode;
    if (msg.answers.len == 0) return error.NoAnswers;
}

fn dohGet(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{
        .doh_url = "https://cloudflare-dns.com/dns-query",
        .doh_method = .get,
        .timeout_ms = 8000,
    });
    defer r.deinit();

    var msg = try r.query("example.com", .a);
    defer msg.deinit();
    if (msg.rcode() != .no_error) return error.UnexpectedRcode;
    if (msg.answers.len == 0) return error.NoAnswers;
}

fn dohJson(io: std.Io, gpa: std.mem.Allocator) !void {
    var r = dns.Resolver.init(io, gpa, .{
        .doh_url = "https://dns.google/resolve",
        .timeout_ms = 8000,
    });
    defer r.deinit();

    const parsed = try r.queryJson("example.com", .a);
    defer parsed.deinit();
    if (parsed.value.Status != 0) return error.UnexpectedStatus;
    if (parsed.value.Answer.len == 0) return error.NoAnswers;
}

const usage =
    \\dns live checks: this module against resolvers nobody here controls.
    \\
    \\  zig build live-dns                  run every check
    \\  zig build live-dns -- --check NAME  run one check (repeatable)
    \\  zig build live-dns -- --list        list the check names
    \\
    \\NEEDS THE INTERNET, and says so instead of skipping: a failure here is
    \\either this module or the network, and the line says which is suspected.
    \\The hermetic half is `zig build test-dns`, which needs neither.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    var arena: std.heap.ArenaAllocator = .init(da.allocator());
    defer arena.deinit();
    const gpa = arena.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var selected: [checks.len][]const u8 = undefined;
    var selected_len: usize = 0;

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--list")) {
            for (checks) |c| std.debug.print("{s}\t{s}\n", .{ c.name, c.why });
            return 0;
        } else if (std.mem.eql(u8, arg, "--check")) {
            const name = args.next() orelse {
                std.debug.print("--check needs a name\n{s}", .{usage});
                return 2;
            };
            if (selected_len == selected.len) return 2;
            selected[selected_len] = name;
            selected_len += 1;
        } else {
            std.debug.print("unknown argument \"{s}\"\n{s}", .{ arg, usage });
            return 2;
        }
    }

    var ran: usize = 0;
    var bad: usize = 0;
    for (checks) |c| {
        if (selected_len != 0) {
            var wanted = false;
            for (selected[0..selected_len]) |s| {
                if (std.mem.eql(u8, s, c.name)) wanted = true;
            }
            if (!wanted) continue;
        }
        ran += 1;
        if (c.run(io, gpa)) |_| {
            std.debug.print("ok   {s}\n", .{c.name});
        } else |err| {
            bad += 1;
            std.debug.print("FAIL {s}: {t}\n     {s}\n", .{ c.name, err, c.why });
        }
    }

    if (ran == 0) {
        std.debug.print("no check matched --check\n{s}", .{usage});
        return 2;
    }
    std.debug.print("\n{d} check(s), {d} failed\n", .{ ran, bad });
    return if (bad == 0) 0 else 1;
}
