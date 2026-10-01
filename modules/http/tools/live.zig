// SPDX-License-Identifier: MIT

//! REAL-INTERNET checks for `http`: an HTTPS round trip to example.com and a
//! plaintext request that may be redirected to HTTPS.
//!
//! ## Why this is a PROGRAM and not two tests
//!
//! Until 2026-10-01 these were two `test "live: …"` in `src/Client.zig`, each
//! ending `catch |err| { print("live network test skipped"); return
//! error.SkipZigTest; }`. With no route to the internet — an offline laptop, a
//! CI runner without egress, the network namespace `scripts/lib/netns-run` puts
//! the loopback lanes in — both timed out and SKIPPED, and `test-http` stayed
//! green while doing less. A skip is a test reporting success for a run in
//! which it did nothing (`CONVENTIONS.md` §9, "A test that needs the REAL
//! INTERNET"; `dns` moved seven such tests the same way on 2026-09-09).
//!
//! What stays behind in `test-http`: the TLS client, the redirect state
//! machine and the pool, all against loopback peers and recorded frames. What
//! only this program proves: that a server nobody here controls accepts the
//! handshake and the request, end to end.
//!
//! `zig build check-interop` COMPILES this with no network anywhere, so it
//! cannot rot unnoticed; nothing runs it on a schedule.

const std = @import("std");
const http = @import("http");

const Client = http.Client;

const Check = struct {
    name: []const u8,
    /// What a failure here would mean — printed with the failure.
    why: []const u8,
    run: *const fn (std.Io, std.mem.Allocator) anyerror!void,
};

const checks = [_]Check{
    .{
        .name = "https-get",
        .why = "GET https://example.com/ — TLS handshake, request and body against a real server",
        .run = httpsGet,
    },
    .{
        .name = "redirect",
        .why = "GET http://example.com/ completes with 2xx/3xx — plaintext transport (and a redirect, if the world still sends one)",
        .run = redirect,
    },
};

fn httpsGet(io: std.Io, gpa: std.mem.Allocator) !void {
    var client = Client.init(io, gpa, .{
        .connect_timeout_ms = 4000,
        .total_timeout_ms = 15000,
    });
    defer client.deinit();

    const body = try client.getAlloc(gpa, "https://example.com/", 1 << 20);
    defer gpa.free(body);
    if (body.len == 0) return error.EmptyBody;
    if (std.mem.indexOf(u8, body, "Example") == null) return error.UnexpectedBody;
}

fn redirect(io: std.Io, gpa: std.mem.Allocator) !void {
    var client = Client.init(io, gpa, .{
        .connect_timeout_ms = 4000,
        .total_timeout_ms = 15000,
    });
    defer client.deinit();

    // www.example.com used to 3xx; if the world changed, accept any 2xx/3xx
    // completion — this is about the transport, the redirect state machine is
    // unit-tested offline.
    var res = try client.request(.get, "http://example.com/", .{});
    defer res.deinit();
    if (res.status < 200 or res.status >= 400) return error.UnexpectedStatus;
}

const usage =
    \\http live checks: this module against servers nobody here controls.
    \\
    \\  zig build live-http                  run every check
    \\  zig build live-http -- --check NAME  run one check (repeatable)
    \\  zig build live-http -- --list        list the check names
    \\
    \\NEEDS THE INTERNET, and says so instead of skipping: a failure here is
    \\either this module or the network, and the line says which is suspected.
    \\The hermetic half is `zig build test-http`, which needs neither.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();

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
