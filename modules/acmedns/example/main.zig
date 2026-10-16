// SPDX-License-Identifier: MIT

//! `acmedns-demo` — what a DNS-01 publisher sees, without a network.
//!
//! A `Dns01Solver` with an in-memory publisher (a stand-in for a zone you
//! control), the zone given and the propagation check off, solves the two
//! authorizations a `*.example.org` + `example.org` order brings: both land
//! at `_acme-challenge.example.org`, each its own TXT value, and each is
//! removed by its own cleanup. In a real setup the publisher is
//! `acmedns.Rfc2136` / `AcmeDns` / `HttpReq` / `Exec`, the zone comes from
//! the SOA walk, and `solver.solver()` goes into `acme.Client.Options.solvers`
//! — see the module README.
//!
//! Run: `zig build run-example-acmedns`.

const std = @import("std");
const acmedns = @import("acmedns");

/// A zone in memory: (name, value) pairs.
const MemoryZone = struct {
    gpa: std.mem.Allocator,
    records: std.ArrayList([2][]u8) = .empty,

    fn publisher(z: *MemoryZone) acmedns.Publisher {
        return .{ .ctx = z, .present = present, .cleanup = cleanup };
    }

    fn present(ctx: ?*anyopaque, rec: *const acmedns.Record) acmedns.PublishError!void {
        const z: *MemoryZone = @ptrCast(@alignCast(ctx.?));
        const name = try z.gpa.dupe(u8, rec.fqdn);
        errdefer z.gpa.free(name);
        const value = try z.gpa.dupe(u8, rec.value);
        errdefer z.gpa.free(value);
        try z.records.append(z.gpa, .{ name, value });
        std.debug.print("present  {s} (zone {s}) TXT \"{s}\"\n", .{ rec.fqdn, rec.zone, rec.value });
    }

    fn cleanup(ctx: ?*anyopaque, rec: *const acmedns.Record) void {
        const z: *MemoryZone = @ptrCast(@alignCast(ctx.?));
        for (z.records.items, 0..) |r, i| {
            if (std.mem.eql(u8, r[0], rec.fqdn) and std.mem.eql(u8, r[1], rec.value)) {
                z.gpa.free(r[0]);
                z.gpa.free(r[1]);
                _ = z.records.orderedRemove(i);
                std.debug.print("cleanup  {s} TXT \"{s}\"\n", .{ rec.fqdn, rec.value });
                return;
            }
        }
    }

    fn deinit(z: *MemoryZone) void {
        for (z.records.items) |r| {
            z.gpa.free(r[0]);
            z.gpa.free(r[1]);
        }
        z.records.deinit(z.gpa);
    }
};

pub fn main(init: std.process.Init.Minimal) !u8 {
    _ = init;
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var zone: MemoryZone = .{ .gpa = gpa };
    defer zone.deinit();
    var solver = acmedns.Dns01Solver.init(io, gpa, .{
        .publisher = zone.publisher(),
        .zone = "example.org",
        .follow_cname = false,
        .check_propagation = false,
    });
    defer solver.deinit();

    // The two authorizations of a wildcard + base order (token "." thumbprint).
    try solver.present("example.org", "token-for-wildcard", "token-for-wildcard.thumbprint");
    try solver.present("example.org", "token-for-base", "token-for-base.thumbprint");
    std.debug.print("{d} TXT records at _acme-challenge.example.org, {d} pending\n", .{ zone.records.items.len, solver.pendingCount() });
    if (zone.records.items.len != 2) return 1;

    for ([_][]const u8{ "token-for-wildcard.thumbprint", "token-for-base.thumbprint" }) |ka| {
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(ka, &sha, .{});
        var value: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&value, &sha);
        solver.cleanup("example.org", &value);
    }
    std.debug.print("{d} TXT records left, {d} pending\n", .{ zone.records.items.len, solver.pendingCount() });
    return if (zone.records.items.len == 0 and solver.pendingCount() == 0) 0 else 1;
}
