// SPDX-License-Identifier: MIT

//! What a caller durably persisting small keyed documents does with
//! `filestore`: open a `Store` rooted at a directory, write and read a
//! record, reject a path-traversal key by name, use compare-and-swap to
//! catch a lost update, and use a TTL sidecar to expire a session — all
//! through the atomic temp-then-rename write path the module documents.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const filestore = @import("filestore");

/// A deterministic clock for the TTL demonstration — `filestore.Store.Clock`
/// is a public struct with public `ctx`/`nowFn` fields (the same shape the
/// module's own tests use), so a consumer can inject one without any
/// private access.
const ManualClock = struct {
    now_ns: i64 = 0,
    fn clock(mc: *ManualClock) filestore.Clock {
        return .{ .ctx = mc, .nowFn = read };
    }
    fn read(ctx: ?*anyopaque) i64 {
        const mc: *ManualClock = @ptrCast(@alignCast(ctx.?));
        return mc.now_ns;
    }
};

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // filestore's `arena`-taking calls (getBytes, casPutBytes, list, sweep)
    // document that the caller owns an arena for their allocations; wrap it
    // around the DebugAllocator so a real leak still gets caught on deinit.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Rooted under the build's own cache dir, cleaned up at the end — a real
    // consumer would point `base` at a durable data directory instead.
    const base = ".zig-cache/tmp/example-filestore";
    defer std.Io.Dir.cwd().deleteTree(io, base) catch {};

    var store = try filestore.Store.init(io, base);

    // ── plain put/get round-trip ────────────────────────────────────────
    try store.putBytes("devices", "sensor-1", "temperature=21.5C");
    const got = (try store.getBytes(arena, "devices", "sensor-1")).?;
    std.debug.print("sensor-1: {s}\n", .{got});

    // ── a path-traversal key is rejected by name, before touching disk ──
    store.putBytes("devices", "../../etc/passwd", "pwned") catch |err| switch (err) {
        error.InvalidName => {
            std.debug.print("rejected unsafe key, as expected\n", .{});
        },
        else => return err,
    };

    // ── compare-and-swap catches a lost update ──────────────────────────
    const v1 = try store.putBytesVersioned("accounts", "acct-1", "balance=100");
    // A second writer that read the same version may safely update...
    const v2 = try store.casPutBytes(arena, "accounts", "acct-1", "balance=150", v1);
    // ...but a third writer racing off the now-stale v1 must be rejected,
    // not silently clobber the update above.
    _ = store.casPutBytes(arena, "accounts", "acct-1", "balance=999", v1) catch |err| switch (err) {
        error.VersionMismatch => blk: {
            std.debug.print("stale writer correctly rejected\n", .{});
            break :blk 0;
        },
        else => return err,
    };
    std.debug.assert(v1 != v2);

    // ── TTL: present before the deadline, absent after, via an injected
    //    deterministic clock (no real sleeping in an example) ───────────
    var clk = ManualClock{ .now_ns = 1_000 };
    store.clock = clk.clock();
    try store.putWithTTL("sessions", "sess-1", "logged-in", 500); // deadline = 1500

    clk.now_ns = 1_499;
    std.debug.assert((try store.getBytes(arena, "sessions", "sess-1")) != null);

    clk.now_ns = 1_500;
    std.debug.assert((try store.getBytes(arena, "sessions", "sess-1")) == null);
    std.debug.print("session expired as scheduled\n", .{});

    // sweep physically reclaims the now-expired record.
    const swept = try store.sweep(arena, "sessions");
    std.debug.print("swept {d} expired session(s)\n", .{swept});
}
