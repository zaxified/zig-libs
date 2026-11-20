// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh mcp`, which builds the
//! harness and prints the control table.
//!
//! Not wired into `zig build test-mcp`: memcheck's context count is valgrind's
//! own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The one secret mcp holds: the `StateSeal` HMAC key. The key is tainted in
//! place, the message, binding and token stay defined, and the public API is
//! driven. A token's MAC is public the moment it is produced: a tainted copy
//! is formatted through the non-constant-time printer as the propagation
//! witness, then the original is declassified.
//!
//!  * `seal` — `StateSeal.seal` with the tainted key. The MAC is public by
//!    design, but the token's base64url encoder indexes a table by each MAC
//!    octet before the caller can declassify it: those contexts are the count.
//!  * `open` — `StateSeal.open` with the tainted key on a genuine token, a
//!    token with one MAC octet flipped, a token rebound to another principal
//!    and an expired one. The tokens are produced with an untainted copy of the
//!    key. The verdict of `timing_safe.eql` is the one value the module
//!    computes from the key, and it is what `open` returns to the caller.
//!  * `control` — POSITIVE CONTROL: the same HMAC under the tainted key,
//!    compared with an early-exit `std.mem.eql` instead of
//!    `timing_safe.eql`. It must flag, otherwise the taint never arrived and
//!    the zeros of the other rows mean nothing.

const std = @import("std");
const builtin = @import("builtin");
const mcp = @import("root.zig");

const memcheck = std.valgrind.memcheck;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

const Target = enum { seal, open, control };
const Taint = enum { yes, no };

const binding: mcp.StateSeal.Binding = .{ .method = "tools/call", .target = "pay", .principal = "alice", .extra = "args-digest" };
const payload = "{\"step\":2,\"order\":\"o-1\"}";

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) memcheck.makeMemUndefined(bytes);
}

fn fillKey(key: *[32]u8) void {
    for (key, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
}

/// Witness: format a (possibly tainted) copy through the non-constant-time
/// printer, then declassify the original.
fn publish(label: []const u8, bytes: []u8) void {
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..bytes.len] });
    memcheck.makeMemDefined(bytes);
}

var verdict_bits: u32 = 0;

fn verdict(label: []const u8, ok: bool) void {
    verdict_bits = verdict_bits *% 2 +% @intFromBool(ok);
    std.debug.print("ctgrind_result {s} ok={}\n", .{ label, ok });
}

fn sealTarget(t: Taint, arena: std.mem.Allocator) !void {
    var s: mcp.StateSeal = .{ .key = undefined };
    fillKey(&s.key);
    taint(t, &s.key);
    const token = try s.seal(arena, binding, payload, 1000, 600);
    publish("token", @constCast(token));
}

fn openTarget(t: Taint, arena: std.mem.Allocator) !void {
    var pub_seal: mcp.StateSeal = .{ .key = undefined };
    fillKey(&pub_seal.key);
    const token = try pub_seal.seal(arena, binding, payload, 1000, 600);
    const bad = try arena.dupe(u8, token);
    // Flip one character inside the MAC (header is 9 bytes = 12 base64 chars).
    bad[20] = if (bad[20] == 'A') 'B' else 'A';
    const other: mcp.StateSeal.Binding = .{ .method = "tools/call", .target = "pay", .principal = "bob", .extra = "args-digest" };

    var s: mcp.StateSeal = .{ .key = undefined };
    fillKey(&s.key);
    taint(t, &s.key);
    verdict("accept", if (s.open(arena, binding, token, 1100)) |p| std.mem.eql(u8, p, payload) else |_| false);
    verdict("flipped", if (s.open(arena, binding, bad, 1100)) |_| true else |_| false);
    verdict("rebound", if (s.open(arena, other, token, 1100)) |_| true else |_| false);
    verdict("expired", if (s.open(arena, binding, token, 2000)) |_| true else |err| err == error.StateExpired);
    // The accept / reject pattern as one pinned value (the output pin reads `ctgrind_result=<hex>`).
    std.debug.print("ctgrind_result={x:0>8}\n", .{verdict_bits});
}

/// Positive control: the same HMAC under the tainted key, compared with an
/// early-exit `std.mem.eql` against a public tag. The branch on the tainted
/// bytes must be reported.
fn controlTarget(t: Taint) !void {
    var key: [32]u8 = undefined;
    fillKey(&key);
    taint(t, &key);
    var tag: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&tag, "mcp-request-state", &key);
    var want: [Hmac.mac_length]u8 = @splat(0x5a);
    std.mem.doNotOptimizeAway(&want);
    // Two distinct calls, so the branch on the tainted verdict is a real jump
    // in this frame (a bool printed with `{}` would only raise the printer's).
    if (std.mem.eql(u8, &tag, &want)) {
        std.debug.print("ctgrind_result control equal\n", .{});
    } else {
        std.debug.print("ctgrind_result control differ\n", .{});
    }
    var pub_tag = tag;
    memcheck.makeMemDefined(&pub_tag);
    std.debug.print("ctgrind_result={x}\n", .{pub_tag[0..8]});
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator); // global-alloc-ok: one-shot ctgrind diagnostic binary, no caller to take one from
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    switch (target) {
        .seal => try sealTarget(t, arena),
        .open => try openTarget(t, arena),
        .control => try controlTarget(t),
    }
}
