// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) for the X25519 key-generation
//! entry points added to the burn set 2026-10-09: `recoverPublicKeyInto`,
//! `KeyPair.generateDeterministicInto`, `KeyPair.generateInto` (the std-shaped
//! by-value wrappers call these). One-shot calls, so a generous burn.
//! ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const root = @import("root.zig");
const sp = @import("testkit").stackprobe;
const X25519 = root.X25519;

const P = sp.Probe(.{ .window = 64 * 1024 });

var seed: [32]u8 = undefined;
var out_pub: [32]u8 = undefined;
var kp: X25519.KeyPair = undefined;

test "STACKPROBE: X25519 key generation leaves no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("ct25519 probe2 seed", &seed, .{});
    _ = try P.run("X25519.recoverPublicKeyInto", X25519.recoverPublicKeyInto, .{ &out_pub, &seed }, &.{&seed}, .{});
    _ = try P.run("X25519.KeyPair.generateDeterministicInto", X25519.KeyPair.generateDeterministicInto, .{ &kp, &seed }, &.{ &seed, std.mem.asBytes(&kp) }, .{});
    _ = try P.run("X25519.KeyPair.generateInto", X25519.KeyPair.generateInto, .{ &kp, std.testing.io }, &.{std.mem.asBytes(&kp)}, .{});
}

// Stack budget (README "Stack use"): the figures the README quotes are pinned here so
// the document cannot drift from the code. Runs in any build mode.
test "stack use: Straus tables, burn sizes, and the entry points run in a 64 KiB stack" {
    const burn = @import("burn.zig");
    const Edwards25519 = root.Edwards25519;
    const msm_chunk = 8; // root.zig's `msm_chunk` (private): terms per Straus pass
    try std.testing.expectEqual(@as(usize, 168), @sizeOf(Edwards25519));
    try std.testing.expectEqual(@as(usize, 21504), @sizeOf([msm_chunk][16]Edwards25519));
    try std.testing.expectEqual(@as(usize, 32 * 1024), burn.msm_burn);
    try std.testing.expectEqual(@as(usize, 16 * 1024), burn.x25519_base_burn);
    try std.testing.expectEqual(@as(usize, 4 * 1024), burn.x25519_burn);
    const Job = struct {
        ok: bool = false,
        fn run(j: *@This()) void {
            var sc: [9][32]u8 = undefined;
            var pe: [9]Edwards25519 = undefined;
            var pr: [9]root.Ristretto255 = undefined;
            for (&sc, &pe, &pr, 0..) |*s, *e, *r, i| {
                var h: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(&.{@as(u8, @intCast(i))}, &h, .{});
                h[31] &= 0x0f; // below the group order
                s.* = h;
                e.* = root.mulBase(h);
                r.* = root.mulRistrettoBase(h);
            }
            // Nine terms: two Straus chunks, the second a partial one.
            const a = root.mulMulti(&sc, &pe);
            const b = root.mulMultiRistretto(&sc, &pr);
            var pk: [32]u8 = undefined;
            root.X25519.recoverPublicKeyInto(&pk, &sc[7]) catch return;
            var shared: [32]u8 = undefined;
            root.X25519.scalarmultInto(&shared, &sc[7], pk) catch return;
            std.mem.doNotOptimizeAway(.{ a, b, shared });
            j.ok = true;
        }
    };
    var job: Job = .{};
    const th = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, Job.run, .{&job});
    th.join();
    try std.testing.expect(job.ok);
}
