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

// ── the prepared Ed25519 signer and the checked one-shot (2026-11-27) ──

const Ed = std.crypto.sign.Ed25519;
var ed_kp: Ed.KeyPair = undefined;
var signer: root.Ed25519Signer = undefined;
var ed_sig: Ed.Signature = undefined;
var ed_msg: [100]u8 = undefined;

fn signerSign(s: *const root.Ed25519Signer, m: []const u8) void {
    ed_sig = s.sign(m, null) catch unreachable;
}
fn signChecked(sk: *const Ed.SecretKey, m: []const u8) void {
    ed_sig = root.signEd25519Checked(sk, m, null) catch unreachable;
}

test "STACKPROBE: Ed25519Signer and signEd25519Checked leave no seed, scalar, prefix or nonce on the dead stack" {
    try sp.skipUnlessOptimized();
    var s: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ct25519 probe2 ed25519 seed", &s, .{});
    ed_kp = try Ed.KeyPair.generateDeterministic(s);
    @memset(&ed_msg, 0x3c);
    // The intermediates every path derives (RFC 8032 §5.1.6).
    var az: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(&s, &az, .{});
    var a: [32]u8 = az[0..32].*;
    root.Edwards25519.scalar.clamp(&a);
    var nh = std.crypto.hash.sha2.Sha512.init(.{});
    nh.update(az[32..64]);
    nh.update(&ed_msg);
    var r64: [64]u8 = undefined;
    nh.final(&r64);
    const r = root.Edwards25519.scalar.reduce64(r64);
    const needles = [_][]const u8{ &s, az[0..32], az[32..64], &a, &r64, &r };

    _ = try P.run("Ed25519Signer.initInto once_at_load", root.Ed25519Signer.initInto, .{ &signer, &ed_kp.secret_key, .once_at_load }, needles[0..4], .{});
    _ = try P.run("Ed25519Signer.sign once_at_load", signerSign, .{ &signer, &ed_msg }, needles[1..], .{});
    signer.deinit();
    _ = try P.run("Ed25519Signer.initInto every_sign", root.Ed25519Signer.initInto, .{ &signer, &ed_kp.secret_key, .every_sign }, needles[0..4], .{});
    _ = try P.run("Ed25519Signer.sign every_sign", signerSign, .{ &signer, &ed_msg }, needles[1..], .{});
    signer.deinit();
    _ = try P.run("signEd25519Checked", signChecked, .{ &ed_kp.secret_key, &ed_msg }, &needles, .{});
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
