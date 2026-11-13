// SPDX-License-Identifier: MIT

//! No-panic sweep (2026-11-13). The only finding (WHS-1: `Verifier.init`
//! precondition `assert`s on caller values, UB in ReleaseFast, now a checked
//! `@panic("webhooksig: ...")` in every mode) cannot be proven by a test that
//! survives the panic; these tests pin the accepted side of every boundary
//! that finding touches, so a "fix" that over-tightens it fails.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

fn fixedNow(_: ?*anyopaque) i64 {
    return 0;
}
const clock: root.Clock = .{ .nowFn = fixedNow };

test "Verifier.init accepts exactly max_keys secrets and max_keys public keys (sweep clean: init bounds)" {
    const gpa = testing.allocator;
    var secs: [root.max_keys][]const u8 = undefined;
    for (&secs) |*s| s.* = "k";
    var v = try root.Verifier.init(gpa, .{ .secret = secs[0], .extra_secrets = secs[1..] });
    defer v.deinit();
    try testing.expectEqual(@as(usize, root.max_keys), v.secretCount());

    const pk = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1))).public_key;
    const pks: [root.max_keys]std.crypto.sign.Ed25519.PublicKey = @splat(pk);
    var w = try root.Verifier.init(gpa, .{ .scheme = .standard_webhooks, .public_keys = &pks, .clock = clock });
    defer w.deinit();
    try testing.expectEqual(@as(usize, 0), w.secretCount());
}

test "Verifier with only public keys refuses a v1 delivery instead of crashing (sweep clean: no-secret standard)" {
    const gpa = testing.allocator;
    const pk = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1))).public_key;
    var w = try root.Verifier.init(gpa, .{ .scheme = .standard_webhooks, .public_keys = &.{pk}, .clock = clock });
    defer w.deinit();
    try testing.expectError(error.NoMatchingSignature, w.verifyRequest(.{ .signature = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", .timestamp = "0", .id = "m" }, "x", 0));
}
